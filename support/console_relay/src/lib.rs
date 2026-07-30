// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Code to launch a terminal emulator for relaying input/output.

#![forbid(unsafe_code)]

mod unix;
mod windows;

use anyhow::Context as _;
use futures::AsyncRead;
use futures::AsyncWrite;
use futures::AsyncWriteExt;
use futures::executor::block_on;
use futures::io::AllowStdIo;
use futures::io::AsyncReadExt;
use pal_async::driver::Driver;
use pal_async::local::block_with_io;
use std::borrow::Cow;
use std::ffi::OsStr;
#[cfg(windows)]
use std::io as pipe_io;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::task::Context;
#[cfg(windows)]
use std::time::Duration;
use term::raw_stdout;

#[derive(Default)]
/// Options to configure a new console window during launch.
pub struct ConsoleLaunchOptions {
    /// If supplied, sets the title of the console window.
    pub window_title: Option<String>,
}

/// Relay stdin/stdout to the given async read/write halves.
///
/// Uses sync stdio (with a separate thread for input) because polling for stdio
/// readiness is difficult, especially on Windows.
async fn relay_stdio(
    read: impl AsyncRead + Unpin,
    mut write: impl AsyncWrite + Unpin + Send + 'static,
    console_title: &str,
) -> anyhow::Result<()> {
    crossterm::terminal::enable_raw_mode().expect("failed to set raw console mode");
    if let Err(err) = crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::SetTitle(console_title)
    ) {
        tracing::warn!("failed to set console title: {}", err);
    }

    std::thread::Builder::new()
        .name("input_thread".into())
        .spawn(move || {
            block_on(futures::io::copy(
                AllowStdIo::new(std::io::stdin()),
                &mut write,
            ))
        })
        .unwrap();

    futures::io::copy(read, &mut AllowStdIo::new(raw_stdout())).await?;
    // Don't wait for the input thread, since it is probably blocking in the stdin read.
    Ok(())
}

/// Synchronously relays stdio to the pipe (Windows) or socket (Unix) pointed to
/// by `path`.
pub fn relay_console(path: &Path, console_title: &str) -> anyhow::Result<()> {
    block_with_io(async |driver| {
        #[cfg(unix)]
        let (read, write) = {
            let pipe = pal_async::socket::PolledSocket::connect_unix(&driver, path)
                .await
                .context("failed to connect to console socket")?;
            pipe.split()
        };
        #[cfg(windows)]
        let (read, write) = {
            let pipe = open_console_pipe(path).context("failed to connect to console pipe")?;
            let pipe = pal_async::pipe::PolledPipe::new(&driver, pipe)
                .context("failed to create polled pipe")?;
            AsyncReadExt::split(pipe)
        };

        relay_stdio(read, write, console_title).await
    })
}

#[cfg(windows)]
fn open_console_pipe(path: &Path) -> pipe_io::Result<std::fs::File> {
    const ATTEMPTS: usize = 100;
    const RETRY_DELAY: Duration = Duration::from_millis(100);

    retry_pipe_connect(
        || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
        },
        ATTEMPTS,
        || std::thread::sleep(RETRY_DELAY),
    )
}

#[cfg(windows)]
fn retry_pipe_connect<T>(
    mut connect: impl FnMut() -> pipe_io::Result<T>,
    attempts: usize,
    mut wait: impl FnMut(),
) -> pipe_io::Result<T> {
    const ERROR_PIPE_BUSY: i32 = 231;

    assert!(attempts > 0);
    for attempt in 0..attempts {
        match connect() {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt + 1 < attempts
                    && (err.kind() == pipe_io::ErrorKind::NotFound
                        || err.raw_os_error() == Some(ERROR_PIPE_BUSY)) =>
            {
                wait();
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!()
}

/// Synchronously relays stdio to an already-connected pipe.
///
/// This is useful when the caller is the pipe server rather than the client.
#[cfg(windows)]
pub fn relay_console_pipe(pipe: std::fs::File, console_title: &str) -> anyhow::Result<()> {
    block_with_io(async |driver| {
        let pipe = pal_async::pipe::PolledPipe::new(&driver, pipe)
            .context("failed to create polled pipe")?;
        let (read, write) = AsyncReadExt::split(pipe);
        relay_stdio(read, write, console_title).await
    })
}

struct App<'a> {
    path: Cow<'a, Path>,
    args: Vec<Cow<'a, OsStr>>,
}

impl<'a, T: AsRef<OsStr> + ?Sized> From<&'a T> for App<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            path: Path::new(value).into(),
            args: Vec::new(),
        }
    }
}

fn choose_terminal_apps(app: Option<&Path>) -> Vec<App<'_>> {
    // If a specific app was specified, use it with no fallbacks.
    if let Some(app) = app {
        return vec![app.into()];
    }

    let mut apps = Vec::new();

    let env_set = |key| std::env::var_os(key).is_some_and(|x| !x.is_empty());

    // If we're running in tmux, use tmux.
    if env_set("TMUX") {
        apps.push(App {
            args: vec![OsStr::new("new-window").into()],
            .."tmux".into()
        });
    }

    // If there's an X11 display, use x-terminal-emulator or xterm.
    if cfg!(unix) && env_set("DISPLAY") {
        apps.push("x-terminal-emulator".into());
        apps.push("xterm".into());
    }

    // On Windows, launch a detached console through cmd's `start` builtin.
    // Direct conhost children can be constrained by the parent's job object,
    // while Windows Terminal reparses the child command line and can combine
    // the executable and arguments into one path.
    if cfg!(windows) {
        apps.push(App {
            args: vec![
                OsStr::new("/d").into(),
                OsStr::new("/c").into(),
                OsStr::new("start").into(),
                OsStr::new("").into(),
            ],
            .."cmd.exe".into()
        });
        apps.push("conhost.exe".into());
        apps.push("wt.exe".into());
    }

    apps
}

/// Launches the terminal application `app` (or the system default), and launch
/// OpenVMM as a child of that to relay the data in the pipe/socket referred to
/// by `path`. Additional launch options can be specified with `launch_options`.
pub fn launch_console(
    app: Option<&Path>,
    path: &Path,
    launch_options: ConsoleLaunchOptions,
) -> anyhow::Result<()> {
    let apps = choose_terminal_apps(app);

    for app in &apps {
        let mut command = Command::new(app.path.as_ref());
        command.args(&app.args);
        add_argument_separator(&mut command, app.path.as_ref());
        let mut child_builder = command
            .arg(std::env::current_exe().context("could not determine current exe path")?)
            .arg("--relay-console-path")
            .arg(path);

        // If a title was specified, pass it to the terminal spawn.
        if let Some(title) = &launch_options.window_title {
            child_builder = child_builder.arg("--relay-console-title").arg(title);
        }

        let child = child_builder
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .spawn();

        match child {
            Ok(mut child) => {
                std::thread::Builder::new()
                    .name("console_waiter".into())
                    .spawn(move || {
                        let _ = child.wait();
                    })
                    .unwrap();

                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && apps.len() != 1 => continue,
            Err(err) => Err(err)
                .with_context(|| format!("failed to launch terminal {}", app.path.display()))?,
        };
    }

    anyhow::bail!("could not find a terminal emulator");
}

/// Adds the terminal-specific separator between terminal arguments and the
/// process to launch.
fn add_argument_separator(command: &mut Command, app: &Path) {
    if let Some(file_name) = app.file_name().and_then(|s| s.to_str()) {
        let arg = match file_name.to_ascii_lowercase().as_str() {
            "cmd" | "cmd.exe" => None,
            "xterm" | "rxvt" | "urxvt" | "x-terminal-emulator" => Some("-e"),
            _ => Some("--"),
        };
        if let Some(arg) = arg {
            command.arg(arg);
        }
    };
}

/// Computes a random console path (pipe path for Windows, Unix socket path for Unix).
pub fn random_console_path() -> PathBuf {
    #[cfg(windows)]
    let mut path = PathBuf::from("\\\\.\\pipe");
    #[cfg(unix)]
    let mut path = std::env::temp_dir();

    let mut random = [0; 16];
    getrandom::fill(&mut random).expect("rng failure");
    path.push(u128::from_ne_bytes(random).to_string());

    path
}

/// An external console window.
///
/// To write to the console, use methods from [`AsyncWrite`]. To read from the
/// console, use methods from [`AsyncRead`].
pub struct Console {
    #[cfg(windows)]
    sys: windows::WindowsNamedPipeConsole,
    #[cfg(unix)]
    sys: unix::UnixSocketConsole,
}

impl Console {
    /// Launches a new terminal emulator and returns an object used to
    /// read/write to the console of that window.
    ///
    /// If `app` is `None`, the system default terminal emulator is used.
    ///
    /// The terminal emulator will relaunch the current executable with the
    /// `--relay-console-path` argument to specify the path of the pipe/socket
    /// used to relay data. Call [`relay_console`] with that path in your `main`
    /// function.
    pub fn new(
        driver: impl Driver,
        app: Option<&Path>,
        launch_options: Option<ConsoleLaunchOptions>,
    ) -> anyhow::Result<Self> {
        let path = random_console_path();
        let this = Self::new_from_path(driver, &path)?;
        launch_console(app, &path, launch_options.unwrap_or_default())
            .context("failed to launch console")?;
        Ok(this)
    }

    fn new_from_path(driver: impl Driver, path: &Path) -> anyhow::Result<Self> {
        #[cfg(windows)]
        let sys = windows::WindowsNamedPipeConsole::new(Box::new(driver), path)
            .context("failed to create console pipe")?;
        #[cfg(unix)]
        let sys = unix::UnixSocketConsole::new(Box::new(driver), path)
            .context("failed to create console socket")?;
        Ok(Console { sys })
    }

    /// Relays the console contents to and from `io`.
    pub async fn relay(&mut self, io: impl AsyncRead + AsyncWrite) -> anyhow::Result<()> {
        let (pipe_recv, mut pipe_send) = { AsyncReadExt::split(self) };

        let (socket_recv, mut socket_send) = io.split();

        let task_a = async move {
            let r = futures::io::copy(pipe_recv, &mut socket_send).await;
            let _ = socket_send.close().await;
            r
        };
        let task_b = async move {
            let r = futures::io::copy(socket_recv, &mut pipe_send).await;
            let _ = pipe_send.close().await;
            r
        };
        futures::future::try_join(task_a, task_b).await?;
        anyhow::Result::<_>::Ok(())
    }
}

impl AsyncRead for Console {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().sys).poll_read(cx, buf)
    }
}

impl AsyncWrite for Console {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().sys).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().sys).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().sys).poll_close(cx)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::choose_terminal_apps;
    use super::retry_pipe_connect;
    use std::io;

    #[test]
    fn detached_console_is_the_default_windows_terminal() {
        let apps = choose_terminal_apps(None);
        let names = apps
            .iter()
            .map(|app| app.path.as_os_str())
            .collect::<Vec<_>>();
        assert_eq!(names.first().copied(), Some("cmd.exe".as_ref()));
    }

    #[test]
    fn pipe_connect_retries_transient_errors() {
        let mut attempts = 0;
        let mut waits = 0;
        let value = retry_pipe_connect(
            || {
                attempts += 1;
                match attempts {
                    1 => Err(io::Error::from(io::ErrorKind::NotFound)),
                    2 => Err(io::Error::from_raw_os_error(231)),
                    _ => Ok(42),
                }
            },
            3,
            || waits += 1,
        )
        .unwrap();

        assert_eq!(value, 42);
        assert_eq!(attempts, 3);
        assert_eq!(waits, 2);
    }

    #[test]
    fn pipe_connect_does_not_retry_permanent_errors() {
        let mut attempts = 0;
        let err = retry_pipe_connect(
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from(io::ErrorKind::PermissionDenied))
            },
            3,
            || unreachable!(),
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn pipe_connect_returns_last_transient_error() {
        let mut attempts = 0;
        let mut waits = 0;
        let err = retry_pipe_connect(
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from(io::ErrorKind::NotFound))
            },
            3,
            || waits += 1,
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(attempts, 3);
        assert_eq!(waits, 2);
    }
}
