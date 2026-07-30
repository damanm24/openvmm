// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone client and server for stressing Consomme with short-lived TCP
//! connections.

use clap::Parser;
use clap::Subcommand;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

const REQUEST: &[u8] = b"consomme-ping";
const RESPONSE: &[u8] = b"consomme-pong";

#[derive(Parser)]
#[command(about = "Stress Consomme with short-lived TCP connections")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the concurrent TCP server inside the guest.
    Server {
        /// Guest address and port on which to listen.
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: SocketAddr,

        /// Number of threads concurrently accepting connections.
        #[arg(long, default_value_t = 100)]
        workers: usize,
    },

    /// Run a bounded-concurrency connection burst from the host.
    Client {
        /// Consomme's forwarded host address and port.
        #[arg(long)]
        address: SocketAddr,

        /// Total number of short-lived connections to make.
        #[arg(long, default_value_t = 1000)]
        connections: u64,

        /// Maximum number of connections active at once.
        #[arg(long, default_value_t = 100)]
        concurrency: usize,

        /// Timeout for connect, request, and response operations.
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,

        /// Print the result as JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug)]
enum AttemptResult {
    Success(Duration),
    Reset,
    Refused,
    TimedOut,
    ProtocolError,
    Other,
}

#[derive(Default)]
struct Summary {
    succeeded: u64,
    reset: u64,
    refused: u64,
    timed_out: u64,
    protocol_error: u64,
    other_error: u64,
    latencies: Vec<Duration>,
}

impl Summary {
    fn record(&mut self, result: AttemptResult) {
        match result {
            AttemptResult::Success(latency) => {
                self.succeeded += 1;
                self.latencies.push(latency);
            }
            AttemptResult::Reset => self.reset += 1,
            AttemptResult::Refused => self.refused += 1,
            AttemptResult::TimedOut => self.timed_out += 1,
            AttemptResult::ProtocolError => self.protocol_error += 1,
            AttemptResult::Other => self.other_error += 1,
        }
    }

    fn merge(&mut self, mut other: Self) {
        self.succeeded += other.succeeded;
        self.reset += other.reset;
        self.refused += other.refused;
        self.timed_out += other.timed_out;
        self.protocol_error += other.protocol_error;
        self.other_error += other.other_error;
        self.latencies.append(&mut other.latencies);
    }

    fn attempted(&self) -> u64 {
        self.succeeded
            + self.reset
            + self.refused
            + self.timed_out
            + self.protocol_error
            + self.other_error
    }
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Server { listen, workers } => run_server(listen, workers),
        Command::Client {
            address,
            connections,
            concurrency,
            timeout_ms,
            json,
        } => run_client(
            address,
            connections,
            concurrency,
            Duration::from_millis(timeout_ms),
            json,
        ),
    }
}

fn run_server(listen: SocketAddr, worker_count: usize) -> anyhow::Result<()> {
    anyhow::ensure!(worker_count > 0, "workers must be greater than zero");

    let listener = Arc::new(TcpListener::bind(listen)?);
    println!(
        "listening on {} with {worker_count} workers",
        listener.local_addr()?
    );

    let mut threads = Vec::with_capacity(worker_count);
    for index in 0..worker_count {
        let listener = listener.clone();
        threads.push(
            std::thread::Builder::new()
                .name(format!("tcp-server-{index}"))
                .spawn(move || {
                    loop {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                if let Err(error) = serve_connection(&mut stream) {
                                    eprintln!("connection failed: {error}");
                                }
                            }
                            Err(error) => eprintln!("accept failed: {error}"),
                        }
                    }
                })?,
        );
    }

    threads
        .into_iter()
        .next()
        .expect("server must have a worker")
        .join()
        .expect("server worker panicked");
    Ok(())
}

fn serve_connection(stream: &mut TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let mut request = [0; REQUEST.len()];
    stream.read_exact(&mut request)?;
    if request != REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request",
        ));
    }
    stream.write_all(RESPONSE)
}

fn run_client(
    address: SocketAddr,
    connections: u64,
    concurrency: usize,
    timeout: Duration,
    json: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(connections > 0, "connections must be greater than zero");
    anyhow::ensure!(concurrency > 0, "concurrency must be greater than zero");

    let worker_count = concurrency.min(usize::try_from(connections).unwrap_or(usize::MAX));
    let next = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut threads = Vec::with_capacity(worker_count);

    for index in 0..worker_count {
        let next = next.clone();
        threads.push(
            std::thread::Builder::new()
                .name(format!("tcp-client-{index}"))
                .spawn(move || {
                    let mut summary = Summary::default();
                    loop {
                        let attempt = next.fetch_add(1, Ordering::Relaxed);
                        if attempt >= connections {
                            break;
                        }
                        summary.record(run_attempt(address, timeout));
                    }
                    summary
                })?,
        );
    }

    let mut summary = Summary::default();
    for thread in threads {
        summary.merge(thread.join().expect("client worker panicked"));
    }
    let elapsed = start.elapsed();
    anyhow::ensure!(
        summary.attempted() == connections,
        "incomplete client accounting"
    );
    print_summary(&mut summary, elapsed, json);
    Ok(())
}

fn run_attempt(address: SocketAddr, timeout: Duration) -> AttemptResult {
    let start = Instant::now();
    let mut stream = match TcpStream::connect_timeout(&address, timeout) {
        Ok(stream) => stream,
        Err(error) => return classify_io_error(error),
    };
    if let Err(error) = stream.set_nodelay(true) {
        return classify_io_error(error);
    }
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        return classify_io_error(error);
    }
    if let Err(error) = stream.set_write_timeout(Some(timeout)) {
        return classify_io_error(error);
    }
    if let Err(error) = stream.write_all(REQUEST) {
        return classify_io_error(error);
    }

    let mut response = [0; RESPONSE.len()];
    if let Err(error) = stream.read_exact(&mut response) {
        return classify_io_error(error);
    }
    if response != RESPONSE {
        return AttemptResult::ProtocolError;
    }
    AttemptResult::Success(start.elapsed())
}

fn classify_io_error(error: io::Error) -> AttemptResult {
    match error.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => AttemptResult::Reset,
        io::ErrorKind::ConnectionRefused => AttemptResult::Refused,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => AttemptResult::TimedOut,
        _ => AttemptResult::Other,
    }
}

fn print_summary(summary: &mut Summary, elapsed: Duration, json: bool) {
    summary.latencies.sort_unstable();
    let elapsed_seconds = elapsed.as_secs_f64();
    let connections_per_second = summary.succeeded as f64 / elapsed_seconds;
    let success_percent = summary.succeeded as f64 * 100.0 / summary.attempted() as f64;
    let p50 = percentile_ms(&summary.latencies, 50);
    let p95 = percentile_ms(&summary.latencies, 95);
    let p99 = percentile_ms(&summary.latencies, 99);

    if json {
        println!(
            concat!(
                "{{\"attempted\":{},\"succeeded\":{},\"reset\":{},",
                "\"refused\":{},\"timed_out\":{},\"protocol_error\":{},",
                "\"other_error\":{},\"elapsed_seconds\":{:.6},",
                "\"connections_per_second\":{:.3},\"success_percent\":{:.3},",
                "\"latency_ms_p50\":{:.3},\"latency_ms_p95\":{:.3},",
                "\"latency_ms_p99\":{:.3}}}"
            ),
            summary.attempted(),
            summary.succeeded,
            summary.reset,
            summary.refused,
            summary.timed_out,
            summary.protocol_error,
            summary.other_error,
            elapsed_seconds,
            connections_per_second,
            success_percent,
            p50,
            p95,
            p99,
        );
    } else {
        println!("attempted:              {}", summary.attempted());
        println!("succeeded:              {}", summary.succeeded);
        println!("reset:                  {}", summary.reset);
        println!("refused:                {}", summary.refused);
        println!("timed out:              {}", summary.timed_out);
        println!("protocol errors:        {}", summary.protocol_error);
        println!("other errors:           {}", summary.other_error);
        println!("elapsed:                {elapsed_seconds:.3} s");
        println!("connections/second:     {connections_per_second:.1}");
        println!("success:                {success_percent:.2}%");
        println!("latency p50/p95/p99:    {p50:.3}/{p95:.3}/{p99:.3} ms");
    }
}

fn percentile_ms(sorted: &[Duration], percentile: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index].as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completes_wire_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_connection(&mut stream).unwrap();
        });

        assert!(matches!(
            run_attempt(address, Duration::from_secs(1)),
            AttemptResult::Success(_)
        ));
        server.join().unwrap();
    }

    #[test]
    fn percentile_uses_sorted_observations() {
        let observations = [
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(4),
            Duration::from_millis(5),
        ];
        assert_eq!(percentile_ms(&observations, 50), 3.0);
        assert_eq!(percentile_ms(&observations, 95), 5.0);
    }
}
