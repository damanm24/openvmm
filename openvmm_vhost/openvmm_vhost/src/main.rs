// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! openvmm_vhost: a vhost-user backend binary that hosts OpenVMM virtio
//! devices over a Unix domain socket (mesh bootstrap on Windows).
//!
//! The process resolves an OpenVMM virtio device, accepts one vhost-user
//! frontend connection, maps the frontend's shared guest memory, and services
//! its virtqueues until the connection closes. The CLI can expose a file as a
//! virtio-blk device or a host directory as a virtio-fs device; OpenVMM
//! connects to it with its `--vhost-user` option.
//!
//! Running a device in a separate process lets it execute under a different
//! identity than the VMM. For example, a virtio-fs backend can be launched
//! with a specific user token so that guest file access is checked against
//! that token.
//!
//! Start it as `openvmm_vhost --socket <path> blk --disk <image>` or
//! `openvmm_vhost --socket <path> fs --path <dir>` before launching the
//! frontend VMM.

#![forbid(unsafe_code)]

fn main() {
    #[cfg(any(target_os = "linux", windows))]
    if let Err(e) = backend::main() {
        eprintln!("openvmm_vhost failed: {e:#}");
        std::process::exit(1);
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        eprintln!("openvmm_vhost is only supported on Linux and Windows");
        std::process::exit(1);
    }
}

#[cfg(any(target_os = "linux", windows))]
mod backend {
    use anyhow::Context as _;
    use clap::Parser;
    use clap::Subcommand;
    use disk_backend_resources::FileDiskHandle;
    use pal_async::DefaultPool;
    use std::path::PathBuf;
    use vhost_user_backend::VhostUserDeviceServer;
    use virtio::resolve::VirtioResolveInput;
    use virtio_resources::blk::VirtioBlkHandle;
    use virtio_resources::fs::VirtioFsBackend;
    use virtio_resources::fs::VirtioFsHandle;
    use vm_resource::Resource;
    use vm_resource::ResourceResolver;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    // Register the resolvers needed by this binary.
    vm_resource::register_static_resolvers! {
        virtio_blk::resolver::VirtioBlkResolver,
        disk_file::FileDiskResolver,
        virtiofs::resolver::VirtioFsResolver,
    }

    /// openvmm_vhost: vhost-user backend for OpenVMM virtio devices.
    #[derive(Parser)]
    #[command(name = "openvmm_vhost")]
    struct Cli {
        /// Path to the Unix domain socket.
        #[arg(long)]
        socket: PathBuf,

        /// Device type to expose.
        #[command(subcommand)]
        device: DeviceCommand,
    }

    #[derive(Subcommand)]
    enum DeviceCommand {
        /// Expose a virtio-blk device.
        Blk {
            /// Path to the disk image file.
            #[arg(long)]
            disk: PathBuf,

            /// Open the disk as read-only.
            #[arg(long, default_value_t = false)]
            read_only: bool,
        },
        /// Expose a host directory as a virtio-fs device.
        Fs {
            /// Path to the host directory to share.
            #[arg(long)]
            path: PathBuf,

            /// Mount tag presented to the guest.
            #[arg(long, default_value = "myfs")]
            tag: String,

            /// Volume mount options (for example `uid=1000;gid=1000;ro`).
            #[arg(long, default_value = "")]
            mount_options: String,
        },
    }

    pub fn main() -> anyhow::Result<()> {
        // Default to info-level logging so server lifecycle events are visible.
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();

        let cli = Cli::parse();

        DefaultPool::run_with(|driver: pal_async::DefaultDriver| async move {
            let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
            let resolver = ResourceResolver::new();

            let server = match &cli.device {
                DeviceCommand::Blk { disk, read_only } => {
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(!read_only)
                        .open(disk)
                        .with_context(|| format!("failed to open disk: {}", disk.display()))?;

                    let virtio_handle = VirtioBlkHandle {
                        disk: Resource::new(FileDiskHandle(file)),
                        read_only: *read_only,
                        serial: None,
                    };

                    let resolved = resolver
                        .resolve(
                            Resource::new(virtio_handle),
                            VirtioResolveInput {
                                driver_source: &driver_source,
                            },
                        )
                        .await
                        .context("failed to resolve virtio-blk device")?;

                    VhostUserDeviceServer::new(resolved.0)
                }
                DeviceCommand::Fs {
                    path,
                    tag,
                    mount_options,
                } => {
                    let root_path = path
                        .to_str()
                        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))?
                        .to_owned();

                    // HostFs does not use a DAX window, which vhost-user
                    // shared memory regions do not support yet.
                    let virtio_handle = VirtioFsHandle {
                        tag: tag.clone(),
                        fs: VirtioFsBackend::HostFs {
                            root_path,
                            mount_options: mount_options.clone(),
                        },
                    };

                    let resolved = resolver
                        .resolve(
                            Resource::new(virtio_handle),
                            VirtioResolveInput {
                                driver_source: &driver_source,
                            },
                        )
                        .await
                        .context("failed to resolve virtio-fs device")?;

                    VhostUserDeviceServer::new(resolved.0)
                }
            };

            server
                .run(&driver, &cli.socket)
                .await
                .context("vhost-user server failed")
        })
    }
}
