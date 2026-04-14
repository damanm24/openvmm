// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filesystem I/O performance test via fio over virtio-fs.
//!
//! Boots a minimal Linux VM (linux_direct, pipette as PID 1) with a
//! virtio-fs device exposing a host directory and a read-only virtio-blk
//! device carrying an erofs image with fio pre-installed. Measures
//! sequential/random read/write bandwidth (MiB/s) and IOPS across multiple
//! iterations. Uses warm mode: the VM is booted once and reused for all
//! iterations.

use super::fio_helpers;
use super::fio_helpers::FioTarget;
use crate::report::MetricResult;
use anyhow::Context as _;
use petri::pipette::cmd;
use petri_artifacts_common::tags::MachineArch;
use std::path::PathBuf;
use vm_resource::IntoResource;

/// Filesystem I/O test via fio over virtio-fs.
pub struct FsIoTest {
    /// Print guest diagnostics.
    pub diag: bool,
    /// Host directory to share via virtio-fs. If `None`, a temporary
    /// directory is created automatically.
    pub share_dir: Option<PathBuf>,
    /// If set, record per-phase perf traces in this directory.
    pub perf_dir: Option<PathBuf>,
}

/// State kept across warm iterations.
pub struct FsIoTestState {
    vm: petri::PetriVm<petri::openvmm::OpenVmmPetriBackend>,
    agent: petri::pipette::PipetteClient,
    /// Temporary directory on the host (kept alive for the VM's lifetime).
    _share_dir: Option<tempfile::TempDir>,
}

/// Tag used for the virtiofs mount inside the guest.
const VIRTIOFS_TAG: &str = "perfshare";
/// Guest mount point for the virtiofs device (on the writable root tmpfs).
const VIRTIOFS_ROOT_MOUNT: &str = "/mnt/virtiofs";
/// Path as seen from inside the chroot (where fio runs).
const VIRTIOFS_CHROOT_PATH: &str = "/mnt/virtiofs";

/// Register artifacts needed by the filesystem I/O test.
pub fn register_artifacts(resolver: &petri::ArtifactResolver<'_>) {
    let firmware = fio_helpers::build_firmware(resolver);
    petri::PetriVmArtifacts::<petri::openvmm::OpenVmmPetriBackend>::new(
        resolver,
        firmware,
        MachineArch::host(),
        true,
    );
    fio_helpers::require_petritools_erofs(resolver);
}

impl crate::harness::WarmPerfTest for FsIoTest {
    type State = FsIoTestState;

    fn name(&self) -> &str {
        "fs_io_virtiofs"
    }

    fn warmup_iterations(&self) -> u32 {
        1
    }

    async fn setup(
        &self,
        resolver: &petri::ArtifactResolver<'_>,
        driver: &pal_async::DefaultDriver,
    ) -> anyhow::Result<FsIoTestState> {
        // Determine the host directory to share.
        let (share_path, temp_dir) = match &self.share_dir {
            Some(p) => {
                std::fs::create_dir_all(p).with_context(|| {
                    format!("failed to create share directory at {}", p.display())
                })?;
                (p.clone(), None)
            }
            None => {
                let td = tempfile::tempdir().context("failed to create temp share directory")?;
                let p = td.path().to_path_buf();
                tracing::info!(
                    path = %p.display(),
                    "using temporary directory for virtio-fs share"
                );
                (p, Some(td))
            }
        };

        let firmware = fio_helpers::build_firmware(resolver);

        let artifacts = petri::PetriVmArtifacts::<petri::openvmm::OpenVmmPetriBackend>::new(
            resolver,
            firmware,
            MachineArch::host(),
            true,
        )
        .context("firmware/arch not compatible with OpenVMM backend")?;

        let mut post_test_hooks = Vec::new();
        let log_source = crate::log_source();
        let params = petri::PetriTestParams {
            test_name: "fs_io",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        // Open the perf rootfs erofs image for the virtio-blk device.
        let erofs_path = fio_helpers::require_petritools_erofs(resolver);
        let erofs_file = fs_err::File::open(&erofs_path)?;

        let share_root = share_path
            .to_str()
            .context("share directory path is not valid UTF-8")?
            .to_string();

        let mut builder = petri::PetriVmBuilder::minimal(params, artifacts, driver)?
            .with_processor_topology(petri::ProcessorTopology {
                vp_count: 2,
                ..Default::default()
            })
            .with_memory(petri::MemoryConfig {
                startup_bytes: 1024 * 1024 * 1024, // 1 GB
                ..Default::default()
            });

        // Attach erofs (for fio tooling) and virtio-fs device on PCIe.
        builder = builder.modify_backend(move |b| {
            b.with_nic()
                .with_pcie_root_topology(1, 1, 2)
                .with_custom_config(|c| {
                    use disk_backend_resources::FileDiskHandle;
                    use openvmm_defs::config::PcieDeviceConfig;

                    // erofs image on port 0
                    c.pcie_devices.push(PcieDeviceConfig {
                        port_name: "s0rc0rp0".into(),
                        resource: virtio_resources::VirtioPciDeviceHandle(
                            virtio_resources::blk::VirtioBlkHandle {
                                disk: FileDiskHandle(erofs_file.into()).into_resource(),
                                read_only: true,
                            }
                            .into_resource(),
                        )
                        .into_resource(),
                    });
                    // virtio-fs device on port 1
                    c.pcie_devices.push(PcieDeviceConfig {
                        port_name: "s0rc0rp1".into(),
                        resource: virtio_resources::VirtioPciDeviceHandle(
                            virtio_resources::fs::VirtioFsHandle {
                                tag: VIRTIOFS_TAG.to_string(),
                                fs: virtio_resources::fs::VirtioFsBackend::HostFs {
                                    root_path: share_root,
                                    mount_options: String::new(),
                                },
                            }
                            .into_resource(),
                        )
                        .into_resource(),
                    });
                })
        });

        if !self.diag {
            builder = builder.without_screenshots();
        } else {
            builder = builder.with_serial_output();
        }

        let (vm, agent) = builder.run().await.context("failed to boot minimal VM")?;

        // Mount the erofs image and prepare chroot (fio is pre-installed).
        fio_helpers::mount_erofs_chroot(&agent).await?;

        // Mount virtiofs on the writable root tmpfs first.
        agent
            .mount(VIRTIOFS_TAG, VIRTIOFS_ROOT_MOUNT, "virtiofs", 0, true)
            .await
            .context("failed to mount virtiofs in guest")?;

        // Bind-mount into the read-only erofs chroot so fio can access it.
        // Layer a writable tmpfs on /perf/mnt, then bind-mount virtiofs in.
        let sh = agent.unix_shell();
        cmd!(sh, "mount -t tmpfs tmpfs /perf/mnt")
            .run()
            .await
            .context("failed to mount tmpfs on /perf/mnt")?;
        cmd!(sh, "mkdir -p /perf/mnt/virtiofs")
            .run()
            .await
            .context("failed to create virtiofs mountpoint in chroot")?;
        cmd!(sh, "mount --bind /mnt/virtiofs /perf/mnt/virtiofs")
            .run()
            .await
            .context("failed to bind-mount virtiofs into chroot")?;

        tracing::info!(
            mount = VIRTIOFS_CHROOT_PATH,
            tag = VIRTIOFS_TAG,
            "virtiofs mounted in guest chroot"
        );

        Ok(FsIoTestState {
            vm,
            agent,
            _share_dir: temp_dir,
        })
    }

    async fn run_once(&self, state: &mut FsIoTestState) -> anyhow::Result<Vec<MetricResult>> {
        let pid = state.vm.backend().pid();
        let mut recorder = crate::harness::PerfRecorder::new(self.perf_dir.as_deref(), pid)?;
        let target = FioTarget::Directory {
            path: VIRTIOFS_CHROOT_PATH,
            file_size: "256M",
        };

        fio_helpers::run_standard_fio_suite(&state.agent, &target, "virtiofs", &mut recorder).await
    }

    async fn teardown(&self, state: FsIoTestState) -> anyhow::Result<()> {
        state.agent.power_off().await?;
        state.vm.wait_for_clean_teardown().await?;
        Ok(())
    }
}
