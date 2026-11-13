// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! virtio-fs DAX tests using a section-backed share.

use anyhow::Context;
use openvmm_defs::config::PcieDeviceConfig;
use openvmm_defs::config::PcieMmioRangeConfig;
use pal::windows::ObjectAttributes;
use pal::windows::UnicodeString;
use petri::PetriVmBuilder;
use petri::SIZE_1_GB;
use petri::openvmm::OpenVmmPetriBackend;
use petri::pipette::cmd;
use virtio_resources::VirtioPciDeviceHandle;
use virtio_resources::fs::VirtioFsBackend;
use virtio_resources::fs::VirtioFsHandle;
use vm_resource::IntoResource;
use vmm_test_macros::openvmm_test;

const DIRECTORY_ALL_ACCESS: u32 = 0x000F_000F;

/// Replaces DAX mappings in place the way a Linux guest does: a read maps a
/// window read-only and a later write maps the same window again writable.
///
/// The guest script is passed in through a second, regular virtio-fs share,
/// which also carries the result back. Set `VIRTIOFS_DAX_SCRIPT` to a host path
/// to run a different script without rebuilding.
#[openvmm_test(uefi_x64(vhd(ubuntu_2404_server_x64)))]
async fn virtiofs_dax_overlapping_mappings(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    const SCRIPT: &str = "virtiofs_dax_overlap.py";

    let host_dir = tempfile::tempdir()?;
    let script = match std::env::var_os("VIRTIOFS_DAX_SCRIPT") {
        Some(path) => fs_err::read(path)?,
        None => include_bytes!("../../../test_data/virtiofs_dax_overlap.py").to_vec(),
    };
    fs_err::write(host_dir.path().join(SCRIPT), script)?;

    // SectionFs serves the named sections in an NT object directory, and
    // creates one when the guest creates a file.
    let dax_root = format!(
        "\\BaseNamedObjects\\openvmm-dax-{}",
        guid::Guid::new_random()
    );
    let dax_root_name = UnicodeString::try_from(dax_root.as_str())
        .ok()
        .context("DAX root path too long")?;
    let _dax_dir = pal::windows::create_object_directory(
        ObjectAttributes::new().name(&dax_root_name),
        DIRECTORY_ALL_ACCESS,
    )
    .context("failed to create the DAX object directory")?;

    let host_share = VirtioFsHandle {
        tag: "hostshare".into(),
        fs: VirtioFsBackend::HostFs {
            root_path: host_dir
                .path()
                .to_str()
                .context("share path is not UTF-8")?
                .to_owned(),
            mount_options: String::new(),
        },
    }
    .into_resource();
    let dax_share = VirtioFsHandle {
        tag: "daxfs".into(),
        fs: VirtioFsBackend::SectionFs {
            root_path: dax_root,
        },
    }
    .into_resource();

    let (vm, agent) = config
        .modify_backend(move |b| {
            // virtio-fs does not support save/restore.
            b.without_save_restore()
                .with_pcie_root_topology(1, 1, 2)
                .with_custom_config(|c| {
                    // Leave room for the 8 GiB DAX window BAR.
                    for rc in &mut c.pcie_root_complexes {
                        rc.high_mmio = PcieMmioRangeConfig::Dynamic {
                            size: 16 * SIZE_1_GB,
                        };
                    }
                    c.pcie_devices.push(PcieDeviceConfig {
                        port_name: "s0rc0rp0".into(),
                        resource: VirtioPciDeviceHandle(host_share).into_resource(),
                    });
                    c.pcie_devices.push(PcieDeviceConfig {
                        port_name: "s0rc0rp1".into(),
                        resource: VirtioPciDeviceHandle(dax_share).into_resource(),
                    });
                })
        })
        .run()
        .await?;

    mount_virtio_fs(&agent, "hostshare", "/mnt/host", "").await?;
    mount_virtio_fs(&agent, "daxfs", "/mnt/dax", "-o dax=always").await?;
    let sh = agent.unix_shell();
    let mounts = cmd!(sh, "cat /proc/mounts").read().await?;
    let dax_mount = mounts
        .lines()
        .find(|l| l.contains("/mnt/dax"))
        .context("DAX share is not mounted")?;
    tracing::info!(dax_mount, "DAX share mounted");
    anyhow::ensure!(
        dax_mount.contains("dax=always"),
        "virtio-fs DAX is not enabled: {dax_mount}"
    );

    let iterations = std::env::var("DAX_RACE_ITERATIONS").unwrap_or_else(|_| "64".into());
    let output = cmd!(sh, "python3 /mnt/host/{SCRIPT} /mnt/dax /mnt/host")
        .env("DAX_RACE_ITERATIONS", iterations)
        .ignore_status()
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    tracing::info!(%stdout, %stderr, status = ?output.status, "guest DAX script finished");
    let dmesg = cmd!(sh, "dmesg").read().await?;
    for line in dmesg
        .lines()
        .filter(|l| ["virtio", "fuse", "dax", "BAR"].iter().any(|s| l.contains(s)))
    {
        tracing::info!(line, "guest dmesg");
    }
    anyhow::ensure!(
        output.status.success(),
        "guest DAX script failed: {stdout}\n{stderr}"
    );
    anyhow::ensure!(
        fs_err::read_to_string(host_dir.path().join("result.txt"))?.trim() == "PASS",
        "guest did not report success through the host share"
    );

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

async fn mount_virtio_fs(
    agent: &petri::pipette::PipetteClient,
    tag: &str,
    target: &str,
    options: &str,
) -> anyhow::Result<()> {
    let sh = agent.unix_shell();
    // The device may still be probing when the agent starts.
    let script = format!(
        "mkdir -p {target}; i=0; while [ $i -lt 200 ]; do \
         mount -t virtiofs {options} {tag} {target} && exit 0; \
         i=$((i + 1)); sleep 0.1; done; exit 1"
    );
    cmd!(sh, "sh -c {script}")
        .run()
        .await
        .with_context(|| format!("mounting virtio-fs share {tag}"))
}
