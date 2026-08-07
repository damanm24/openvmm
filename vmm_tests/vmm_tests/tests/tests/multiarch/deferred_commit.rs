// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deferred guest-memory commit tests.

use anyhow::Context as _;
use futures::AsyncBufReadExt as _;
use futures::io::BufReader;
use petri::MemoryConfig;
use petri::PetriVm;
use petri::PetriVmBuilder;
use petri::SIZE_1_GB;
use petri::openvmm::OpenVmmPetriBackend;
use petri::pipette::PipetteClient;
use petri::pipette::process::Child;
use petri::pipette::process::Stdio;
use petri_artifacts_common::tags::OsFlavor;
use vmm_test_macros::openvmm_test;

const RAM_BYTES: u64 = 4 * SIZE_1_GB;
const TOUCHED_BYTES: u64 = SIZE_1_GB;

#[cfg(windows)]
#[openvmm_test(
    uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    uefi_x64(vhd(ubuntu_2504_server_x64))
)]
async fn deferred_commit_off_reserves_complete_guest_memory(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    let (mut vm, agent) = config
        .with_memory(MemoryConfig {
            startup_bytes: RAM_BYTES,
            private_memory: Some(true),
            deferred_commit: false,
            host_numa_node: Some(0),
            transparent_hugepages: true,
            ..Default::default()
        })
        .run()
        .await?;

    let private_bytes = petri::process_memory::process_private_memory_bytes(vm.backend().pid())?;
    tracing::info!(private_bytes, RAM_BYTES, "measured eager guest memory");
    anyhow::ensure!(
        private_bytes >= RAM_BYTES,
        "without deferred commit, OpenVMM private commit {private_bytes:#x} was less than guest RAM {RAM_BYTES:#x}"
    );

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

#[openvmm_test(
    uefi_x64(vhd(windows_datacenter_core_2022_x64)),
    uefi_x64(vhd(ubuntu_2504_server_x64))
)]
async fn deferred_commit_grows_with_guest_demand(
    config: PetriVmBuilder<OpenVmmPetriBackend>,
) -> anyhow::Result<()> {
    let os_flavor = config.os_flavor();
    let (mut vm, agent) = config
        .with_memory(MemoryConfig {
            startup_bytes: RAM_BYTES,
            private_memory: Some(true),
            deferred_commit: true,
            host_numa_node: Some(0),
            transparent_hugepages: true,
            ..Default::default()
        })
        .run()
        .await?;

    log_deferred_memory_diagnostics(&vm, &agent, os_flavor, "after_agent_ready").await?;
    let initial_private_bytes =
        petri::process_memory::process_private_memory_bytes(vm.backend().pid())?;
    tracing::info!(
        initial_private_bytes,
        RAM_BYTES,
        "measured initial deferred guest memory"
    );
    anyhow::ensure!(
        initial_private_bytes < RAM_BYTES,
        "with deferred commit, initial OpenVMM private memory {initial_private_bytes:#x} was not less than guest RAM {RAM_BYTES:#x}"
    );

    let _memory_pressure = start_memory_pressure(&agent, os_flavor, TOUCHED_BYTES).await?;
    log_deferred_memory_diagnostics(&vm, &agent, os_flavor, "after_guest_pressure").await?;
    let grown_private_bytes =
        petri::process_memory::process_private_memory_bytes(vm.backend().pid())?;
    let minimum_growth = TOUCHED_BYTES * 7 / 8;
    tracing::info!(
        initial_private_bytes,
        grown_private_bytes,
        TOUCHED_BYTES,
        "measured deferred guest memory growth"
    );
    anyhow::ensure!(
        grown_private_bytes >= initial_private_bytes + minimum_growth,
        "touching {TOUCHED_BYTES:#x} guest bytes grew OpenVMM private memory only from {initial_private_bytes:#x} to {grown_private_bytes:#x}"
    );
    anyhow::ensure!(
        grown_private_bytes < RAM_BYTES,
        "after touching {TOUCHED_BYTES:#x} guest bytes, deferred OpenVMM private memory {grown_private_bytes:#x} reached the complete guest RAM size {RAM_BYTES:#x}"
    );

    agent.power_off().await?;
    vm.wait_for_clean_teardown().await?;
    Ok(())
}

async fn log_deferred_memory_diagnostics(
    vm: &PetriVm<OpenVmmPetriBackend>,
    agent: &PipetteClient,
    os_flavor: OsFlavor,
    phase: &str,
) -> anyhow::Result<()> {
    let mappings = vm
        .inspect_vmm("memory/mappings")
        .await
        .with_context(|| format!("inspecting deferred memory mappings during {phase}"))?;
    let mappings_json = mappings.json().to_string();
    let mappings_value: serde_json::Value = serde_json::from_str(&mappings_json)
        .context("parsing deferred memory mapping inspect output")?;
    let resident_bytes = mappings_value.as_object().and_then(|entries| {
        let values = entries
            .values()
            .filter(|entry| {
                entry["private"].as_bool() == Some(true)
                    && entry["deferred_commit"].as_bool() == Some(true)
            })
            .filter_map(|entry| entry["resident_bytes"].as_u64())
            .collect::<Vec<_>>();
        (!values.is_empty()).then(|| values.into_iter().sum::<u64>())
    });
    tracing::info!(
        phase,
        ?resident_bytes,
        mappings = %mappings_json,
        "deferred guest memory mapping diagnostics"
    );

    let mut command = match os_flavor {
        OsFlavor::Linux => {
            let mut command = agent.command("sh");
            command.args([
                "-c",
                "grep -E '^(MemTotal|MemFree|MemAvailable|Active\\(anon\\)|Inactive\\(anon\\)|AnonPages):' /proc/meminfo",
            ]);
            command
        }
        OsFlavor::Windows => {
            let mut command = agent.command("powershell.exe");
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$os = Get-CimInstance Win32_OperatingSystem; $memory = Get-CimInstance Win32_PerfRawData_PerfOS_Memory; [ordered]@{ TotalVisibleMemoryBytes = [uint64]$os.TotalVisibleMemorySize * 1KB; FreePhysicalMemoryBytes = [uint64]$os.FreePhysicalMemory * 1KB; AvailableBytes = [uint64]$memory.AvailableBytes; FreeAndZeroPageListBytes = [uint64]$memory.FreeAndZeroPageListBytes; ModifiedPageListBytes = [uint64]$memory.ModifiedPageListBytes; StandbyCacheNormalPriorityBytes = [uint64]$memory.StandbyCacheNormalPriorityBytes } | ConvertTo-Json -Compress",
            ]);
            command
        }
        _ => return Ok(()),
    };
    let output = command.output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        tracing::info!(phase, guest_memory = %stdout.trim(), "guest memory diagnostics");
    } else {
        tracing::warn!(
            phase,
            status = %output.status,
            stderr = %stderr.trim(),
            "guest memory diagnostics unavailable"
        );
    }

    Ok(())
}

async fn start_memory_pressure(
    agent: &PipetteClient,
    os_flavor: OsFlavor,
    bytes: u64,
) -> anyhow::Result<Child> {
    let mut command = match os_flavor {
        OsFlavor::Linux => {
            let mut command = agent.command("sh");
            command.args([
                "-c",
                &format!(
                    "dd if=/dev/zero of=/dev/shm/openvmm-deferred-commit-test bs=1M count={} status=none && echo ready && sleep 600",
                    bytes / (1024 * 1024)
                ),
            ]);
            command
        }
        OsFlavor::Windows => {
            let mut command = agent.command("powershell.exe");
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "$memory = [byte[]]::new({bytes}); for ($i = 0; $i -lt $memory.Length; $i += 4096) {{ $memory[$i] = 1 }}; [Console]::Out.WriteLine('ready'); Start-Sleep -Seconds 600"
                ),
            ]);
            command
        }
        _ => anyhow::bail!("unsupported guest OS for memory pressure: {os_flavor:?}"),
    };

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().await?;
    let stdout = child
        .stdout
        .take()
        .context("memory pressure process has no stdout")?;
    let mut stdout = BufReader::new(stdout);
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .await
        .context("waiting for guest memory pressure")?;
    anyhow::ensure!(
        ready.trim() == "ready",
        "guest memory pressure failed before becoming ready"
    );
    Ok(child)
}
