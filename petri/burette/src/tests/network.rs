// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network throughput performance test.
//!
//! Boots a minimal Linux VM (linux_direct, pipette as PID 1) with a NIC
//! and a read-only virtio-blk device carrying an erofs image with iperf3
//! pre-installed. Measures TCP throughput (Gbps) and UDP packet rate (pps)
//! between the guest and host across multiple iterations. Uses warm mode: the
//! VM is booted once and reused for all iterations.
//!
//! Supports three NIC backends:
//! - `vmbus`: VMBus synthetic NIC (NETVSP) + Consomme NAT
//! - `virtio-net`: virtio-net on PCIe + Consomme NAT
//! - `virtio-net-tap`: virtio-net on PCIe + Linux TAP device (Linux only)
//!
//! The TAP backend provides a direct host↔guest L2 path (no NAT), which
//! enables additional metrics not available with Consomme:
//! - UDP RX throughput (host sends to guest)
//! - Ping round-trip latency

use crate::report::MetricResult;
use anyhow::Context as _;
use petri::pipette::cmd;

use petri_artifacts_common::tags::MachineArch;

/// Which NIC backend to use for the network test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum NicBackend {
    /// VMBus synthetic NIC (NETVSP) backed by Consomme NAT.
    Vmbus,
    /// Virtio-net on PCIe backed by Consomme NAT.
    #[value(name = "virtio-net")]
    VirtioNet,
    /// Virtio-net on PCIe backed by a Linux TAP device (Linux only).
    /// Provides direct host↔guest connectivity; requires CAP_NET_ADMIN.
    #[value(name = "virtio-net-tap")]
    VirtioNetTap,
}

impl std::fmt::Display for NicBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use clap::ValueEnum;
        f.write_str(self.to_possible_value().unwrap().get_name())
    }
}

/// Network throughput test via iperf3.
pub struct NetworkTest {
    /// Print guest serial output and take framebuffer screenshots.
    pub diag: bool,
    /// Which NIC backend to test.
    pub nic: NicBackend,
    /// If set, record per-phase perf traces in this directory.
    pub perf_dir: Option<std::path::PathBuf>,
    /// TAP device name — used only when `nic == VirtioNetTap`.
    /// Burette creates and removes this device automatically.
    pub tap_name: String,
}

/// State kept across warm iterations: the running VM and pipette agent.
pub struct NetworkTestState {
    vm: petri::PetriVm<petri::openvmm::OpenVmmPetriBackend>,
    agent: petri::pipette::PipetteClient,
    /// The host IP address reachable from the guest.
    /// For Consomme: the host's real routable IP (detected via routing table).
    /// For TAP: the host-side TAP address (10.0.0.1).
    host_ip: String,
    /// For TAP only: the guest-side IP (10.0.0.2) used by host→guest tests.
    guest_ip: Option<String>,
    /// Async driver for timers.
    driver: pal_async::DefaultDriver,
    /// TAP device name to remove on teardown, if TAP is in use.
    tap_name: Option<String>,
}

fn build_firmware(resolver: &petri::ArtifactResolver<'_>) -> petri::Firmware {
    petri::Firmware::linux_direct(resolver, MachineArch::host())
}

fn require_petritools_erofs(
    resolver: &petri::ArtifactResolver<'_>,
) -> petri_artifacts_core::ResolvedArtifact {
    use petri_artifacts_vmm_test::artifacts::petritools::*;
    match MachineArch::host() {
        MachineArch::X86_64 => resolver.require(PETRITOOLS_EROFS_X64).erase(),
        MachineArch::Aarch64 => resolver.require(PETRITOOLS_EROFS_AARCH64).erase(),
    }
}

/// Register artifacts needed by the network test.
pub fn register_artifacts(resolver: &petri::ArtifactResolver<'_>) {
    let firmware = build_firmware(resolver);
    petri::PetriVmArtifacts::<petri::openvmm::OpenVmmPetriBackend>::new(
        resolver,
        firmware,
        MachineArch::host(),
        true,
    );
    require_petritools_erofs(resolver);
}

impl crate::harness::WarmPerfTest for NetworkTest {
    type State = NetworkTestState;

    fn name(&self) -> &str {
        match self.nic {
            NicBackend::Vmbus => "network_vmbus",
            NicBackend::VirtioNet => "network_virtio",
            NicBackend::VirtioNetTap => "network_virtio_tap",
        }
    }

    fn warmup_iterations(&self) -> u32 {
        1
    }

    async fn setup(
        &self,
        resolver: &petri::ArtifactResolver<'_>,
        driver: &pal_async::DefaultDriver,
    ) -> anyhow::Result<NetworkTestState> {
        // Verify host iperf3 is available (cross-platform).
        let status = std::process::Command::new("iperf3")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        anyhow::ensure!(
            status.is_ok_and(|s| s.success()),
            "iperf3 not found on host — install it (e.g. apt install iperf3)"
        );

        // TAP backend is Linux-only; reject early on other platforms.
        if self.nic == NicBackend::VirtioNetTap {
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!(
                "virtio-net-tap requires Linux (CAP_NET_ADMIN); \
                 use --nic vmbus or --nic virtio-net on this platform"
            );
        }

        let firmware = build_firmware(resolver);

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
            test_name: "network",
            logger: &log_source,
            post_test_hooks: &mut post_test_hooks,
        };

        // Open the perf rootfs erofs image for the virtio-blk device.
        let erofs_path = require_petritools_erofs(resolver);
        let erofs_file = fs_err::File::open(&erofs_path)?;

        // For TAP: create and configure the host-side TAP interface.
        let mut active_tap_name: Option<String> = None;
        #[cfg(target_os = "linux")]
        if self.nic == NicBackend::VirtioNetTap {
            let tap = &self.tap_name;
            let result = setup_tap_device(tap);
            match result {
                Ok(()) => {
                    active_tap_name = Some(tap.clone());
                    tracing::info!(tap = %tap, "TAP device created and configured");
                }
                Err(e) => {
                    // Clean up in case of partial setup.
                    let _ = teardown_tap_device(tap);
                    return Err(e);
                }
            }
        }

        let mut builder = petri::PetriVmBuilder::minimal(params, artifacts, driver)?
            .with_processor_topology(petri::ProcessorTopology {
                vp_count: 2,
                ..Default::default()
            })
            .with_memory(petri::MemoryConfig {
                startup_bytes: 1024 * 1024 * 1024, // 1 GB
                ..Default::default()
            })
            .modify_backend({
                let nic = self.nic;
                let tap_name = self.tap_name.clone();
                move |c| {
                    let (c, blk_port) = match nic {
                        NicBackend::Vmbus => {
                            (c.with_pcie_root_topology(1, 1, 1).with_nic(), "s0rc0rp0")
                        }
                        NicBackend::VirtioNet => (
                            c.with_pcie_root_topology(1, 1, 2)
                                .with_virtio_nic("s0rc0rp0"),
                            "s0rc0rp1",
                        ),
                        NicBackend::VirtioNetTap => {
                            #[cfg(target_os = "linux")]
                            {
                                (
                                    c.with_pcie_root_topology(1, 1, 2)
                                        .with_virtio_nic_tap("s0rc0rp0", &tap_name),
                                    "s0rc0rp1",
                                )
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                let _ = tap_name;
                                // Unreachable: rejected above in setup().
                                unreachable!("VirtioNetTap on non-Linux")
                            }
                        }
                    };
                    // Attach the erofs image as a read-only virtio-blk device
                    // on a PCIe root port.
                    c.with_custom_config(|config| {
                        use disk_backend_resources::FileDiskHandle;
                        use openvmm_defs::config::PcieDeviceConfig;
                        use vm_resource::IntoResource;

                        config.pcie_devices.push(PcieDeviceConfig {
                            port_name: blk_port.into(),
                            resource: virtio_resources::VirtioPciDeviceHandle(
                                virtio_resources::blk::VirtioBlkHandle {
                                    disk: FileDiskHandle(erofs_file.into()).into_resource(),
                                    read_only: true,
                                }
                                .into_resource(),
                            )
                            .into_resource(),
                        });
                    })
                }
            });

        if !self.diag {
            builder = builder.without_screenshots();
        } else {
            builder = builder.with_serial_output();
        }

        let (vm, agent) = builder.run().await.context("failed to boot minimal VM")?;

        // Bring up guest networking.
        let sh = agent.unix_shell();
        match self.nic {
            NicBackend::VirtioNetTap => {
                // TAP: direct L2 path; assign static IP (no DHCP needed).
                cmd!(sh, "ifconfig eth0 10.0.0.2/24 up").run().await?;
            }
            NicBackend::Vmbus | NicBackend::VirtioNet => {
                // Consomme NAT: use DHCP.
                cmd!(sh, "ifconfig eth0 up").run().await?;
                cmd!(sh, "udhcpc eth0").run().await?;
            }
        }

        // Mount the erofs image and prepare chroot.
        agent
            .mount("/dev/vda", "/perf", "erofs", 1 /* MS_RDONLY */, true)
            .await
            .context("failed to mount erofs on /dev/vda")?;
        agent
            .prepare_chroot("/perf")
            .await
            .context("failed to prepare chroot at /perf")?;

        // Determine host and guest IPs for the test.
        let (host_ip, guest_ip) = match self.nic {
            NicBackend::VirtioNetTap => {
                // TAP: host is 10.0.0.1, guest is 10.0.0.2.
                ("10.0.0.1".to_string(), Some("10.0.0.2".to_string()))
            }
            NicBackend::Vmbus | NicBackend::VirtioNet => {
                // Consomme NATs outbound traffic; the guest reaches the host
                // at the host's real routable address.
                let ip = detect_host_ip().context("failed to detect host IP")?;
                tracing::info!(host_ip = %ip, "detected host IP for iperf3 server");
                (ip, None)
            }
        };

        Ok(NetworkTestState {
            vm,
            agent,
            host_ip,
            guest_ip,
            driver: driver.clone(),
            tap_name: active_tap_name,
        })
    }

    async fn run_once(&self, state: &mut NetworkTestState) -> anyhow::Result<Vec<MetricResult>> {
        let mut metrics = Vec::new();
        let label = self.nic;
        let pid = state.vm.backend().pid();
        let mut recorder = crate::harness::PerfRecorder::new(self.perf_dir.as_deref(), pid)?;
        let mut timer = pal_async::timer::PolledTimer::new(&state.driver);
        let perf_delay = std::time::Duration::from_millis(500);

        // TCP TX (guest sends to host)
        let name = format!("net_{label}_tcp_tx_gbps");
        recorder.start(&name)?;
        timer.sleep(perf_delay).await;
        let m = run_iperf3_test(
            &state.agent,
            &state.host_ip,
            None,
            5201,
            &name,
            IperfMode::TcpTx,
            &mut timer,
        )
        .await
        .context("TCP TX test failed")?;
        recorder.stop()?;
        metrics.push(m);

        // TCP RX (host sends to guest, -R flag)
        let name = format!("net_{label}_tcp_rx_gbps");
        recorder.start(&name)?;
        timer.sleep(perf_delay).await;
        let m = run_iperf3_test(
            &state.agent,
            &state.host_ip,
            None,
            5202,
            &name,
            IperfMode::TcpRx,
            &mut timer,
        )
        .await
        .context("TCP RX test failed")?;
        recorder.stop()?;
        metrics.push(m);

        // UDP TX (guest sends to host)
        let name = format!("net_{label}_udp_tx_pps");
        recorder.start(&name)?;
        timer.sleep(perf_delay).await;
        let m = run_iperf3_test(
            &state.agent,
            &state.host_ip,
            None,
            5203,
            &name,
            IperfMode::UdpTx,
            &mut timer,
        )
        .await
        .context("UDP TX test failed")?;
        recorder.stop()?;
        metrics.push(m);

        // TAP-only metrics: UDP RX and ping RTT.
        //
        // These require direct host→guest reachability (10.0.0.2), which is
        // only available with the TAP backend. Consomme NAT blocks inbound
        // host→guest connections, making UDP RX unreliable (see comment in
        // original code) and ping impossible.
        if let Some(guest_ip) = &state.guest_ip {
            // UDP RX (host sends to guest)
            let name = format!("net_{label}_udp_rx_pps");
            recorder.start(&name)?;
            timer.sleep(perf_delay).await;
            let m = run_iperf3_test(
                &state.agent,
                &state.host_ip,
                Some(guest_ip.as_str()),
                5204,
                &name,
                IperfMode::UdpRx,
                &mut timer,
            )
            .await
            .context("UDP RX test failed")?;
            recorder.stop()?;
            metrics.push(m);

            // Ping RTT (host → guest latency)
            let name = format!("net_{label}_ping_rtt_ms");
            recorder.start(&name)?;
            let m = run_ping_latency(guest_ip, &name)
                .context("ping latency test failed")?;
            recorder.stop()?;
            metrics.push(m);
        }

        Ok(metrics)
    }

    async fn teardown(&self, state: NetworkTestState) -> anyhow::Result<()> {
        state.agent.power_off().await?;
        state.vm.wait_for_clean_teardown().await?;

        // Remove the TAP device if we created one.
        #[cfg(target_os = "linux")]
        if let Some(ref tap) = state.tap_name {
            if let Err(e) = teardown_tap_device(tap) {
                tracing::warn!(tap = %tap, err = %e, "failed to remove TAP device");
            } else {
                tracing::info!(tap = %tap, "TAP device removed");
            }
        }

        Ok(())
    }
}

/// Which iperf3 test variant to run.
enum IperfMode {
    /// TCP, guest sends to host.
    TcpTx,
    /// TCP, host sends to guest (-R).
    TcpRx,
    /// UDP, guest sends to host.
    UdpTx,
    /// UDP, host sends to guest (host is client, guest runs server).
    /// Requires direct host→guest reachability (TAP backend only).
    UdpRx,
}

/// Spawn a host iperf3 server, run the guest client, collect JSON results.
///
/// For `UdpRx`: the guest runs the server and the host runs the client.
/// `guest_ip` must be `Some` for `UdpRx`.
async fn run_iperf3_test(
    agent: &petri::pipette::PipetteClient,
    host_ip: &str,
    guest_ip: Option<&str>,
    port: u16,
    metric_name: &str,
    mode: IperfMode,
    timer: &mut pal_async::timer::PolledTimer,
) -> anyhow::Result<MetricResult> {
    let port_str = port.to_string();

    match mode {
        IperfMode::UdpRx => {
            // Guest runs iperf3 server; host runs the client.
            let guest_ip = guest_ip.context("guest_ip required for UdpRx")?;

            // Start guest server in background (fire-and-forget).
            let mut sh = agent.unix_shell();
            sh.chroot("/perf");
            cmd!(sh, "iperf3 -s -1 -p {port_str}")
                .ignore_status()
                .run()
                .await
                .with_context(|| format!("failed to start guest iperf3 server for {metric_name}"))?;

            // Give the guest server time to bind.
            timer.sleep(std::time::Duration::from_millis(500)).await;

            // Host sends UDP to guest.
            let output = std::process::Command::new("iperf3")
                .args(["-c", guest_ip, "-p", &port_str, "-t", "10", "-u", "-b", "0", "-J"])
                .output()
                .context("failed to run host iperf3 client for UdpRx")?;

            if !output.status.success() {
                tracing::warn!(
                    status = %output.status,
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "host iperf3 client exited non-zero for UdpRx (may still have valid JSON)"
                );
            }

            let json = String::from_utf8(output.stdout)
                .context("iperf3 client output is not valid UTF-8")?;

            tracing::debug!(metric = metric_name, json = %json, "raw iperf3 (UdpRx) output");
            parse_udp_pps(&json, metric_name)
        }

        _ => {
            // Guest is the iperf3 client; host runs the server.
            let server = spawn_iperf3_server(port)?;

            // Brief delay to let the server bind.
            timer.sleep(std::time::Duration::from_millis(500)).await;

            // Run guest iperf3 client. Use ignore_status() because iperf3 may
            // exit non-zero even when data was exchanged (e.g., control socket
            // issues in reverse mode). We parse results from the host server JSON.
            let mut sh = agent.unix_shell();
            sh.chroot("/perf");
            match mode {
                IperfMode::TcpTx => {
                    cmd!(sh, "iperf3 -c {host_ip} -p {port_str} -t 10 -J")
                        .ignore_status()
                        .run()
                        .await
                }
                IperfMode::TcpRx => {
                    cmd!(sh, "iperf3 -c {host_ip} -p {port_str} -t 10 -R -J")
                        .ignore_status()
                        .run()
                        .await
                }
                IperfMode::UdpTx => {
                    cmd!(sh, "iperf3 -c {host_ip} -p {port_str} -t 10 -u -b 0 -J")
                        .ignore_status()
                        .run()
                        .await
                }
                IperfMode::UdpRx => unreachable!(),
            }
            .with_context(|| format!("guest iperf3 client failed for {metric_name}"))?;

            // Collect host server output (it exits after one client session).
            let output = server
                .wait_with_output()
                .context("failed to wait for iperf3 server")?;

            let json = String::from_utf8(output.stdout)
                .context("iperf3 server output is not valid UTF-8")?;

            // iperf3 server may exit non-zero on cleanup even when data was collected.
            // Log a warning but try to parse the JSON anyway.
            if !output.status.success() {
                tracing::warn!(
                    status = %output.status,
                    stderr = %String::from_utf8_lossy(&output.stderr),
                    "iperf3 server exited non-zero (may still have valid JSON)"
                );
            }

            anyhow::ensure!(
                !json.is_empty(),
                "iperf3 server produced no output for {metric_name}"
            );

            tracing::debug!(metric = metric_name, json = %json, "raw iperf3 output");

            // Parse metrics from the *host server* JSON. We use host-side rather
            // than guest-side output because (a) the guest client output goes
            // through pipette and isn't easily captured, and (b) in -R (reverse)
            // mode the client sometimes exits before flushing complete JSON.
            //
            // Field mapping (host perspective):
            //   TcpTx (guest sends): host received -> sum_received
            //   TcpRx (host sends):  host sent     -> sum_sent
            match mode {
                IperfMode::TcpTx => parse_tcp_throughput(&json, metric_name, false),
                IperfMode::TcpRx => parse_tcp_throughput(&json, metric_name, true),
                IperfMode::UdpTx => parse_udp_pps(&json, metric_name),
                IperfMode::UdpRx => unreachable!(),
            }
        }
    }
}

fn spawn_iperf3_server(port: u16) -> anyhow::Result<std::process::Child> {
    std::process::Command::new("iperf3")
        .args(["-s", "-1", "-J", "-p", &port.to_string()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn iperf3 server")
}

/// Measure host-to-guest ping round-trip latency.
///
/// Sends 1000 ICMP echo requests at 10 ms intervals (10 s total) and parses
/// the `rtt min/avg/max/mdev` summary line. Returns the average RTT in ms.
fn run_ping_latency(guest_ip: &str, metric_name: &str) -> anyhow::Result<MetricResult> {
    let output = std::process::Command::new("ping")
        .args(["-c", "1000", "-i", "0.01", guest_ip])
        .output()
        .context("failed to run ping")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!(metric = metric_name, output = %stdout, "raw ping output");

    // Parse: "rtt min/avg/max/mdev = X/Y/Z/W ms"
    let avg_ms = stdout
        .lines()
        .find(|l| l.contains("rtt min/avg/max/mdev"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|stats| stats.trim().split('/').nth(1))
        .and_then(|avg| avg.parse::<f64>().ok())
        .with_context(|| {
            format!(
                "failed to parse ping RTT from output for {metric_name}:\n{stdout}"
            )
        })?;

    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "ms".to_string(),
        value: avg_ms,
    })
}

/// Detect the host's primary IP address by finding the default route source.
///
/// Works cross-platform (Linux, macOS, Windows) by using a UDP socket connect
/// to query the kernel routing table without sending any traffic.
fn detect_host_ip() -> anyhow::Result<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .context("failed to bind UDP socket for host IP detection")?;
    socket
        .connect("1.1.1.1:80")
        .context("failed to connect UDP socket (no default route?)")?;
    let addr = socket
        .local_addr()
        .context("failed to get local address of UDP socket")?;
    Ok(addr.ip().to_string())
}

/// Parse TCP throughput from iperf3 JSON output.
///
/// For TX (guest sends): use `end.sum_received` (what the host received).
/// For RX (`-R`, host sends): use `end.sum_sent` (what the host sent).
fn parse_tcp_throughput(json: &str, metric_name: &str, sent: bool) -> anyhow::Result<MetricResult> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse iperf3 JSON")?;

    let field = if sent { "sum_sent" } else { "sum_received" };
    let bps = v["end"][field]["bits_per_second"].as_f64();

    // Fall back to the other field if the primary is missing or zero.
    let alt_field = if sent { "sum_received" } else { "sum_sent" };
    let bps = match bps {
        Some(v) if v > 0.0 => v,
        _ => v["end"][alt_field]["bits_per_second"]
            .as_f64()
            .with_context(|| {
                tracing::error!(json = %json, "failed to find bits_per_second in iperf3 TCP output");
                format!("missing bits_per_second in iperf3 output for {metric_name}")
            })?,
    };

    let gbps = bps / 1_000_000_000.0;
    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "Gbps".to_string(),
        value: gbps,
    })
}

/// Parse UDP packets-per-second from iperf3 JSON output.
fn parse_udp_pps(json: &str, metric_name: &str) -> anyhow::Result<MetricResult> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse iperf3 JSON")?;

    let packets = v["end"]["sum"]["packets"].as_f64();
    let seconds = v["end"]["sum"]["seconds"].as_f64();

    let pps = match (packets, seconds) {
        (Some(p), Some(s)) if s > 0.0 => p / s,
        _ => {
            // Fall back: try bits_per_second with default packet size (1460 bytes).
            let bps = v["end"]["sum"]["bits_per_second"].as_f64().with_context(|| {
                tracing::error!(json = %json, "failed to find packets/seconds in iperf3 UDP output");
                format!("missing packets or seconds in iperf3 output for {metric_name}")
            })?;
            // Approximate: default UDP datagram is 1460 bytes.
            bps / (1460.0 * 8.0)
        }
    };

    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "pps".to_string(),
        value: pps,
    })
}

/// Create, assign an IP, and bring up a TAP network interface.
///
/// Host side: 10.0.0.1/24. Guest side will use 10.0.0.2/24.
/// Requires `CAP_NET_ADMIN` (or root).
#[cfg(target_os = "linux")]
fn setup_tap_device(name: &str) -> anyhow::Result<()> {
    let run = |args: &[&str]| -> anyhow::Result<()> {
        let status = std::process::Command::new("ip")
            .args(args)
            .status()
            .with_context(|| format!("failed to run: ip {}", args.join(" ")))?;
        anyhow::ensure!(
            status.success(),
            "ip {} failed with {}",
            args.join(" "),
            status
        );
        Ok(())
    };

    run(&["tuntap", "add", "dev", name, "mode", "tap"])
        .with_context(|| format!("failed to create TAP device '{name}' (need CAP_NET_ADMIN?)"))?;
    run(&["addr", "add", "10.0.0.1/24", "dev", name])
        .with_context(|| format!("failed to assign IP to TAP device '{name}'"))?;
    run(&["link", "set", name, "up"])
        .with_context(|| format!("failed to bring up TAP device '{name}'"))?;
    Ok(())
}

/// Remove a TAP network interface created by [`setup_tap_device`].
#[cfg(target_os = "linux")]
fn teardown_tap_device(name: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("ip")
        .args(["tuntap", "del", "dev", name, "mode", "tap"])
        .status()
        .with_context(|| format!("failed to run ip tuntap del for '{name}'"))?;
    anyhow::ensure!(
        status.success(),
        "ip tuntap del dev {name} mode tap failed with {status}"
    );
    Ok(())
}
