// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared fio helpers for I/O performance tests.
//!
//! Provides common routines for running fio jobs and parsing results,
//! used by both the block I/O (`disk_io`) and filesystem I/O (`fs_io`)
//! test modules.

use crate::report::MetricResult;
use anyhow::Context as _;
use petri::pipette::cmd;
use petri_artifacts_common::tags::MachineArch;

/// Target for a fio job: either a raw block device or a filesystem directory.
pub enum FioTarget<'a> {
    /// Raw block device (e.g. `/dev/vdb`). Uses `io_uring` engine with
    /// `direct=1` for unbuffered I/O.
    BlockDevice { device: &'a str },
    /// Directory on a mounted filesystem (e.g. `/mnt/virtiofs`). Uses `psync`
    /// engine with buffered I/O since FUSE may not support `O_DIRECT` or
    /// `io_uring`.
    Directory { path: &'a str, file_size: &'a str },
}

/// Build firmware for a Linux direct-boot VM on the host architecture.
pub fn build_firmware(resolver: &petri::ArtifactResolver<'_>) -> petri::Firmware {
    petri::Firmware::linux_direct(resolver, MachineArch::host())
}

/// Resolve the petritools erofs artifact (contains fio, iperf3, etc.).
pub fn require_petritools_erofs(
    resolver: &petri::ArtifactResolver<'_>,
) -> petri_artifacts_core::ResolvedArtifact {
    use petri_artifacts_vmm_test::artifacts::petritools::*;
    match MachineArch::host() {
        MachineArch::X86_64 => resolver.require(PETRITOOLS_EROFS_X64).erase(),
        MachineArch::Aarch64 => resolver.require(PETRITOOLS_EROFS_AARCH64).erase(),
    }
}

/// Mount the erofs image and prepare a chroot with fio pre-installed.
pub async fn mount_erofs_chroot(agent: &petri::pipette::PipetteClient) -> anyhow::Result<()> {
    agent
        .mount("/dev/vda", "/perf", "erofs", 1 /* MS_RDONLY */, true)
        .await
        .context("failed to mount erofs on /dev/vda")?;
    agent
        .prepare_chroot("/perf")
        .await
        .context("failed to prepare chroot at /perf")?;
    Ok(())
}

/// Run a single fio job and return the raw JSON output.
pub async fn run_fio_job(
    agent: &petri::pipette::PipetteClient,
    target: &FioTarget<'_>,
    rw_mode: &str,
    iodepth: u32,
) -> anyhow::Result<String> {
    let mut sh = agent.unix_shell();
    sh.chroot("/perf");
    let iodepth_str = iodepth.to_string();

    let output: String = match target {
        FioTarget::BlockDevice { device } => {
            cmd!(sh, "fio --name=test --filename={device} --rw={rw_mode} --bs=4k --ioengine=io_uring --direct=1 --runtime=10 --ramp_time=5 --iodepth={iodepth_str} --numjobs=1 --percentile_list=50:99:99.9 --output-format=json")
                .read()
                .await
                .with_context(|| format!("fio {rw_mode} on {device} failed"))?
        }
        FioTarget::Directory { path, file_size } => {
            // psync is synchronous — iodepth is always capped at 1.
            cmd!(sh, "fio --name=test --directory={path} --rw={rw_mode} --bs=4k --ioengine=psync --size={file_size} --runtime=10 --ramp_time=5 --iodepth=1 --numjobs=1 --percentile_list=50:99:99.9 --fallocate=none --output-format=json")
                .read()
                .await
                .with_context(|| format!("fio {rw_mode} on {path} failed"))?
        }
    };

    // Strip any non-JSON prefix (e.g. fio "note:" lines) before the opening brace.
    let json_start = output
        .find('{')
        .context("fio output contains no JSON object")?;
    Ok(output[json_start..].to_string())
}

/// Standard set of fio jobs: sequential and random read/write, plus an
/// iodepth=1 random-read latency probe. Returns all collected metrics.
///
/// `label` is the backend name used in metric prefixes (e.g. `"virtio-blk"`).
pub async fn run_standard_fio_suite(
    agent: &petri::pipette::PipetteClient,
    target: &FioTarget<'_>,
    label: &str,
    recorder: &mut crate::harness::PerfRecorder,
) -> anyhow::Result<Vec<MetricResult>> {
    let mut metrics = Vec::new();

    // Each fio job: 10s runtime + 5s ramp = 15s.
    // For sequential modes we only extract BW; for random modes we extract
    // both BW and IOPS from a single fio run to avoid redundant work.
    let fio_jobs: &[(&str, &str)] = &[
        // (fio_rw_mode, primary_field)
        ("read", "read"),
        ("write", "write"),
        ("randread", "read"),
        ("randwrite", "write"),
    ];

    for &(rw_mode, field) in fio_jobs {
        let is_random = rw_mode.starts_with("rand");
        let phase = if is_random {
            rw_mode.strip_prefix("rand").unwrap()
        } else {
            rw_mode
        };
        let prefix = if is_random { "rand" } else { "seq" };

        let perf_label = format!("fio_{label}_{prefix}_{phase}");
        recorder.start(&perf_label)?;

        let json = run_fio_job(agent, target, rw_mode, 32)
            .await
            .with_context(|| format!("fio {rw_mode} failed"))?;

        recorder.stop()?;

        let metric_prefix = format!("fio_{label}_{prefix}_{phase}");
        metrics.push(parse_fio_bw(&json, &format!("{metric_prefix}_bw"), field)?);
        metrics.extend(parse_fio_clat(&json, &metric_prefix, field)?);

        if is_random {
            metrics.push(parse_fio_iops(
                &json,
                &format!("{metric_prefix}_iops"),
                field,
            )?);
        }
    }

    // iodepth=1 random-read job — every IO goes through the notification
    // path, so the clat directly reflects notification overhead.
    {
        let perf_label = format!("fio_{label}_lat_randread");
        recorder.start(&perf_label)?;

        let json = run_fio_job(agent, target, "randread", 1)
            .await
            .context("fio iodepth=1 randread failed")?;

        recorder.stop()?;

        let prefix = format!("fio_{label}_qd1_rand_read");
        metrics.push(parse_fio_iops(&json, &format!("{prefix}_iops"), "read")?);
        metrics.extend(parse_fio_clat(&json, &prefix, "read")?);
    }

    Ok(metrics)
}

/// Parse bandwidth (MiB/s) from fio JSON output.
pub fn parse_fio_bw(json: &str, metric_name: &str, field: &str) -> anyhow::Result<MetricResult> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse fio JSON")?;

    let bw_bytes = v["jobs"][0][field]["bw_bytes"].as_f64().with_context(|| {
        tracing::error!(json = %json, "failed to find {field}.bw_bytes in fio output");
        format!("missing {field}.bw_bytes in fio output for {metric_name}")
    })?;

    let mib_s = bw_bytes / (1024.0 * 1024.0);
    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "MiB/s".to_string(),
        value: mib_s,
    })
}

/// Parse IOPS from fio JSON output.
pub fn parse_fio_iops(json: &str, metric_name: &str, field: &str) -> anyhow::Result<MetricResult> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse fio JSON")?;

    let iops = v["jobs"][0][field]["iops"].as_f64().with_context(|| {
        tracing::error!(json = %json, "failed to find {field}.iops in fio output");
        format!("missing {field}.iops in fio output for {metric_name}")
    })?;

    Ok(MetricResult {
        name: metric_name.to_string(),
        unit: "IOPS".to_string(),
        value: iops,
    })
}

/// Parse completion latency (clat) mean and p99 from fio JSON output.
///
/// fio reports `clat_ns` in nanoseconds; we convert to microseconds.
pub fn parse_fio_clat(
    json: &str,
    metric_prefix: &str,
    field: &str,
) -> anyhow::Result<Vec<MetricResult>> {
    let v: serde_json::Value = serde_json::from_str(json).context("failed to parse fio JSON")?;
    let clat = &v["jobs"][0][field]["clat_ns"];

    let mut out = Vec::new();

    if let Some(mean_ns) = clat["mean"].as_f64() {
        out.push(MetricResult {
            name: format!("{metric_prefix}_clat_mean"),
            unit: "us".to_string(),
            value: mean_ns / 1000.0,
        });
    }

    // fio uses string keys like "99.000000" for percentiles.
    if let Some(p99_ns) = clat["percentile"]["99.000000"].as_f64() {
        out.push(MetricResult {
            name: format!("{metric_prefix}_clat_p99"),
            unit: "us".to_string(),
            value: p99_ns / 1000.0,
        });
    }

    Ok(out)
}
