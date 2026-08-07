// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host process memory accounting used by VMM tests.

/// Returns the host memory charged to private allocations in `pid`.
///
/// On Windows this is the process private commit charge (`PrivateUsage`). On
/// Linux this is resident anonymous memory (`RssAnon`). These are the native
/// host counters that expose whether private guest RAM is committed eagerly or
/// populated on demand.
#[cfg(target_os = "linux")]
pub fn process_private_memory_bytes(pid: i32) -> anyhow::Result<u64> {
    use anyhow::Context as _;

    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("failed to read /proc/{pid}/status"))?;
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))
        .context("RssAnon not found in process status")?;
    let kib = line
        .trim()
        .strip_suffix("kB")
        .context("unexpected RssAnon format")?
        .trim()
        .parse::<u64>()
        .context("failed to parse RssAnon")?;
    Ok(kib * 1024)
}

/// Returns the host memory charged to private allocations in `pid`.
///
/// On Windows this is the process private commit charge (`PrivateUsage`). On
/// Linux this is resident anonymous memory (`RssAnon`). These are the native
/// host counters that expose whether private guest RAM is committed eagerly or
/// populated on demand.
#[cfg(windows)]
pub fn process_private_memory_bytes(pid: i32) -> anyhow::Result<u64> {
    // UNSAFETY: Querying memory counters for an owned process handle.
    use anyhow::Context as _;
    use std::mem::size_of;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
    use windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS_EX;
    use windows::Win32::System::Threading::OpenProcess;
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

    // SAFETY: OpenProcess is called with query-only access for a live PID.
    #[expect(unsafe_code, reason = "calling Win32 OpenProcess")]
    let raw_handle = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid as u32)
            .context("failed to open process")?
    };
    // SAFETY: OpenProcess returned an owned handle.
    #[expect(unsafe_code, reason = "taking ownership of a Win32 handle")]
    let _handle = unsafe { OwnedHandle::from_raw_handle(raw_handle.0.cast()) };

    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: The process handle is valid and `counters` has the size passed to
    // the API.
    #[expect(unsafe_code, reason = "calling Win32 GetProcessMemoryInfo")]
    unsafe {
        GetProcessMemoryInfo(
            raw_handle,
            std::ptr::from_mut(&mut counters).cast(),
            size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
        .context("failed to query process memory")?;
    }

    Ok(counters.PrivateUsage as u64)
}

/// Returns the host memory charged to private allocations in `pid`.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn process_private_memory_bytes(_pid: i32) -> anyhow::Result<u64> {
    anyhow::bail!("private process memory accounting is unsupported on this host")
}
