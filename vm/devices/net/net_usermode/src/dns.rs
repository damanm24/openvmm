// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Discovery of the host's DNS nameservers.

#[cfg_attr(unix, path = "dns_unix.rs")]
#[cfg_attr(windows, path = "dns_windows.rs")]
mod sys;

pub use sys::Error;

use smoltcp::wire::IpAddress;

/// How to treat an IPv6 nameserver with a zone, such as `fe80::1%eth0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedIpv6 {
    /// Skip the nameserver, logging a warning.
    Skip,
    /// Keep the address without its zone. The caller must apply a scope
    /// before using a link-local address.
    Strip,
}

/// Returns the host's nameservers, in configuration order.
///
/// On Unix, these come from `/etc/resolv.conf`. On Windows, they are the DNS
/// servers of all adapters, and zones are always stripped.
pub fn nameservers(scoped_ipv6: ScopedIpv6) -> Result<Vec<IpAddress>, Error> {
    sys::nameservers(scoped_ipv6)
}
