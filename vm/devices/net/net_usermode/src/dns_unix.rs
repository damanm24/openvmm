// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::ScopedIpv6;
use resolv_conf::ScopedIp;
use smoltcp::wire::IpAddress;
use thiserror::Error;

/// An error reading the host's nameservers.
#[derive(Debug, Error)]
pub enum Error {
    /// `/etc/resolv.conf` could not be read.
    #[error("failing reading resolv.conf")]
    Io(#[from] std::io::Error),
    /// `/etc/resolv.conf` could not be parsed.
    #[error("failing parsing resolv.conf")]
    Parse(#[from] resolv_conf::ParseError),
}

pub(super) fn nameservers(scoped_ipv6: ScopedIpv6) -> Result<Vec<IpAddress>, Error> {
    let contents = std::fs::read("/etc/resolv.conf")?;
    let config = resolv_conf::Config::parse(contents)?;
    Ok(config
        .nameservers
        .iter()
        .filter_map(|ns| match ns {
            ScopedIp::V4(addr) => Some(IpAddress::Ipv4(*addr)),
            ScopedIp::V6(addr, None) => Some(IpAddress::Ipv6(*addr)),
            ScopedIp::V6(addr, Some(scope)) => match scoped_ipv6 {
                ScopedIpv6::Strip => Some(IpAddress::Ipv6(*addr)),
                ScopedIpv6::Skip => {
                    tracelimit::warn_ratelimited!(
                        %addr,
                        scope,
                        "ignoring scoped IPv6 nameserver"
                    );
                    None
                }
            },
        })
        .collect())
}
