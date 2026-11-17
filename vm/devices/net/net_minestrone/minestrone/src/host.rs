// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Discovery of the host network configuration that the guest mirrors.
//!
//! As in passt, for each IP version the template is the host interface with
//! the first default route: the guest is given that interface's most specific
//! address and the route's gateway. Discovery is only implemented on Linux.

// The parsers are only used on Linux.
#![cfg_attr(not(target_os = "linux"), expect(dead_code))]

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// The host's IPv4 configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostIpv4 {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
}

/// The host's IPv6 configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostIpv6 {
    pub addr: Ipv6Addr,
    pub gateway: Ipv6Addr,
    pub interface_index: u32,
    /// The link-local address the gateway uses on the guest's link: the
    /// host's default gateway if that is link-local, otherwise the host's own
    /// link-local address.
    pub gateway_link_local: Ipv6Addr,
}

/// `RTF_UP | RTF_GATEWAY`.
const RTF_UP: u32 = 0x1;
const RTF_REJECT: u32 = 0x200;
/// `/proc/net/if_inet6` scope of link-local addresses.
const SCOPE_LINK: u32 = 0x20;
/// `/proc/net/if_inet6` scope of loopback addresses.
const SCOPE_HOST: u32 = 0x10;
const IFA_F_DEPRECATED: u32 = 0x20;

fn read_network_file(path: &str) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                path,
                error = &err as &dyn std::error::Error,
                "host network information unavailable"
            );
            None
        }
        Err(err) => {
            tracing::warn!(
                path,
                error = &err as &dyn std::error::Error,
                "failed to read host network configuration"
            );
            None
        }
    }
}

/// Returns the host's IPv4 configuration from a usable routed interface.
pub(crate) fn ipv4() -> Option<HostIpv4> {
    #[cfg(target_os = "linux")]
    {
        let routes = read_network_file("/proc/net/route")?;
        let (ifname, gateway) = default_route_v4(&routes)?;
        let interfaces = match nix::ifaddrs::getifaddrs() {
            Ok(interfaces) => interfaces,
            Err(err) => {
                tracing::warn!(
                    error = &err as &dyn std::error::Error,
                    "failed to discover host interface addresses"
                );
                return None;
            }
        };
        let addrs = interfaces.filter_map(|ifa| {
            if ifa.interface_name != ifname {
                return None;
            }
            let addr = ifa.address?.as_sockaddr_in()?.ip();
            let mask = ifa.netmask?.as_sockaddr_in()?.ip();
            Some((addr, mask.to_bits().count_ones() as u8))
        });
        let (addr, prefix_len) = most_specific(addrs.filter(|(a, _)| !a.is_unspecified()))?;
        Some(HostIpv4 {
            addr,
            prefix_len,
            gateway,
        })
    }
    #[cfg(not(target_os = "linux"))]
    None
}

/// Returns the host's IPv6 configuration from a usable routed interface.
pub(crate) fn ipv6() -> Option<HostIpv6> {
    #[cfg(target_os = "linux")]
    {
        let routes = read_network_file("/proc/net/ipv6_route")?;
        let addrs = read_network_file("/proc/net/if_inet6")?;
        let (ifname, gateway) = default_route_v6(&routes)?;
        let mut config = host_ipv6(&addrs, &ifname, gateway)?;
        config.interface_index = match nix::net::if_::if_nametoindex(ifname.as_str()) {
            Ok(index) => index,
            Err(err) => {
                tracing::warn!(%ifname, error = &err as &dyn std::error::Error, "failed to discover IPv6 interface index");
                return None;
            }
        };
        Some(config)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

/// Returns the first of the addresses with the longest prefix.
fn most_specific<A>(addrs: impl Iterator<Item = (A, u8)>) -> Option<(A, u8)> {
    addrs.fold(None, |best, (addr, len)| match best {
        Some((_, best_len)) if best_len >= len => best,
        _ => Some((addr, len)),
    })
}

/// Prefers the first default route, otherwise the first non-link-local route.
/// An interface without a default gateway returns an unspecified gateway.
fn default_route_v4(routes: &str) -> Option<(String, Ipv4Addr)> {
    let mut first_route = None;
    for (ifname, dst, gateway, mask) in routes.lines().skip(1).filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [ifname, dst, gateway, flags, _, _, _, mask, ..] = fields[..] else {
            return None;
        };
        let hex = |s| u32::from_str_radix(s, 16).ok();
        let (dst, gateway, flags, mask) = (hex(dst)?, hex(gateway)?, hex(flags)?, hex(mask)?);
        // Addresses are in network byte order, printed as native integers.
        let gateway = Ipv4Addr::from(gateway.to_ne_bytes());
        (flags & RTF_UP != 0 && flags & RTF_REJECT == 0 && ifname != "lo").then_some((
            ifname.to_owned(),
            dst,
            gateway,
            mask,
        ))
    }) {
        if dst == 0 && mask == 0 {
            return Some((ifname, gateway));
        }
        let destination = Ipv4Addr::from(dst.to_ne_bytes());
        if !destination.is_link_local() {
            first_route.get_or_insert((ifname, Ipv4Addr::UNSPECIFIED));
        }
    }
    first_route
}

fn parse_ipv6(hex: &str) -> Option<Ipv6Addr> {
    u128::from_str_radix(hex, 16)
        .ok()
        .filter(|_| hex.len() == 32)
        .map(Ipv6Addr::from)
}

/// IPv6 counterpart of `default_route_v4`.
fn default_route_v6(routes: &str) -> Option<(String, Ipv6Addr)> {
    let mut first_route = None;
    for (ifname, dst, dst_len, gateway) in routes.lines().filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [dst, dst_len, _, _, gateway, _, _, _, flags, ifname] = fields[..] else {
            return None;
        };
        let flags = u32::from_str_radix(flags, 16).ok()?;
        let gateway = parse_ipv6(gateway)?;
        (flags & RTF_UP != 0 && flags & RTF_REJECT == 0 && ifname != "lo").then_some((
            ifname.to_owned(),
            parse_ipv6(dst)?,
            dst_len == "00",
            gateway,
        ))
    }) {
        if dst.is_unspecified() && dst_len {
            return Some((ifname, gateway));
        }
        if !dst.is_unicast_link_local() {
            first_route.get_or_insert((ifname, Ipv6Addr::UNSPECIFIED));
        }
    }
    first_route
}

/// Selects the IPv6 configuration for `ifname` from `/proc/net/if_inet6`.
fn host_ipv6(addrs: &str, ifname: &str, gateway: Ipv6Addr) -> Option<HostIpv6> {
    let entries = addrs.lines().filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [addr, _, prefix_len, scope, flags, name] = fields[..] else {
            return None;
        };
        let hex = |s| u32::from_str_radix(s, 16).ok();
        let (prefix_len, scope, flags) = (hex(prefix_len)?, hex(scope)?, hex(flags)?);
        (name == ifname && flags & IFA_F_DEPRECATED == 0).then_some((
            parse_ipv6(addr)?,
            u8::try_from(prefix_len).ok()?,
            scope,
        ))
    });
    let entries: Vec<_> = entries.collect();
    let (addr, _) = most_specific(
        entries
            .iter()
            .filter(|&&(_, _, scope)| scope != SCOPE_LINK && scope != SCOPE_HOST)
            .map(|&(addr, len, _)| (addr, len)),
    )?;
    let gateway_link_local = if gateway.is_unicast_link_local() {
        gateway
    } else {
        most_specific(
            entries
                .iter()
                .filter(|&&(_, _, scope)| scope == SCOPE_LINK)
                .map(|&(addr, len, _)| (addr, len)),
        )?
        .0
    };
    Some(HostIpv6 {
        addr,
        gateway,
        interface_index: 0,
        gateway_link_local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    fn route_v4_line(
        ifname: &str,
        dst: [u8; 4],
        gateway: [u8; 4],
        flags: u32,
        mask: [u8; 4],
    ) -> String {
        let hex = |a: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(a));
        format!(
            "{ifname}\t{}\t{}\t{flags:04X}\t0\t0\t100\t{}\t0\t0\t0",
            hex(dst),
            hex(gateway),
            hex(mask)
        )
    }

    #[test]
    fn ipv4_default_route_prefers_first_up_route_even_without_gateway() {
        let header =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
        let routes = [
            header.to_owned(),
            // Subnet route, without a gateway.
            route_v4_line("eth0", [192, 168, 1, 0], [0; 4], 0x1, [255, 255, 255, 0]),
            // Default route without RTF_GATEWAY.
            route_v4_line("tun0", [0; 4], [0; 4], 0x1, [0; 4]),
            route_v4_line("eth0", [0; 4], [192, 168, 1, 1], 0x3, [0; 4]),
            route_v4_line("eth1", [0; 4], [10, 0, 0, 1], 0x3, [0; 4]),
        ]
        .join("\n");
        assert_eq!(
            default_route_v4(&routes),
            Some(("tun0".to_owned(), Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(default_route_v4(header), None);
        assert_eq!(
            default_route_v4(&format!("{header}\n{}", routes.lines().nth(1).unwrap())),
            Some(("eth0".to_owned(), Ipv4Addr::UNSPECIFIED))
        );
    }

    const IPV6_ROUTE: &str = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0
";

    #[test]
    fn ipv6_default_route_skips_reject_and_loopback() {
        assert_eq!(
            default_route_v6(IPV6_ROUTE),
            Some(("eth0".to_owned(), "fe80::1".parse().unwrap()))
        );
        let routes_without_default = IPV6_ROUTE.lines().take(2).collect::<Vec<_>>().join("\n");
        assert_eq!(
            default_route_v6(&routes_without_default),
            Some(("eth0".to_owned(), Ipv6Addr::UNSPECIFIED))
        );
    }

    const IF_INET6: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
20010db8000000000000000000000abc 02 40 00 00     eth0
20010db8000000000000000000000def 02 80 00 20     eth0
20010db8000000000000000000000123 02 80 00 00     eth0
fe8000000000000000000000000000aa 02 40 20 80     eth0
20010db8000000000000000000000999 03 80 00 00     eth1
";

    #[test]
    fn ipv6_prefers_most_specific_current_global_address() {
        let link_gateway: Ipv6Addr = "fe80::1".parse().unwrap();
        let cfg = host_ipv6(IF_INET6, "eth0", link_gateway).unwrap();
        // The deprecated /128 is skipped, and /128 beats /64.
        assert_eq!(cfg.addr, "2001:db8::123".parse::<Ipv6Addr>().unwrap());
        assert_eq!(cfg.gateway_link_local, link_gateway);

        // A global gateway is replaced by the host's link-local address.
        let cfg = host_ipv6(IF_INET6, "eth0", "2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!(
            cfg.gateway_link_local,
            "fe80::aa".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(host_ipv6(IF_INET6, "eth2", link_gateway), None);
    }
}
