// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Address helpers for the virtual link between a guest and a user-mode
//! stack.

use smoltcp::wire::EthernetAddress;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Cidr;
use smoltcp::wire::Ipv6Address;
use thiserror::Error;

/// Returns `true` if two IPv4 addresses are in the same subnet given a mask.
pub fn is_same_ipv4_subnet(a: Ipv4Address, b: Ipv4Address, mask: Ipv4Address) -> bool {
    let mask = mask.to_bits();
    a.to_bits() & mask == b.to_bits() & mask
}

/// Returns `true` if two IPv6 addresses share their first `prefix_len` bits.
pub fn is_same_ipv6_subnet(a: Ipv6Address, b: Ipv6Address, prefix_len: u8) -> bool {
    let mask = u128::MAX
        .checked_shl(128 - u32::from(prefix_len.min(128)))
        .unwrap_or(0);
    a.to_bits() & mask == b.to_bits() & mask
}

/// Returns `true` if an IPv4 destination is host-local: loopback, unspecified,
/// or link-local.
pub fn is_host_local_ipv4(addr: Ipv4Address) -> bool {
    addr.is_loopback() || addr.is_unspecified() || addr.is_link_local()
}

/// Returns `true` if an IPv6 destination is host-local: loopback, unspecified,
/// or link-local.
pub fn is_host_local_ipv6(addr: Ipv6Address) -> bool {
    addr.is_loopback() || addr.is_unspecified() || addr.is_unicast_link_local()
}

/// Computes the EUI-64 link-local IPv6 address for a MAC address (RFC 4291
/// section 2.5.6, RFC 2464 section 4): the `fe80::/64` prefix, followed by the
/// MAC with `ff:fe` inserted in the middle and the universal/local bit
/// inverted.
pub fn link_local_from_mac(mac: EthernetAddress) -> Ipv6Address {
    let m = mac.0;
    Ipv6Address::from_octets([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        m[0] ^ 0x02,
        m[1],
        m[2],
        0xff,
        0xfe,
        m[3],
        m[4],
        m[5],
    ])
}

/// An error indicating that a CIDR is invalid or too small for a gateway and
/// a guest.
#[derive(Debug, Error)]
#[error("invalid CIDR")]
pub struct InvalidCidr;

/// A private IPv4 network holding the gateway and the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Network {
    /// The gateway: the first address after the network address.
    pub gateway: Ipv4Address,
    /// The guest: the second address after the network address.
    pub client: Ipv4Address,
    /// The network mask.
    pub net_mask: Ipv4Address,
}

impl Ipv4Network {
    /// Parses a CIDR such as `192.168.0.0/24`, which places the gateway at
    /// 192.168.0.1 and the guest at 192.168.0.2. The network needs room for
    /// both, so the prefix may be at most 30 bits.
    pub fn parse(cidr: &str) -> Result<Self, InvalidCidr> {
        let cidr: Ipv4Cidr = cidr.parse().map_err(|()| InvalidCidr)?;
        if cidr.prefix_len() > 30 {
            return Err(InvalidCidr);
        }
        let base = cidr.network().address().to_bits();
        Ok(Self {
            gateway: Ipv4Address::from_bits(base + 1),
            client: Ipv4Address::from_bits(base + 2),
            net_mask: cidr.netmask(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn subnet_helpers() {
        let mask = Ipv4Address::new(255, 255, 255, 0);
        assert!(is_same_ipv4_subnet(
            Ipv4Address::new(10, 0, 0, 1),
            Ipv4Address::new(10, 0, 0, 200),
            mask
        ));
        assert!(!is_same_ipv4_subnet(
            Ipv4Address::new(10, 0, 0, 1),
            Ipv4Address::new(10, 0, 1, 1),
            mask
        ));
        let a = Ipv6Address::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let b = Ipv6Address::new(0xfe80, 0, 0, 0, 0x8000, 9, 9, 9);
        assert!(is_same_ipv6_subnet(a, b, 64));
        assert!(!is_same_ipv6_subnet(a, b, 65));
        assert!(is_same_ipv6_subnet(a, Ipv6Address::LOCALHOST, 0));
        assert!(is_same_ipv6_subnet(a, a, 128));
        assert!(!is_same_ipv6_subnet(a, b, 128));
        // Longer prefixes require an exact match rather than panicking.
        assert!(is_same_ipv6_subnet(a, a, 200));
        assert!(!is_same_ipv6_subnet(a, b, 255));
    }

    #[test]
    fn link_local_is_eui64() {
        assert_eq!(
            link_local_from_mac(EthernetAddress([0x52, 0x55, 0x0a, 0x00, 0x01, 0x02])),
            Ipv6Address::new(0xfe80, 0, 0, 0, 0x5055, 0x0aff, 0xfe00, 0x0102)
        );
    }

    #[test]
    fn network_needs_room_for_gateway_and_guest() {
        let net = Ipv4Network::parse("192.168.0.0/24").unwrap();
        assert_eq!(net.gateway, Ipv4Address::new(192, 168, 0, 1));
        assert_eq!(net.client, Ipv4Address::new(192, 168, 0, 2));
        assert_eq!(net.net_mask, Ipv4Address::new(255, 255, 255, 0));
        // The host bits of the address are ignored.
        assert_eq!(Ipv4Network::parse("192.168.0.77/24").unwrap(), net);
        let net = Ipv4Network::parse("10.0.0.252/30").unwrap();
        assert_eq!(net.client, Ipv4Address::new(10, 0, 0, 254));
        // Too small, or would have wrapped past the last octet.
        assert!(Ipv4Network::parse("10.0.0.254/31").is_err());
        assert!(Ipv4Network::parse("10.0.0.255/32").is_err());
        assert!(Ipv4Network::parse("not a cidr").is_err());
    }
}
