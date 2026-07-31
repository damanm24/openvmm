// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ConsommeConfig;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP: u8 = 6;
const UDP: u8 = 17;

/// Creates an endpoint-local steering seed.
pub fn random_steering_seed() -> u64 {
    let mut bytes = [0; 8];
    if let Err(error) = getrandom::fill(&mut bytes) {
        tracelimit::warn_ratelimited!(
            error = &error as &dyn std::error::Error,
            "failed to generate Consomme steering seed"
        );
        return 0x6f70_656e_766d_6d21;
    }
    u64::from_ne_bytes(bytes)
}

/// The direction in which a guest-visible frame is being classified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDirection {
    /// A frame transmitted by the guest.
    GuestToRemote,
    /// A frame generated from host-side input for delivery to the guest.
    RemoteToGuest,
}

/// A normalized guest-visible transport flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKey {
    /// A TCP flow keyed by its guest and remote socket addresses.
    Tcp {
        /// The guest-visible socket address.
        guest: SocketAddr,
        /// The remote socket address.
        remote: SocketAddr,
    },
    /// A UDP flow. Initial shard ownership hashes only `guest` to preserve
    /// Consomme's endpoint-independent UDP mapping behavior.
    Udp {
        /// The guest-visible source socket used for shard ownership.
        guest: SocketAddr,
        /// The remote socket address retained for diagnostics.
        remote: SocketAddr,
    },
}

impl FlowKey {
    /// Computes a stable endpoint-seeded hash for shard selection.
    pub fn stable_hash(self, seed: u64) -> u64 {
        let mut hash = 0xcbf29ce484222325 ^ seed;
        let mut write = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x100000001b3);
            }
        };
        match self {
            FlowKey::Tcp { guest, remote } => {
                write(&[TCP]);
                write_socket(&mut write, guest);
                write_socket(&mut write, remote);
            }
            FlowKey::Udp { guest, .. } => {
                write(&[UDP]);
                write_socket(&mut write, guest);
            }
        }
        // FNV's low bits have poor avalanche behavior, which matters when a
        // power-of-two shard count selects a queue with modulo. Finalize the
        // stable hash so patterned ephemeral ports use all available shards.
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xff51afd7ed558ccd);
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xc4ceb9fe1a85ec53);
        hash ^ (hash >> 33)
    }
}

fn write_socket(mut write: impl FnMut(&[u8]), socket: SocketAddr) {
    match socket.ip() {
        IpAddr::V4(ip) => write(&ip.octets()),
        IpAddr::V6(ip) => write(&ip.octets()),
    }
    write(&socket.port().to_be_bytes());
}

/// The classification result for a frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketClass {
    /// A transport flow suitable for shard steering.
    Flow(FlowKey),
    /// Endpoint-wide control traffic, routed to shard zero.
    Control,
    /// A malformed frame that must be dropped before protocol processing.
    Drop,
}

/// Parses and classifies a frame without modifying protocol state.
pub fn classify_frame(
    frame: &[u8],
    direction: PacketDirection,
    config: &ConsommeConfig,
) -> PacketClass {
    let Some(ethertype) = frame.get(12..14) else {
        return PacketClass::Drop;
    };
    let payload = match frame.get(ETHERNET_HEADER_LEN..) {
        Some(payload) => payload,
        None => return PacketClass::Drop,
    };
    let parsed = match ethertype {
        [0x08, 0x00] => parse_ipv4(payload),
        [0x86, 0xdd] => parse_ipv6(payload),
        [0x08, 0x06] => return PacketClass::Control,
        _ => return PacketClass::Control,
    };
    let Some((protocol, src, dst, transport)) = parsed else {
        return PacketClass::Drop;
    };
    if protocol != TCP && protocol != UDP {
        return PacketClass::Control;
    }
    let Some(ports) = transport.get(..4) else {
        return PacketClass::Drop;
    };
    let src = SocketAddr::new(src, u16::from_be_bytes([ports[0], ports[1]]));
    let dst = SocketAddr::new(dst, u16::from_be_bytes([ports[2], ports[3]]));
    let (guest, remote) = match direction {
        PacketDirection::GuestToRemote => (src, dst),
        PacketDirection::RemoteToGuest => (dst, src),
    };
    if is_gateway_dns(remote, config) {
        return PacketClass::Control;
    }
    if protocol == UDP && is_local_subnet(remote.ip(), config) {
        return PacketClass::Control;
    }
    if protocol == UDP && matches!((guest.port(), remote.port()), (68, 67) | (546, 547)) {
        return PacketClass::Control;
    }
    if protocol == TCP {
        PacketClass::Flow(FlowKey::Tcp { guest, remote })
    } else {
        PacketClass::Flow(FlowKey::Udp { guest, remote })
    }
}

fn is_local_subnet(remote: IpAddr, config: &ConsommeConfig) -> bool {
    match remote {
        IpAddr::V4(remote) => {
            crate::is_same_ipv4_subnet(remote.into(), config.gateway_ip, config.net_mask)
        }
        IpAddr::V6(remote) => crate::is_same_ipv6_subnet(
            remote.into(),
            config.gateway_link_local_ipv6,
            config.prefix_len_ipv6,
        ),
    }
}

fn parse_ipv4(payload: &[u8]) -> Option<(u8, IpAddr, IpAddr, &[u8])> {
    let header = payload.get(..IPV4_MIN_HEADER_LEN)?;
    if header[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(header[0] & 0xf) * 4;
    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header_len < IPV4_MIN_HEADER_LEN || total_len < header_len || total_len > payload.len() {
        return None;
    }
    let fragments = u16::from_be_bytes([header[6], header[7]]);
    if fragments & 0x3fff != 0 {
        return None;
    }
    let src = IpAddr::V4(Ipv4Addr::new(
        header[12], header[13], header[14], header[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ));
    Some((header[9], src, dst, payload.get(header_len..total_len)?))
}

fn parse_ipv6(payload: &[u8]) -> Option<(u8, IpAddr, IpAddr, &[u8])> {
    let header = payload.get(..IPV6_HEADER_LEN)?;
    if header[0] >> 4 != 6 {
        return None;
    }
    let total_len = IPV6_HEADER_LEN + usize::from(u16::from_be_bytes([header[4], header[5]]));
    if total_len > payload.len() {
        return None;
    }
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[24..40]).ok()?));
    Some((
        header[6],
        src,
        dst,
        payload.get(IPV6_HEADER_LEN..total_len)?,
    ))
}

fn is_gateway_dns(remote: SocketAddr, config: &ConsommeConfig) -> bool {
    if remote.port() != 53 {
        return false;
    }
    match remote.ip() {
        IpAddr::V4(ip) => ip.octets() == config.gateway_ip.octets(),
        IpAddr::V6(ip) => ip.octets() == config.gateway_link_local_ipv6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(protocol: u8, src: [u8; 4], dst: [u8; 4], ports: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0; ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + ports.len()];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        let total_len = (IPV4_MIN_HEADER_LEN + ports.len()) as u16;
        frame[16..18].copy_from_slice(&total_len.to_be_bytes());
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&src);
        frame[30..34].copy_from_slice(&dst);
        frame[34..38].copy_from_slice(&ports);
        frame
    }

    #[test]
    fn tcp_directions_normalize_to_same_key() {
        let config = ConsommeConfig::new();
        let outbound = ipv4_frame(TCP, [10, 0, 0, 2], [1, 1, 1, 1], [0x12, 0x34, 0, 80]);
        let inbound = ipv4_frame(TCP, [1, 1, 1, 1], [10, 0, 0, 2], [0, 80, 0x12, 0x34]);
        assert_eq!(
            classify_frame(&outbound, PacketDirection::GuestToRemote, &config),
            classify_frame(&inbound, PacketDirection::RemoteToGuest, &config)
        );
    }

    #[test]
    fn translated_local_tcp_directions_normalize_to_same_key() {
        let config = ConsommeConfig::new();
        let guest_to_remote = ipv4_frame(
            TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 254],
            [0x1f, 0x90, 0xaf, 0xc8],
        );
        let remote_to_guest = ipv4_frame(
            TCP,
            [10, 0, 0, 254],
            [10, 0, 0, 2],
            [0xaf, 0xc8, 0x1f, 0x90],
        );
        let expected = PacketClass::Flow(FlowKey::Tcp {
            guest: "10.0.0.2:8080".parse().unwrap(),
            remote: "10.0.0.254:45000".parse().unwrap(),
        });

        assert_eq!(
            classify_frame(
                &guest_to_remote,
                PacketDirection::GuestToRemote,
                &config
            ),
            expected
        );
        assert_eq!(
            classify_frame(
                &remote_to_guest,
                PacketDirection::RemoteToGuest,
                &config
            ),
            expected
        );
    }

    #[test]
    fn local_subnet_udp_is_control() {
        let config = ConsommeConfig::new();
        let frame = ipv4_frame(
            UDP,
            [10, 0, 0, 2],
            [10, 0, 0, 254],
            [0x12, 0x34, 0x56, 0x78],
        );
        assert_eq!(
            classify_frame(&frame, PacketDirection::GuestToRemote, &config),
            PacketClass::Control
        );
    }

    #[test]
    fn gateway_tcp_dns_is_control() {
        let config = ConsommeConfig::new();
        let frame = ipv4_frame(
            TCP,
            [10, 0, 0, 2],
            config.gateway_ip.octets(),
            [0x12, 0x34, 0, 53],
        );
        assert_eq!(
            classify_frame(&frame, PacketDirection::GuestToRemote, &config),
            PacketClass::Control
        );
    }

    #[test]
    fn udp_hash_uses_guest_socket_only() {
        let guest = "10.0.0.2:4660".parse().unwrap();
        let first = FlowKey::Udp {
            guest,
            remote: "1.1.1.1:53".parse().unwrap(),
        };
        let second = FlowKey::Udp {
            guest,
            remote: "8.8.8.8:53".parse().unwrap(),
        };
        assert_eq!(first.stable_hash(7), second.stable_hash(7));
    }

    #[test]
    fn sequential_even_tcp_ports_are_balanced_across_power_of_two_shards() {
        let remote = "192.168.2.107:5201".parse().unwrap();
        let mut counts = [0; 4];
        for port in (40000..40128).step_by(2) {
            let flow = FlowKey::Tcp {
                guest: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), port),
                remote,
            };
            counts[flow.stable_hash(7) as usize % counts.len()] += 1;
        }
        assert!(counts.into_iter().all(|count| (8..=24).contains(&count)));
    }

    #[test]
    fn truncated_frame_drops() {
        assert_eq!(
            classify_frame(
                &[0; 13],
                PacketDirection::GuestToRemote,
                &ConsommeConfig::new()
            ),
            PacketClass::Drop
        );
    }
}
