// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Virtual-gateway services: ARP, DHCPv4, DHCPv6, and NDP.
//!
//! The translator impersonates the guest's default gateway, so it must answer
//! the link- and network-layer protocols the guest directs at that gateway.
//! [`GatewayServices::handle_frame`] is offered every guest frame before L4
//! translation. Replies are written to a [`FrameSink`].
//!
//! These are ported from Consomme. Sharing one implementation between the two
//! stacks is left for a later cleanup.

mod arp;
mod dhcp;
mod dhcpv6;
mod ndp;

use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::Icmpv6Message;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::UdpPacket;
use thiserror::Error;

/// Standard DNS port.
pub const DNS_PORT: u16 = 53;

/// The largest standard Ethernet frame, without FCS. Service replies always
/// fit, so every guest receive buffer can hold them.
pub const MIN_MTU: usize = 1514;

/// Checksum and segmentation state for a frame passed between a stack and the
/// guest NIC.
#[derive(Debug, Copy, Clone)]
pub struct ChecksumState {
    /// On receive, the data has a valid IPv4 header checksum. On send, the
    /// checksum should be ignored.
    pub ipv4: bool,
    /// On receive, the data has a valid TCP checksum, or a pseudo-header
    /// partial checksum when `partial` is set. On send, the checksum should be
    /// ignored.
    pub tcp: bool,
    /// On receive, the data has a valid UDP checksum, or a pseudo-header
    /// partial checksum when `partial` is set. On send, the checksum should be
    /// ignored.
    pub udp: bool,
    /// On receive, the TCP or UDP checksum contains only the uncomplemented
    /// pseudo-header sum, including the transport length. The client must
    /// complete the checksum. Not used on send.
    pub partial: bool,
    /// The data consists of multiple TCP segments, each with the provided
    /// segment size.
    ///
    /// The IP header's length field may be invalid and should be ignored.
    pub tso: Option<u16>,
    /// The data is a large UDP payload to be split into UDP datagrams of this
    /// segment size.
    pub gso: Option<u16>,
}

impl ChecksumState {
    /// No checksums are valid and no segmentation is requested.
    pub const NONE: Self = Self {
        ipv4: false,
        tcp: false,
        udp: false,
        partial: false,
        tso: None,
        gso: None,
    };
    /// Valid IPv4 header and TCP checksums.
    pub const TCP4: Self = Self {
        ipv4: true,
        tcp: true,
        ..Self::NONE
    };
    /// Valid TCP checksum over IPv6.
    pub const TCP6: Self = Self {
        tcp: true,
        ..Self::NONE
    };
    /// Valid IPv4 header and UDP checksums.
    pub const UDP4: Self = Self {
        ipv4: true,
        udp: true,
        ..Self::NONE
    };
    /// Valid UDP checksum over IPv6.
    pub const UDP6: Self = Self {
        udp: true,
        ..Self::NONE
    };
}

/// Destination for frames sent to the guest.
pub trait FrameSink {
    /// Delivers a complete Ethernet frame to the guest.
    fn send_frame(&mut self, frame: &[u8], checksum: &ChecksumState) {
        self.send_frame_segments(&[frame], checksum);
    }

    /// Delivers one Ethernet frame whose bytes are split across `segments`,
    /// in order. This avoids linearizing headers and payload.
    fn send_frame_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState);

    /// Returns the largest frame the sink can currently accept, or 0 if the
    /// guest has no receive buffers available.
    fn max_frame_len(&mut self) -> usize;
}

/// Computes the EUI-64 link-local IPv6 address for a MAC address (RFC 4291
/// section 2.5.6, RFC 2464 section 4).
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

/// Returns true if `a` and `b` are in the same IPv4 subnet.
pub fn is_same_ipv4_subnet(a: Ipv4Address, b: Ipv4Address, mask: Ipv4Address) -> bool {
    let mask = mask.to_bits();
    a.to_bits() & mask == b.to_bits() & mask
}

/// Returns true if `a` and `b` share their first `prefix_len` bits.
pub fn is_same_ipv6_subnet(a: Ipv6Address, b: Ipv6Address, prefix_len: u8) -> bool {
    let shift = 128 - u32::from(prefix_len.min(128));
    let a = u128::from_be_bytes(a.octets());
    let b = u128::from_be_bytes(b.octets());
    a.checked_shr(shift).unwrap_or(0) == b.checked_shr(shift).unwrap_or(0)
}

/// Addressing of the virtual link between the guest and the gateway.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// The gateway's MAC address.
    pub gateway_mac: EthernetAddress,
    /// The gateway's IPv4 address.
    pub gateway_ip: Ipv4Address,
    /// The guest's MAC address.
    pub client_mac: EthernetAddress,
    /// The IPv4 address assigned to the guest.
    pub client_ip: Ipv4Address,
    /// The IPv4 network mask.
    pub net_mask: Ipv4Address,
    /// The gateway's MAC address for IPv6.
    pub gateway_mac_ipv6: EthernetAddress,
    /// The gateway's link-local IPv6 address.
    pub gateway_link_local_ipv6: Ipv6Address,
    /// The IPv6 prefix length advertised to the guest.
    pub prefix_len_ipv6: u8,
    /// If true, advertise an autonomous IPv6 prefix so the guest configures a
    /// routable address with SLAAC.
    pub advertise_routable_ipv6: bool,
    /// The guest's link-local IPv6 address, once learned.
    pub client_ip_ipv6: Option<Ipv6Address>,
    /// The guest's routable IPv6 address, once learned.
    pub client_ip_ipv6_routable: Option<Ipv6Address>,
    /// Nameservers handed to the guest.
    pub nameservers: Vec<IpAddress>,
    /// If true, DNS queries to the gateway are answered by the gateway.
    pub internal_dns: bool,
}

impl GatewayConfig {
    /// Returns the IPv6 nameservers that are usable from the guest's link.
    pub fn filtered_ipv6_nameservers(&self) -> impl Iterator<Item = Ipv6Address> + '_ {
        self.nameservers.iter().filter_map(|ip| match ip {
            IpAddress::Ipv6(addr)
                if !(addr.is_unspecified()
                    || addr.is_loopback()
                    || addr.is_multicast()
                    || matches!(addr.octets()[0], 0xfc | 0xfd)
                    || addr.octets().starts_with(&[0xfe, 0xc0])) =>
            {
                Some(*addr)
            }
            _ => None,
        })
    }
}

/// A gateway service.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Service {
    /// ARP for IPv4 neighbor resolution.
    Arp,
    /// DHCPv4 address assignment.
    Dhcp,
    /// DHCPv6 information requests.
    Dhcpv6,
    /// IPv6 router and neighbor discovery.
    Ndp,
    /// DNS queries addressed to the gateway.
    Dns,
}

/// The outcome of offering a frame to the gateway services.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// A service consumed the frame. The stack must not process it further.
    Handled,
    /// The frame is not addressed to a gateway service. The stack should
    /// translate it.
    NotForGateway,
}

/// An error handling a frame addressed to a gateway service.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// The frame could not be parsed.
    #[error("malformed packet")]
    Packet(#[from] smoltcp::wire::Error),
    /// The frame parsed but is invalid for the service.
    #[error("invalid service message")]
    Malformed,
    /// The ARP operation is not supported.
    #[error("unsupported arp operation")]
    UnsupportedArp,
    /// The DHCP message type is not supported.
    #[error("unsupported dhcp message type {0:?}")]
    UnsupportedDhcp(smoltcp::wire::DhcpMessageType),
    /// The DHCPv6 message type is not supported.
    #[error("unsupported dhcpv6 message type {0}")]
    UnsupportedDhcpv6(u8),
    /// The service has not been implemented.
    #[error("{0:?} service is not implemented")]
    Unimplemented(Service),
}

/// Identifies the gateway service, if any, that a guest frame is addressed to.
///
/// Malformed frames are not classified; the caller's own parsing reports them.
pub fn classify(cfg: &GatewayConfig, eth: &EthernetRepr, payload: &[u8]) -> Option<Service> {
    match eth.ethertype {
        EthernetProtocol::Arp => Some(Service::Arp),
        EthernetProtocol::Ipv4 => {
            let ip = Ipv4Packet::new_checked(payload).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            match udp.dst_port() {
                dhcp::DHCP_SERVER => Some(Service::Dhcp),
                DNS_PORT if cfg.internal_dns && ip.dst_addr() == cfg.gateway_ip => {
                    Some(Service::Dns)
                }
                _ => None,
            }
        }
        EthernetProtocol::Ipv6 => {
            let ip = Ipv6Packet::new_checked(payload).ok()?;
            match ip.next_header() {
                IpProtocol::Udp => {
                    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
                    match udp.dst_port() {
                        dhcpv6::DHCPV6_SERVER => Some(Service::Dhcpv6),
                        DNS_PORT
                            if cfg.internal_dns && ip.dst_addr() == cfg.gateway_link_local_ipv6 =>
                        {
                            Some(Service::Dns)
                        }
                        _ => None,
                    }
                }
                IpProtocol::Icmpv6 => {
                    let icmp = Icmpv6Packet::new_checked(ip.payload()).ok()?;
                    matches!(
                        icmp.msg_type(),
                        Icmpv6Message::RouterSolicit
                            | Icmpv6Message::RouterAdvert
                            | Icmpv6Message::NeighborSolicit
                            | Icmpv6Message::NeighborAdvert
                            | Icmpv6Message::Redirect
                    )
                    .then_some(Service::Ndp)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// State for the gateway services of one virtual link.
#[derive(Debug, Default)]
pub struct GatewayServices {}

impl GatewayServices {
    /// Creates the gateway services.
    pub fn new() -> Self {
        Self {}
    }

    /// Offers a guest frame to the gateway services.
    ///
    /// `eth` is the parsed Ethernet header and `payload` the bytes after it.
    /// Replies are written to `sink`. `cfg` is mutable because services learn
    /// the guest's IPv6 addresses from Duplicate Address Detection.
    pub fn handle_frame(
        &mut self,
        cfg: &mut GatewayConfig,
        eth: &EthernetRepr,
        payload: &[u8],
        sink: &mut dyn FrameSink,
    ) -> Result<Disposition, ServiceError> {
        let Some(service) = classify(cfg, eth, payload) else {
            return Ok(Disposition::NotForGateway);
        };
        // `classify` validated the headers it inspected, so the checked
        // constructors below cannot fail for the classified services.
        match service {
            Service::Arp => arp::handle_arp(cfg, eth, payload, sink)?,
            Service::Dhcp => {
                let ip = Ipv4Packet::new_checked(payload)?;
                let udp = UdpPacket::new_checked(ip.payload())?;
                dhcp::handle_dhcp(cfg, udp.payload(), sink)?
            }
            Service::Dhcpv6 => {
                let ip = Ipv6Packet::new_checked(payload)?;
                let udp = UdpPacket::new_checked(ip.payload())?;
                dhcpv6::handle_dhcpv6(cfg, udp.payload(), ip.src_addr(), sink)?
            }
            Service::Ndp => {
                let ip = Ipv6Packet::new_checked(payload)?;
                // RFC 4861: NDP messages must not have been forwarded.
                if ip.hop_limit() != 255 {
                    return Err(ServiceError::Malformed);
                }
                ndp::handle_ndp(cfg, eth, ip.payload(), ip.src_addr(), sink)?
            }
            Service::Dns => return Err(ServiceError::Unimplemented(Service::Dns)),
        }
        Ok(Disposition::Handled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::ArpOperation;
    use smoltcp::wire::ArpPacket;
    use smoltcp::wire::ArpRepr;
    use smoltcp::wire::DhcpMessageType;
    use smoltcp::wire::DhcpPacket;
    use smoltcp::wire::DhcpRepr;
    use smoltcp::wire::EthernetFrame;
    use smoltcp::wire::Ipv4Repr;
    use smoltcp::wire::Ipv6Repr;
    use smoltcp::wire::NdiscRepr;
    use smoltcp::wire::RawHardwareAddress;
    use smoltcp::wire::UdpRepr;
    use test_with_tracing::test;

    const CLIENT_MAC: EthernetAddress = EthernetAddress([0, 0x15, 0x5d, 0x12, 0x34, 0x56]);

    #[derive(Default)]
    struct Capture(Vec<(Vec<u8>, ChecksumState)>);

    impl FrameSink for Capture {
        fn send_frame_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState) {
            self.0.push((segments.concat(), *checksum));
        }

        fn max_frame_len(&mut self) -> usize {
            MIN_MTU
        }
    }

    fn config() -> GatewayConfig {
        let gateway_mac_ipv6 = EthernetAddress([0x52, 0x55, 10, 0, 1, 2]);
        GatewayConfig {
            gateway_mac: EthernetAddress([0x52, 0x55, 10, 0, 0, 1]),
            gateway_ip: Ipv4Address::new(10, 0, 0, 1),
            client_mac: CLIENT_MAC,
            client_ip: Ipv4Address::new(10, 0, 0, 2),
            net_mask: Ipv4Address::new(255, 255, 255, 0),
            gateway_mac_ipv6,
            gateway_link_local_ipv6: link_local_from_mac(gateway_mac_ipv6),
            prefix_len_ipv6: 64,
            advertise_routable_ipv6: true,
            client_ip_ipv6: None,
            client_ip_ipv6_routable: None,
            nameservers: vec![Ipv4Address::new(192, 0, 2, 53).into()],
            internal_dns: false,
        }
    }

    fn eth(ethertype: EthernetProtocol) -> EthernetRepr {
        EthernetRepr {
            src_addr: CLIENT_MAC,
            dst_addr: EthernetAddress::BROADCAST,
            ethertype,
        }
    }

    fn udp4(src: Ipv4Address, dst: Ipv4Address, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp = UdpRepr {
            src_port: 40000,
            dst_port,
        };
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut buf = vec![0; ip.buffer_len() + ip.payload_len];
        let caps = ChecksumCapabilities::default();
        let mut packet = Ipv4Packet::new_unchecked(&mut buf);
        ip.emit(&mut packet, &caps);
        udp.emit(
            &mut UdpPacket::new_unchecked(packet.payload_mut()),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &caps,
        );
        buf
    }

    fn handle(cfg: &mut GatewayConfig, e: &EthernetRepr, payload: &[u8]) -> Capture {
        let mut sink = Capture::default();
        GatewayServices::new()
            .handle_frame(cfg, e, payload, &mut sink)
            .unwrap();
        sink
    }

    #[test]
    fn dns_is_gateway_service_only_when_addressed_to_gateway() {
        let mut cfg = config();
        cfg.internal_dns = true;
        let to_gateway = udp4(cfg.client_ip, cfg.gateway_ip, DNS_PORT, &[0; 8]);
        let to_remote = udp4(
            cfg.client_ip,
            Ipv4Address::new(8, 8, 8, 8),
            DNS_PORT,
            &[0; 8],
        );
        let e = eth(EthernetProtocol::Ipv4);
        assert_eq!(classify(&cfg, &e, &to_gateway), Some(Service::Dns));
        assert_eq!(classify(&cfg, &e, &to_remote), None);
        cfg.internal_dns = false;
        assert_eq!(classify(&cfg, &e, &to_gateway), None);
    }

    #[test]
    fn truncated_frames_are_not_classified() {
        let cfg = config();
        let frame = udp4(cfg.client_ip, cfg.gateway_ip, 67, &[0; 8]);
        for len in 0..frame.len() {
            assert_eq!(
                classify(&cfg, &eth(EthernetProtocol::Ipv4), &frame[..len]),
                None
            );
        }
    }

    #[test]
    fn arp_answers_subnet_addresses_except_guest() {
        let mut cfg = config();
        let request = |target| {
            let repr = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: CLIENT_MAC,
                source_protocol_addr: cfg.client_ip,
                target_hardware_addr: EthernetAddress([0; 6]),
                target_protocol_addr: target,
            };
            let mut buf = vec![0; repr.buffer_len()];
            repr.emit(&mut ArpPacket::new_unchecked(&mut buf));
            buf
        };
        let e = eth(EthernetProtocol::Arp);
        let gateway_req = request(cfg.gateway_ip);
        let other_req = request(Ipv4Address::new(10, 0, 0, 77));
        let self_req = request(cfg.client_ip);
        let remote_req = request(Ipv4Address::new(10, 0, 1, 1));

        let replies = handle(&mut cfg, &e, &gateway_req).0;
        let frame = EthernetFrame::new_checked(&replies[0].0[..]).unwrap();
        let ArpRepr::EthernetIpv4 {
            operation,
            source_hardware_addr,
            source_protocol_addr,
            ..
        } = ArpRepr::parse(&ArpPacket::new_checked(frame.payload()).unwrap()).unwrap()
        else {
            panic!()
        };
        assert_eq!(operation, ArpOperation::Reply);
        assert_eq!(source_hardware_addr, cfg.gateway_mac);
        assert_eq!(source_protocol_addr, cfg.gateway_ip);
        assert_eq!(handle(&mut cfg, &e, &other_req).0.len(), 1);
        assert!(handle(&mut cfg, &e, &self_req).0.is_empty());
        assert!(handle(&mut cfg, &e, &remote_req).0.is_empty());
    }

    #[test]
    fn dhcp_discover_offers_configured_lease() {
        let mut cfg = config();
        let discover = DhcpRepr {
            message_type: DhcpMessageType::Discover,
            transaction_id: 0x1234_5678,
            secs: 0,
            client_hardware_address: CLIENT_MAC,
            client_ip: Ipv4Address::UNSPECIFIED,
            your_ip: Ipv4Address::UNSPECIFIED,
            server_ip: Ipv4Address::UNSPECIFIED,
            router: None,
            subnet_mask: None,
            relay_agent_ip: Ipv4Address::UNSPECIFIED,
            broadcast: true,
            requested_ip: None,
            client_identifier: None,
            server_identifier: None,
            parameter_request_list: None,
            dns_servers: None,
            max_size: None,
            lease_duration: None,
            renew_duration: None,
            rebind_duration: None,
            additional_options: &[],
        };
        let mut dhcp = vec![0; discover.buffer_len()];
        discover
            .emit(&mut DhcpPacket::new_unchecked(&mut dhcp))
            .unwrap();
        let frame = udp4(Ipv4Address::UNSPECIFIED, Ipv4Address::BROADCAST, 67, &dhcp);
        let replies = handle(&mut cfg, &eth(EthernetProtocol::Ipv4), &frame).0;

        let (reply, checksum) = &replies[0];
        assert!(checksum.ipv4 && checksum.udp);
        let eth = EthernetFrame::new_checked(&reply[..]).unwrap();
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        let packet = DhcpPacket::new_checked(udp.payload()).unwrap();
        let offer = DhcpRepr::parse(&packet).unwrap();
        assert_eq!(offer.message_type, DhcpMessageType::Offer);
        assert_eq!(offer.your_ip, cfg.client_ip);
        assert_eq!(offer.router, Some(cfg.gateway_ip));
        assert_eq!(offer.subnet_mask, Some(cfg.net_mask));
        assert_eq!(
            offer.dns_servers.unwrap().as_slice(),
            &[Ipv4Address::new(192, 0, 2, 53)]
        );
    }

    fn ndp_frame(src: Ipv6Address, dst: Ipv6Address, repr: NdiscRepr<'_>) -> Vec<u8> {
        let ip = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Icmpv6,
            payload_len: repr.buffer_len(),
            hop_limit: 255,
        };
        let mut buf = vec![0; ip.buffer_len() + ip.payload_len];
        let mut packet = Ipv6Packet::new_unchecked(&mut buf);
        ip.emit(&mut packet);
        let mut icmp = Icmpv6Packet::new_unchecked(packet.payload_mut());
        repr.emit(&mut icmp);
        icmp.fill_checksum(&src, &dst);
        buf
    }

    #[test]
    fn ndp_learns_dad_addresses_and_answers_router_solicit() {
        let mut cfg = config();
        let guest_ll = link_local_from_mac(CLIENT_MAC);
        let all_routers = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        let e = eth(EthernetProtocol::Ipv6);

        let dad = ndp_frame(
            Ipv6Address::UNSPECIFIED,
            Ipv6Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0),
            NdiscRepr::NeighborSolicit {
                target_addr: guest_ll,
                lladdr: None,
            },
        );
        assert!(handle(&mut cfg, &e, &dad).0.is_empty());
        assert_eq!(cfg.client_ip_ipv6, Some(guest_ll));

        let rs = ndp_frame(
            guest_ll,
            all_routers,
            NdiscRepr::RouterSolicit {
                lladdr: Some(RawHardwareAddress::from(CLIENT_MAC)),
            },
        );
        let replies = handle(&mut cfg, &e, &rs).0;
        let eth = EthernetFrame::new_checked(&replies[0].0[..]).unwrap();
        assert_eq!(eth.dst_addr(), CLIENT_MAC);
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.dst_addr(), guest_ll);
        let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
        let NdiscRepr::RouterAdvert { prefix_info, .. } = NdiscRepr::parse(&icmp).unwrap() else {
            panic!("expected router advertisement");
        };
        let prefix = prefix_info.unwrap();
        assert_eq!(prefix.prefix_len, 64);
        assert_eq!(
            prefix.prefix,
            Ipv6Address::new(0xfd64, 0xa050, 0xcea6, 0, 0, 0, 0, 0)
        );
    }

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
    }
}
