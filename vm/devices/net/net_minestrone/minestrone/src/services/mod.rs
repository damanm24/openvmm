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

pub use net_usermode::ChecksumState;
pub use net_usermode::DNS_PORT;
pub use net_usermode::FrameSink;
pub use net_usermode::MIN_MTU;
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

/// Addressing of the virtual link between the guest and the gateway.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Negotiated IP MTU, excluding the Ethernet header.
    pub mtu: u16,
    /// The gateway's MAC address, for IPv4 and IPv6.
    pub gateway_mac: EthernetAddress,
    /// The gateway's IPv4 address.
    pub gateway_ip: Ipv4Address,
    /// The guest's MAC address.
    pub client_mac: EthernetAddress,
    /// The IPv4 address assigned to the guest.
    pub client_ip: Ipv4Address,
    /// The IPv4 network mask.
    pub net_mask: Ipv4Address,
    /// The gateway's link-local IPv6 address, the guest's IPv6 default
    /// router.
    pub gateway_link_local_ipv6: Ipv6Address,
    /// The IPv6 address assigned to the guest with DHCPv6. Its /64 prefix is
    /// advertised as on-link and for SLAAC. If `None`, the guest is only
    /// given its link-local address and no default route.
    pub assigned_ipv6: Option<Ipv6Address>,
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
                if !(addr.is_unspecified() || addr.is_loopback() || addr.is_multicast()) =>
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
    /// DHCPv6 address assignment and information requests.
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
    use net_usermode::addr::link_local_from_mac;
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
    use smoltcp::wire::NdiscPrefixInfoFlags;
    use smoltcp::wire::NdiscRepr;
    use smoltcp::wire::NdiscRouterFlags;
    use smoltcp::wire::RawHardwareAddress;
    use smoltcp::wire::UdpRepr;
    use test_with_tracing::test;

    const CLIENT_MAC: EthernetAddress = EthernetAddress([0, 0x15, 0x5d, 0x12, 0x34, 0x56]);

    #[derive(Default)]
    struct Capture(Vec<(Vec<u8>, ChecksumState)>);

    impl FrameSink for Capture {
        fn recv(&mut self, data: &[u8], checksum: &ChecksumState) {
            self.0.push((data.to_vec(), *checksum));
        }

        fn rx_mtu(&mut self) -> usize {
            MIN_MTU
        }
    }

    fn config() -> GatewayConfig {
        GatewayConfig {
            mtu: 1500,
            gateway_mac: EthernetAddress([0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55]),
            gateway_ip: Ipv4Address::new(10, 0, 0, 1),
            client_mac: CLIENT_MAC,
            client_ip: Ipv4Address::new(10, 0, 0, 2),
            net_mask: Ipv4Address::new(255, 255, 255, 0),
            gateway_link_local_ipv6: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            assigned_ipv6: Some(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x123)),
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
    fn arp_answers_all_addresses_except_guest() {
        let mut cfg = config();
        let request_from = |source, target| {
            let repr = ArpRepr::EthernetIpv4 {
                operation: ArpOperation::Request,
                source_hardware_addr: CLIENT_MAC,
                source_protocol_addr: source,
                target_hardware_addr: EthernetAddress([0; 6]),
                target_protocol_addr: target,
            };
            let mut buf = vec![0; repr.buffer_len()];
            repr.emit(&mut ArpPacket::new_unchecked(&mut buf));
            buf
        };
        let request = |target| request_from(cfg.client_ip, target);
        let e = eth(EthernetProtocol::Arp);
        let gateway_req = request(cfg.gateway_ip);
        let other_req = request(Ipv4Address::new(10, 0, 0, 77));
        let self_req = request(cfg.client_ip);
        let remote_req = request(Ipv4Address::new(10, 0, 1, 1));
        let announcement = request_from(cfg.client_ip, cfg.client_ip);
        let probe = request_from(Ipv4Address::UNSPECIFIED, Ipv4Address::new(10, 0, 0, 9));

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
        assert_eq!(handle(&mut cfg, &e, &remote_req).0.len(), 1);
        assert!(handle(&mut cfg, &e, &announcement).0.is_empty());
        assert_eq!(handle(&mut cfg, &e, &probe).0.len(), 1);
    }

    fn dhcp_discover(cfg: &mut GatewayConfig) -> Capture {
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
        handle(cfg, &eth(EthernetProtocol::Ipv4), &frame)
    }

    /// Sends a DHCPDISCOVER and returns the raw DHCP payload of the offer.
    fn dhcp_offer(cfg: &mut GatewayConfig) -> Vec<u8> {
        let replies = dhcp_discover(cfg).0;

        let (reply, checksum) = &replies[0];
        assert!(checksum.ipv4 && checksum.udp);
        let eth = EthernetFrame::new_checked(&reply[..]).unwrap();
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        udp.payload().to_vec()
    }

    #[test]
    fn dhcp_without_a_gateway_does_not_offer_a_lease() {
        let mut cfg = config();
        cfg.gateway_ip = Ipv4Address::UNSPECIFIED;
        assert!(dhcp_discover(&mut cfg).0.is_empty());
    }

    #[test]
    fn dhcp_discover_offers_configured_lease() {
        let mut cfg = config();
        cfg.mtu = 9000;
        let payload = dhcp_offer(&mut cfg);
        let packet = DhcpPacket::new_checked(&payload[..]).unwrap();
        let offer = DhcpRepr::parse(&packet).unwrap();
        assert_eq!(offer.message_type, DhcpMessageType::Offer);
        assert_eq!(offer.your_ip, cfg.client_ip);
        assert_eq!(offer.router, Some(cfg.gateway_ip));
        assert_eq!(offer.subnet_mask, Some(cfg.net_mask));
        assert_eq!(offer.lease_duration, Some(u32::MAX));
        assert_eq!(
            packet.options().find(|o| o.kind == 26).unwrap().data,
            &9000u16.to_be_bytes()
        );
        assert_eq!(
            offer.dns_servers.unwrap().as_slice(),
            &[Ipv4Address::new(192, 0, 2, 53)]
        );
        assert!(packet.options().all(|o| o.kind != 121));
    }

    #[test]
    fn dhcp_routes_to_gateway_outside_subnet() {
        let mut cfg = config();
        cfg.gateway_ip = Ipv4Address::new(192, 0, 2, 1);
        let payload = dhcp_offer(&mut cfg);
        let packet = DhcpPacket::new_checked(&payload[..]).unwrap();
        let routes = packet.options().find(|o| o.kind == 121).unwrap();
        // 192.0.2.1/32 on-link, then 0.0.0.0/0 via 192.0.2.1.
        assert_eq!(routes.data, [32, 192, 0, 2, 1, 0, 0, 0, 0, 0, 192, 0, 2, 1]);
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
        cfg.mtu = 9000;
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
        let NdiscRepr::RouterAdvert {
            flags,
            prefix_info,
            mtu,
            ..
        } = NdiscRepr::parse(&icmp).unwrap()
        else {
            panic!("expected router advertisement");
        };
        assert_eq!(flags, NdiscRouterFlags::MANAGED);
        assert_eq!(mtu, Some(9000));
        let prefix = prefix_info.unwrap();
        assert_eq!(prefix.prefix_len, 64);
        assert_eq!(
            prefix.prefix,
            Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            prefix.flags,
            NdiscPrefixInfoFlags::ON_LINK | NdiscPrefixInfoFlags::ADDRCONF
        );

        // Without an assigned address, the guest gets no router.
        cfg.assigned_ipv6 = None;
        assert!(handle(&mut cfg, &e, &rs).0.is_empty());
    }

    #[test]
    fn ndp_answers_neighbor_solicits_except_for_guest() {
        let mut cfg = config();
        let guest_ll = link_local_from_mac(CLIENT_MAC);
        let e = eth(EthernetProtocol::Ipv6);
        let solicit = |target| {
            ndp_frame(
                guest_ll,
                target,
                NdiscRepr::NeighborSolicit {
                    target_addr: target,
                    lladdr: Some(RawHardwareAddress::from(CLIENT_MAC)),
                },
            )
        };
        let on_link = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x77);
        let replies = handle(&mut cfg, &e, &solicit(on_link)).0;
        let eth = EthernetFrame::new_checked(&replies[0].0[..]).unwrap();
        assert_eq!(eth.src_addr(), cfg.gateway_mac);
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        let NdiscRepr::NeighborAdvert { target_addr, .. } = NdiscRepr::parse(&icmp).unwrap() else {
            panic!("expected neighbor advertisement");
        };
        assert_eq!(target_addr, on_link);
        let gateway_ns = solicit(cfg.gateway_link_local_ipv6);
        assert_eq!(handle(&mut cfg, &e, &gateway_ns).0.len(), 1);
        let assigned_ns = solicit(cfg.assigned_ipv6.unwrap());
        assert!(handle(&mut cfg, &e, &assigned_ns).0.is_empty());
    }
}
