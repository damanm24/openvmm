// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal DHCPv4 server that leases the single configured guest address.

use super::ChecksumState;
use super::FrameSink;
use super::GatewayConfig;
use super::MIN_MTU;
use super::ServiceError;
use heapless::Vec as HeaplessVec;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::DHCP_MAX_DNS_SERVER_COUNT;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::UdpPacket;
use smoltcp::wire::UdpRepr;

pub(crate) const DHCP_SERVER: u16 = 67;
const DHCP_CLIENT: u16 = 68;
// RFC 1542 section 2.1 requires every BOOTP message to be at least 300 octets.
const BOOTP_MIN_MESSAGE_LEN: usize = 300;
const LEASE_SECS: u32 = 86400;

pub(crate) fn handle_dhcp(
    cfg: &GatewayConfig,
    payload: &[u8],
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    let packet = DhcpPacket::new_checked(payload)?;
    let req = DhcpRepr::parse(&packet)?;
    let gateway_ip = cfg.gateway_ip;
    let client_ip = cfg.client_ip;

    // There is no relay-facing network path; ignore relayed requests.
    if req.relay_agent_ip != Ipv4Address::UNSPECIFIED {
        return Ok(());
    }

    let (your_ip, message_type) = match req.message_type {
        DhcpMessageType::Discover => (Some(client_ip), DhcpMessageType::Offer),
        DhcpMessageType::Request => {
            // A SELECTING request for another server declines our offer.
            if req.server_identifier.is_some_and(|s| s != gateway_ip) {
                return Ok(());
            }
            let requested = req
                .requested_ip
                .or_else(|| (req.client_ip != Ipv4Address::UNSPECIFIED).then_some(req.client_ip));
            let your_ip = match requested {
                Some(addr) if addr == client_ip => Some(addr),
                None => return Ok(()),
                Some(_) => None,
            };
            (your_ip, DhcpMessageType::Ack)
        }
        ty => return Err(ServiceError::UnsupportedDhcp(ty)),
    };
    let response_client_ip = if message_type == DhcpMessageType::Ack && req.requested_ip.is_none() {
        req.client_ip
    } else {
        Ipv4Address::UNSPECIFIED
    };

    let mut dns_servers: HeaplessVec<Ipv4Address, DHCP_MAX_DNS_SERVER_COUNT> = HeaplessVec::new();
    dns_servers.extend(
        cfg.nameservers
            .iter()
            .filter_map(|ip| match ip {
                IpAddress::Ipv4(addr) => Some(*addr),
                _ => None,
            })
            .take(DHCP_MAX_DNS_SERVER_COUNT),
    );

    let base = DhcpRepr {
        message_type,
        transaction_id: req.transaction_id,
        secs: 0,
        client_hardware_address: req.client_hardware_address,
        client_ip: Ipv4Address::UNSPECIFIED,
        your_ip: Ipv4Address::UNSPECIFIED,
        server_ip: Ipv4Address::UNSPECIFIED,
        router: None,
        subnet_mask: None,
        relay_agent_ip: Ipv4Address::UNSPECIFIED,
        broadcast: req.broadcast,
        requested_ip: None,
        client_identifier: None,
        server_identifier: Some(gateway_ip),
        parameter_request_list: None,
        dns_servers: None,
        max_size: None,
        lease_duration: None,
        renew_duration: None,
        rebind_duration: None,
        additional_options: &[],
    };
    let resp = match your_ip {
        Some(your_ip) => DhcpRepr {
            client_ip: response_client_ip,
            your_ip,
            router: Some(gateway_ip),
            subnet_mask: Some(cfg.net_mask),
            dns_servers: Some(dns_servers),
            lease_duration: Some(LEASE_SECS),
            ..base
        },
        None => DhcpRepr {
            message_type: DhcpMessageType::Nak,
            ..base
        },
    };

    // RFC 2131 section 4.1: a DHCPNAK is always broadcast without a relay.
    let (dst_mac, dst_ip) = match your_ip {
        None => (EthernetAddress::BROADCAST, Ipv4Address::BROADCAST),
        Some(_) if req.client_ip != Ipv4Address::UNSPECIFIED => {
            (req.client_hardware_address, req.client_ip)
        }
        Some(_) if req.broadcast => (EthernetAddress::BROADCAST, Ipv4Address::BROADCAST),
        Some(ip) => (req.client_hardware_address, ip),
    };

    let udp = UdpRepr {
        src_port: DHCP_SERVER,
        dst_port: DHCP_CLIENT,
    };
    let dhcp_len = resp.buffer_len().max(BOOTP_MIN_MESSAGE_LEN);
    let ipv4 = Ipv4Repr {
        src_addr: gateway_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + dhcp_len,
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: cfg.gateway_mac,
        dst_addr: dst_mac,
        ethertype: EthernetProtocol::Ipv4,
    };

    let mut buffer = [0; MIN_MTU];
    let mut eth_packet = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth.emit(&mut eth_packet);
    let mut ipv4_packet = Ipv4Packet::new_unchecked(eth_packet.payload_mut());
    ipv4.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    let mut emit_result = Ok(());
    udp.emit(
        &mut UdpPacket::new_unchecked(ipv4_packet.payload_mut()),
        &IpAddress::Ipv4(ipv4.src_addr),
        &IpAddress::Ipv4(ipv4.dst_addr),
        dhcp_len,
        |payload| emit_result = resp.emit(&mut DhcpPacket::new_unchecked(payload)),
        &ChecksumCapabilities::default(),
    );
    emit_result?;

    let len = eth.buffer_len() + ipv4.buffer_len() + udp.header_len() + dhcp_len;
    sink.send_frame(&buffer[..len], &ChecksumState::UDP4);
    Ok(())
}
