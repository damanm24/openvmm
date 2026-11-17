// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stateless DHCPv6 (RFC 8415): answers Information-Request messages with the
//! configured IPv6 DNS servers, for guests that configured their addresses with
//! SLAAC.

use super::ChecksumState;
use super::FrameSink;
use super::GatewayConfig;
use super::MIN_MTU;
use super::ServiceError;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::Ipv6Repr;
use smoltcp::wire::UdpPacket;
use smoltcp::wire::UdpRepr;

pub(crate) const DHCPV6_SERVER: u16 = 547;
const DHCPV6_CLIENT: u16 = 546;
const ALL_AGENTS_MULTICAST: Ipv6Address =
    Ipv6Address::from_octets([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2]);

const MSG_REPLY: u8 = 7;
const MSG_INFORMATION_REQUEST: u8 = 11;
const OPTION_CLIENT_ID: u16 = 1;
const OPTION_SERVER_ID: u16 = 2;
const OPTION_DNS_SERVERS: u16 = 23;

/// The fields of a guest DHCPv6 message that the server uses.
struct Request<'a> {
    msg_type: u8,
    transaction_id: [u8; 3],
    client_id: Option<&'a [u8]>,
}

fn parse(msg: &[u8]) -> Result<Request<'_>, ServiceError> {
    let (header, mut rest) = msg
        .split_first_chunk::<4>()
        .ok_or(ServiceError::Malformed)?;
    let [msg_type, t0, t1, t2] = *header;
    let mut client_id = None;
    while !rest.is_empty() {
        let (option, after) = rest
            .split_first_chunk::<4>()
            .ok_or(ServiceError::Malformed)?;
        let [c0, c1, l0, l1] = *option;
        let len = u16::from_be_bytes([l0, l1]) as usize;
        let value = after.get(..len).ok_or(ServiceError::Malformed)?;
        if u16::from_be_bytes([c0, c1]) == OPTION_CLIENT_ID {
            client_id = Some(value);
        }
        rest = &after[len..];
    }
    Ok(Request {
        msg_type,
        transaction_id: [t0, t1, t2],
        client_id,
    })
}

fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}

pub(crate) fn handle_dhcpv6(
    cfg: &GatewayConfig,
    payload: &[u8],
    client_ip: Ipv6Address,
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    let req = parse(payload)?;
    if req.msg_type != MSG_INFORMATION_REQUEST {
        return Err(ServiceError::UnsupportedDhcpv6(req.msg_type));
    }

    let mut reply = vec![MSG_REPLY];
    reply.extend_from_slice(&req.transaction_id);
    if let Some(client_id) = req.client_id {
        push_option(&mut reply, OPTION_CLIENT_ID, client_id);
    }
    // DUID-LL: type 3, hardware type 1 (Ethernet), gateway MAC.
    let mut duid = vec![0x00, 0x03, 0x00, 0x01];
    duid.extend_from_slice(&cfg.gateway_mac_ipv6.0);
    push_option(&mut reply, OPTION_SERVER_ID, &duid);
    let dns: Vec<u8> = cfg
        .filtered_ipv6_nameservers()
        .flat_map(|a| a.octets())
        .collect();
    if !dns.is_empty() {
        push_option(&mut reply, OPTION_DNS_SERVERS, &dns);
    }

    let udp = UdpRepr {
        src_port: DHCPV6_SERVER,
        dst_port: DHCPV6_CLIENT,
    };
    let dst_addr = if client_ip.is_unspecified() {
        ALL_AGENTS_MULTICAST
    } else {
        client_ip
    };
    let ipv6 = Ipv6Repr {
        src_addr: cfg.gateway_link_local_ipv6,
        dst_addr,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + reply.len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: cfg.gateway_mac_ipv6,
        dst_addr: cfg.client_mac,
        ethertype: EthernetProtocol::Ipv6,
    };
    let len = eth.buffer_len() + ipv6.buffer_len() + udp.header_len() + reply.len();
    if len > MIN_MTU {
        return Err(ServiceError::Malformed);
    }

    let mut buffer = [0; MIN_MTU];
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth.emit(&mut eth_frame);
    let mut ipv6_packet = Ipv6Packet::new_unchecked(eth_frame.payload_mut());
    ipv6.emit(&mut ipv6_packet);
    udp.emit(
        &mut UdpPacket::new_unchecked(ipv6_packet.payload_mut()),
        &IpAddress::Ipv6(ipv6.src_addr),
        &IpAddress::Ipv6(ipv6.dst_addr),
        reply.len(),
        |p| p[..reply.len()].copy_from_slice(&reply),
        &ChecksumCapabilities::default(),
    );
    sink.send_frame(&buffer[..len], &ChecksumState::NONE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn parse_captured_information_request() {
        // An Information-Request captured from a Windows VM.
        let hex = "0b1c57ca0008000200000001000e0001000130adec9800155d300e150010000e0000013700084d53465420352e30000600080011001700180020";
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let req = parse(&bytes).unwrap();
        assert_eq!(req.msg_type, MSG_INFORMATION_REQUEST);
        assert_eq!(req.transaction_id, [0x1c, 0x57, 0xca]);
        assert_eq!(
            req.client_id.unwrap(),
            [
                0, 1, 0, 1, 0x30, 0xad, 0xec, 0x98, 0, 0x15, 0x5d, 0x30, 0x0e, 0x15
            ]
        );
    }

    #[test]
    fn truncated_options_are_rejected() {
        let msg = [MSG_INFORMATION_REQUEST, 0, 0, 1, 0, 1, 0, 8, 1, 2];
        for len in 0..msg.len() {
            // Every prefix is either a complete header with no options or
            // malformed; none may panic.
            let r = parse(&msg[..len]);
            assert_eq!(r.is_ok(), len == 4, "len {len}");
        }
    }
}
