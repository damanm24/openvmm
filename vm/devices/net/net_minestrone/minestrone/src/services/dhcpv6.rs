// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DHCPv6 (RFC 8415) server for the single guest address.
//!
//! As in passt, the guest's assigned IPv6 address is leased with infinite
//! lifetimes in an IA_NA, and Information-Request messages are answered with
//! the configured IPv6 DNS servers. Rapid commit, temporary addresses, and
//! prefix delegation are not supported.

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

const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_CONFIRM: u8 = 4;
const MSG_RENEW: u8 = 5;
const MSG_REBIND: u8 = 6;
const MSG_REPLY: u8 = 7;
const MSG_INFORMATION_REQUEST: u8 = 11;
const OPTION_CLIENT_ID: u16 = 1;
const OPTION_SERVER_ID: u16 = 2;
const OPTION_IA_NA: u16 = 3;
const OPTION_IAADDR: u16 = 5;
const OPTION_STATUS_CODE: u16 = 13;
const OPTION_DNS_SERVERS: u16 = 23;
const STATUS_SUCCESS: u16 = 0;
const STATUS_NOT_ON_LINK: u16 = 4;
/// The fixed fields of an IA_NA: IAID, T1, and T2.
const IA_NA_HEADER_LEN: usize = 12;
const INFINITY: u32 = u32::MAX;

/// The fields of a guest DHCPv6 message that the server uses.
struct Request<'a> {
    msg_type: u8,
    transaction_id: [u8; 3],
    client_id: Option<&'a [u8]>,
    server_id: Option<&'a [u8]>,
    /// The value of the first IA_NA option.
    ia_na: Option<&'a [u8]>,
}

/// Iterates over the options in `rest`, yielding an error for a truncated
/// option.
fn options(mut rest: &[u8]) -> impl Iterator<Item = Result<(u16, &[u8]), ServiceError>> {
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let Some(([c0, c1, l0, l1], after)) = rest.split_first_chunk::<4>().map(|(h, a)| (*h, a))
        else {
            rest = &[];
            return Some(Err(ServiceError::Malformed));
        };
        let len = u16::from_be_bytes([l0, l1]) as usize;
        let Some(value) = after.get(..len) else {
            rest = &[];
            return Some(Err(ServiceError::Malformed));
        };
        rest = &after[len..];
        Some(Ok((u16::from_be_bytes([c0, c1]), value)))
    })
}

fn parse(msg: &[u8]) -> Result<Request<'_>, ServiceError> {
    let (header, rest) = msg
        .split_first_chunk::<4>()
        .ok_or(ServiceError::Malformed)?;
    let [msg_type, t0, t1, t2] = *header;
    let mut req = Request {
        msg_type,
        transaction_id: [t0, t1, t2],
        client_id: None,
        server_id: None,
        ia_na: None,
    };
    for option in options(rest) {
        let (code, value) = option?;
        match code {
            OPTION_CLIENT_ID => req.client_id = Some(value),
            OPTION_SERVER_ID => req.server_id = Some(value),
            OPTION_IA_NA if req.ia_na.is_none() => {
                if value.len() < IA_NA_HEADER_LEN {
                    return Err(ServiceError::Malformed);
                }
                req.ia_na = Some(value);
            }
            _ => {}
        }
    }
    Ok(req)
}

/// Returns whether every address in the IA_NA is `assigned`, or `None` if it
/// holds no address.
fn ia_na_matches(ia_na: &[u8], assigned: Ipv6Address) -> Result<Option<bool>, ServiceError> {
    let mut any = false;
    for option in options(&ia_na[IA_NA_HEADER_LEN..]) {
        let (code, value) = option?;
        if code == OPTION_IAADDR {
            let addr = value.first_chunk::<16>().ok_or(ServiceError::Malformed)?;
            if Ipv6Address::from_octets(*addr) != assigned {
                return Ok(Some(false));
            }
            any = true;
        }
    }
    Ok(any.then_some(true))
}

fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}

/// What the reply to a message carries.
enum Answer {
    /// Only configuration, such as DNS servers.
    Information,
    /// A lease of the assigned address in an IA_NA with this IAID.
    Lease([u8; 4]),
    /// The result of confirming the guest's addresses.
    Status(u16),
}

pub(crate) fn handle_dhcpv6(
    cfg: &GatewayConfig,
    payload: &[u8],
    client_ip: Ipv6Address,
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    let req = parse(payload)?;
    // DUID-LL: type 3, hardware type 1 (Ethernet), gateway MAC.
    let mut duid = vec![0x00, 0x03, 0x00, 0x01];
    duid.extend_from_slice(&cfg.gateway_mac.0);
    let for_us = req.server_id.is_none_or(|id| id == duid.as_slice());
    let iaid = req.ia_na.map(|ia| {
        let mut iaid = [0; 4];
        iaid.copy_from_slice(&ia[..4]);
        iaid
    });

    // Messages that need an address are ignored without one, as are
    // messages meant for another server (RFC 8415 section 16).
    let (msg_type, answer) = match req.msg_type {
        MSG_INFORMATION_REQUEST if for_us => (MSG_REPLY, Answer::Information),
        MSG_SOLICIT | MSG_REBIND | MSG_CONFIRM if req.server_id.is_some() => return Ok(()),
        MSG_REQUEST | MSG_RENEW if req.server_id.is_none() || !for_us => return Ok(()),
        MSG_SOLICIT | MSG_REQUEST | MSG_RENEW | MSG_REBIND => {
            let (Some(_), Some(iaid)) = (cfg.assigned_ipv6, iaid) else {
                return Ok(());
            };
            let msg_type = if req.msg_type == MSG_SOLICIT {
                MSG_ADVERTISE
            } else {
                MSG_REPLY
            };
            (msg_type, Answer::Lease(iaid))
        }
        MSG_CONFIRM => {
            let (Some(assigned), Some(ia_na)) = (cfg.assigned_ipv6, req.ia_na) else {
                return Ok(());
            };
            // A Confirm without addresses gets no reply.
            let status = match ia_na_matches(ia_na, assigned)? {
                None => return Ok(()),
                Some(true) => STATUS_SUCCESS,
                Some(false) => STATUS_NOT_ON_LINK,
            };
            (MSG_REPLY, Answer::Status(status))
        }
        MSG_INFORMATION_REQUEST => return Ok(()),
        ty => return Err(ServiceError::UnsupportedDhcpv6(ty)),
    };
    if !matches!(answer, Answer::Information) && req.client_id.is_none() {
        return Err(ServiceError::Malformed);
    }

    let mut reply = vec![msg_type];
    reply.extend_from_slice(&req.transaction_id);
    if let Some(client_id) = req.client_id {
        push_option(&mut reply, OPTION_CLIENT_ID, client_id);
    }
    push_option(&mut reply, OPTION_SERVER_ID, &duid);
    match answer {
        Answer::Information => {}
        Answer::Lease(iaid) => {
            let assigned = cfg.assigned_ipv6.expect("checked above");
            let mut iaaddr = assigned.octets().to_vec();
            iaaddr.extend_from_slice(&INFINITY.to_be_bytes());
            iaaddr.extend_from_slice(&INFINITY.to_be_bytes());
            let mut ia_na = iaid.to_vec();
            ia_na.extend_from_slice(&INFINITY.to_be_bytes());
            ia_na.extend_from_slice(&INFINITY.to_be_bytes());
            push_option(&mut ia_na, OPTION_IAADDR, &iaaddr);
            push_option(&mut reply, OPTION_IA_NA, &ia_na);
        }
        Answer::Status(code) => push_option(&mut reply, OPTION_STATUS_CODE, &code.to_be_bytes()),
    }
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
        src_addr: cfg.gateway_mac,
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
    sink.recv(&buffer[..len], &ChecksumState::NONE);
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

    const CLIENT_DUID: &[u8] = &[0, 3, 0, 1, 0, 0x15, 0x5d, 1, 2, 3];
    const IAID: [u8; 4] = [0, 0, 0, 7];

    fn assigned() -> Ipv6Address {
        Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x123)
    }

    fn config() -> GatewayConfig {
        GatewayConfig {
            mtu: 1500,
            gateway_mac: smoltcp::wire::EthernetAddress([0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55]),
            gateway_ip: smoltcp::wire::Ipv4Address::new(10, 0, 0, 1),
            client_mac: smoltcp::wire::EthernetAddress([0, 0x15, 0x5d, 1, 2, 3]),
            client_ip: smoltcp::wire::Ipv4Address::new(10, 0, 0, 2),
            net_mask: smoltcp::wire::Ipv4Address::new(255, 255, 255, 0),
            gateway_link_local_ipv6: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            assigned_ipv6: Some(assigned()),
            client_ip_ipv6: None,
            client_ip_ipv6_routable: None,
            nameservers: Vec::new(),
            internal_dns: false,
        }
    }

    #[derive(Default)]
    struct Capture(Vec<Vec<u8>>);

    impl FrameSink for Capture {
        fn recv(&mut self, data: &[u8], _: &ChecksumState) {
            self.0.push(data.to_vec());
        }

        fn rx_mtu(&mut self) -> usize {
            MIN_MTU
        }
    }

    fn message(msg_type: u8, options: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut msg = vec![msg_type, 1, 2, 3];
        for (code, value) in options {
            push_option(&mut msg, *code, value);
        }
        msg
    }

    fn ia_na(addrs: &[Ipv6Address]) -> Vec<u8> {
        let mut ia = IAID.to_vec();
        ia.extend_from_slice(&[0; 8]);
        for addr in addrs {
            let mut iaaddr = addr.octets().to_vec();
            iaaddr.extend_from_slice(&[0; 8]);
            push_option(&mut ia, OPTION_IAADDR, &iaaddr);
        }
        ia
    }

    /// Returns the reply's message type and options, if there is a reply.
    fn exchange(cfg: &GatewayConfig, msg: &[u8]) -> Option<(u8, Vec<(u16, Vec<u8>)>)> {
        let mut sink = Capture::default();
        let client = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        handle_dhcpv6(cfg, msg, client, &mut sink).unwrap();
        let frame = sink.0.pop()?;
        let eth = EthernetFrame::new_checked(&frame[..]).unwrap();
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        let (&[msg_type, ..], rest) = udp.payload().split_at(4) else {
            panic!("short reply");
        };
        assert_eq!(&udp.payload()[1..4], &msg[1..4], "transaction id");
        let options = options(rest)
            .map(|o| o.map(|(c, v)| (c, v.to_vec())))
            .collect::<Result<_, _>>()
            .unwrap();
        Some((msg_type, options))
    }

    fn option(options: &[(u16, Vec<u8>)], code: u16) -> Option<&[u8]> {
        options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| &v[..])
    }

    #[test]
    fn solicit_and_request_lease_the_assigned_address() {
        let cfg = config();
        let solicit = message(
            MSG_SOLICIT,
            &[
                (OPTION_CLIENT_ID, CLIENT_DUID.to_vec()),
                (OPTION_IA_NA, ia_na(&[])),
            ],
        );
        let (msg_type, options) = exchange(&cfg, &solicit).unwrap();
        assert_eq!(msg_type, MSG_ADVERTISE);
        assert_eq!(option(&options, OPTION_CLIENT_ID), Some(CLIENT_DUID));
        let ia = option(&options, OPTION_IA_NA).unwrap();
        assert_eq!(ia[..4], IAID);
        assert_eq!(ia[4..12], [0xff; 8], "infinite T1 and T2");
        let (code, iaaddr) = super::options(&ia[IA_NA_HEADER_LEN..])
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(code, OPTION_IAADDR);
        assert_eq!(iaaddr[..16], assigned().octets());
        assert_eq!(iaaddr[16..24], [0xff; 8], "infinite lifetimes");

        let server_id = option(&options, OPTION_SERVER_ID).unwrap().to_vec();
        let request = |server_id: Vec<u8>| {
            message(
                MSG_REQUEST,
                &[
                    (OPTION_CLIENT_ID, CLIENT_DUID.to_vec()),
                    (OPTION_SERVER_ID, server_id),
                    (OPTION_IA_NA, ia_na(&[assigned()])),
                ],
            )
        };
        let (msg_type, options) = exchange(&cfg, &request(server_id)).unwrap();
        assert_eq!(msg_type, MSG_REPLY);
        assert!(option(&options, OPTION_IA_NA).is_some());
        // A request for another server is ignored.
        assert!(exchange(&cfg, &request(vec![0, 3, 0, 1, 1, 2, 3, 4, 5, 6])).is_none());
    }

    #[test]
    fn confirm_reports_whether_addresses_are_on_link() {
        let cfg = config();
        let confirm = |addrs: &[Ipv6Address]| {
            message(
                MSG_CONFIRM,
                &[
                    (OPTION_CLIENT_ID, CLIENT_DUID.to_vec()),
                    (OPTION_IA_NA, ia_na(addrs)),
                ],
            )
        };
        let status = |addrs: &[Ipv6Address]| {
            let (msg_type, options) = exchange(&cfg, &confirm(addrs))?;
            assert_eq!(msg_type, MSG_REPLY);
            Some(option(&options, OPTION_STATUS_CODE).unwrap().to_vec())
        };
        assert_eq!(
            status(&[assigned()]),
            Some(STATUS_SUCCESS.to_be_bytes().to_vec())
        );
        let other = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            status(&[other]),
            Some(STATUS_NOT_ON_LINK.to_be_bytes().to_vec())
        );
        assert_eq!(status(&[]), None);
    }

    #[test]
    fn without_an_address_only_information_requests_are_answered() {
        let mut cfg = config();
        cfg.assigned_ipv6 = None;
        let solicit = message(
            MSG_SOLICIT,
            &[
                (OPTION_CLIENT_ID, CLIENT_DUID.to_vec()),
                (OPTION_IA_NA, ia_na(&[])),
            ],
        );
        assert!(exchange(&cfg, &solicit).is_none());
        let info = message(MSG_INFORMATION_REQUEST, &[]);
        assert_eq!(exchange(&cfg, &info).unwrap().0, MSG_REPLY);
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
