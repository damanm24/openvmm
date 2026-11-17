// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Construction of frames sent to the guest.

use crate::ChecksumState;
use crate::Client;
use crate::services::GatewayConfig;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::ETHERNET_HEADER_LEN;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::IPV4_HEADER_LEN;
use smoltcp::wire::IPV6_HEADER_LEN;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::IpRepr;
use smoltcp::wire::checksum;
use std::net::SocketAddr;

/// Largest TCP header (with options) emitted.
pub(crate) const MAX_TCP_HEADER_LEN: usize = 60;
/// Largest L2+L3 header emitted.
const MAX_L3_HEADER_LEN: usize = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN;

/// Returns the Ethernet plus IP header length for a flow's address family.
pub(crate) fn l3_header_len(addr: &SocketAddr) -> usize {
    ETHERNET_HEADER_LEN
        + match addr {
            SocketAddr::V4(_) => IPV4_HEADER_LEN,
            SocketAddr::V6(_) => IPV6_HEADER_LEN,
        }
}

/// Sends a TCP or UDP packet from `src` (the remote peer, as the guest sees
/// it) to `dst` (the guest).
///
/// `l4_header` is the transport header with a zero checksum field. The
/// checksum is filled in here: completely, or as the pseudo-header partial
/// sum when the client completes checksums or `tso` is set. `payload` follows
/// the header and may be split across segments.
pub(crate) fn send_l4<C: Client + ?Sized>(
    client: &mut C,
    cfg: &GatewayConfig,
    src: SocketAddr,
    dst: SocketAddr,
    protocol: IpProtocol,
    l4_header: &[u8],
    payload: &[&[u8]],
    tso: Option<u16>,
) {
    let payload_len: usize = payload.iter().map(|p| p.len()).sum();
    let l4_len = l4_header.len() + payload_len;
    let (src_ip, dst_ip): (IpAddress, IpAddress) = (src.ip().into(), dst.ip().into());
    let (eth_src, ethertype, base) = match dst {
        SocketAddr::V4(_) => (cfg.gateway_mac, EthernetProtocol::Ipv4, ChecksumState::TCP4),
        SocketAddr::V6(_) => (cfg.gateway_mac, EthernetProtocol::Ipv6, ChecksumState::TCP6),
    };
    let ip = IpRepr::new(src_ip, dst_ip, protocol, l4_len, 64);

    let mut buf = [0u8; MAX_L3_HEADER_LEN + MAX_TCP_HEADER_LEN];
    let mut eth = EthernetFrame::new_unchecked(&mut buf[..]);
    eth.set_dst_addr(cfg.client_mac);
    eth.set_src_addr(eth_src);
    eth.set_ethertype(ethertype);
    let l3_len = ETHERNET_HEADER_LEN + ip.header_len();
    ip.emit(
        &mut buf[ETHERNET_HEADER_LEN..l3_len],
        &ChecksumCapabilities::default(),
    );
    let header_len = l3_len + l4_header.len();
    buf[l3_len..header_len].copy_from_slice(l4_header);

    let (is_tcp, checksum_offset) = match protocol {
        IpProtocol::Tcp => (true, 16),
        _ => (false, 6),
    };
    let partial = tso.is_some() || client.rx_checksum_supported();
    let pseudo = checksum::pseudo_header(&src_ip, &dst_ip, protocol, l4_len as u32);
    let sum = if partial {
        pseudo
    } else {
        // Transport headers have even length, so only payload segments can
        // shift the 16-bit alignment of the data that follows them.
        let mut odd = false;
        let mut parts = Vec::with_capacity(payload.len() + 2);
        parts.push(pseudo);
        parts.push(checksum::data(l4_header));
        for p in payload {
            let s = checksum::data(p);
            parts.push(if odd { s.swap_bytes() } else { s });
            odd ^= p.len() % 2 == 1;
        }
        match !checksum::combine(&parts) {
            // RFC 768: a computed UDP checksum of zero is sent as all ones.
            0 if !is_tcp => 0xffff,
            s => s,
        }
    };
    buf[l3_len + checksum_offset..l3_len + checksum_offset + 2].copy_from_slice(&sum.to_be_bytes());

    let state = ChecksumState {
        tcp: is_tcp,
        udp: !is_tcp,
        partial,
        tso,
        ..base
    };
    match payload {
        [] => client.recv_segments(&[&buf[..header_len]], &state),
        [a] => client.recv_segments(&[&buf[..header_len], a], &state),
        [a, b] => client.recv_segments(&[&buf[..header_len], a, b], &state),
        _ => {
            let mut segments = vec![&buf[..header_len]];
            segments.extend_from_slice(payload);
            client.recv_segments(&segments, &state)
        }
    }
}
