// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Neighbor Discovery (RFC 4861).
//!
//! As in passt, Router Solicitations are answered, when the guest has an
//! assigned IPv6 address, with a Router Advertisement that directs the guest
//! to DHCPv6 for that address and advertises its /64 prefix as on-link and
//! for SLAAC (RFC 4862), with RDNSS (RFC 8106). Neighbor Solicitations for
//! any address other than the guest's are answered with the gateway's MAC.
//! The guest's addresses are learned from its Duplicate Address Detection
//! probes.

use super::ChecksumState;
use super::FrameSink;
use super::GatewayConfig;
use super::MIN_MTU;
use super::ServiceError;
use smoltcp::phy::Medium;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::Icmpv6Packet;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::Ipv6Repr;
use smoltcp::wire::NdiscNeighborFlags;
use smoltcp::wire::NdiscPrefixInfoFlags;
use smoltcp::wire::NdiscPrefixInformation;
use smoltcp::wire::NdiscRepr;
use smoltcp::wire::NdiscRouterFlags;
use smoltcp::wire::RawHardwareAddress;

/// Length of the advertised prefix of the assigned address.
const PREFIX_LEN: u8 = 64;
/// Infinite prefix lifetime (RFC 4861 section 4.6.2).
const INFINITE_LIFETIME: smoltcp::time::Duration =
    smoltcp::time::Duration::from_secs(u32::MAX as u64);
const LINK_LOCAL_ALL_NODES: Ipv6Address =
    Ipv6Address::from_octets([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const NDP_OPTION_RDNSS: u8 = 25;
const RDNSS_LIFETIME_SECS: u32 = 3600;
/// RDNSS servers that fit in one minimum-MTU Router Advertisement.
const MAX_RDNSS_SERVERS: usize = 8;

pub(crate) fn handle_ndp(
    cfg: &mut GatewayConfig,
    frame: &EthernetRepr,
    payload: &[u8],
    ipv6_src: Ipv6Address,
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    let icmp = Icmpv6Packet::new_checked(payload)?;
    match NdiscRepr::parse(&icmp)? {
        NdiscRepr::RouterSolicit { lladdr } => router_solicit(cfg, frame, ipv6_src, lladdr, sink),
        NdiscRepr::NeighborSolicit {
            target_addr,
            lladdr,
        } => neighbor_solicit(cfg, frame, ipv6_src, target_addr, lladdr, sink),
        NdiscRepr::NeighborAdvert { .. }
        | NdiscRepr::RouterAdvert { .. }
        | NdiscRepr::Redirect { .. } => Ok(()),
    }
}

fn lladdr_is_client(cfg: &GatewayConfig, lladdr: RawHardwareAddress) -> bool {
    matches!(
        lladdr.parse(Medium::Ethernet),
        Ok(HardwareAddress::Ethernet(mac)) if mac == cfg.client_mac
    )
}

fn router_solicit(
    cfg: &GatewayConfig,
    frame: &EthernetRepr,
    ipv6_src: Ipv6Address,
    lladdr: Option<RawHardwareAddress>,
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    // RFC 4861 section 6.1.1.
    if ipv6_src.is_unspecified() && lladdr.is_some() {
        return Err(ServiceError::Malformed);
    }
    if lladdr.is_some_and(|l| !lladdr_is_client(cfg, l)) {
        return Ok(());
    }
    // Without an address to assign, the guest has no IPv6 router.
    let Some(assigned) = cfg.assigned_ipv6 else {
        return Ok(());
    };
    // RFC 4861 section 6.2.6: unicast when the solicitation carries a source
    // link-layer address, otherwise multicast to all nodes.
    let (dst, eth_dst) = if lladdr.is_some() && !ipv6_src.is_unspecified() {
        (ipv6_src, frame.src_addr)
    } else {
        let o = LINK_LOCAL_ALL_NODES.octets();
        (
            LINK_LOCAL_ALL_NODES,
            EthernetAddress([0x33, 0x33, o[12], o[13], o[14], o[15]]),
        )
    };

    let prefix_info = Some(NdiscPrefixInformation {
        prefix_len: PREFIX_LEN,
        prefix: mask_prefix(assigned, PREFIX_LEN),
        valid_lifetime: INFINITE_LIFETIME,
        preferred_lifetime: INFINITE_LIFETIME,
        flags: NdiscPrefixInfoFlags::ON_LINK | NdiscPrefixInfoFlags::ADDRCONF,
    });
    let ndp = NdiscRepr::RouterAdvert {
        hop_limit: 255,
        // The assigned address itself comes from DHCPv6.
        flags: NdiscRouterFlags::MANAGED,
        router_lifetime: smoltcp::time::Duration::from_secs(9000),
        reachable_time: smoltcp::time::Duration::from_millis(30_000),
        retrans_time: smoltcp::time::Duration::from_millis(1000),
        lladdr: Some(RawHardwareAddress::from(cfg.gateway_mac)),
        mtu: Some(u32::from(cfg.mtu)),
        prefix_info,
    };
    let dns: Vec<Ipv6Address> = cfg
        .filtered_ipv6_nameservers()
        .take(MAX_RDNSS_SERVERS)
        .collect();
    let rdnss_len = if dns.is_empty() {
        0
    } else {
        8 + 16 * dns.len()
    };
    let icmp_len = ndp.buffer_len() + rdnss_len;

    let ipv6 = Ipv6Repr {
        src_addr: cfg.gateway_link_local_ipv6,
        dst_addr: dst,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp_len,
        hop_limit: 255,
    };
    let eth = EthernetRepr {
        src_addr: cfg.gateway_mac,
        dst_addr: eth_dst,
        ethertype: EthernetProtocol::Ipv6,
    };
    let mut buffer = [0; MIN_MTU];
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth.emit(&mut eth_frame);
    let mut ipv6_packet = Ipv6Packet::new_unchecked(eth_frame.payload_mut());
    ipv6.emit(&mut ipv6_packet);
    let icmp_buf = &mut ipv6_packet.payload_mut()[..icmp_len];
    ndp.emit(&mut Icmpv6Packet::new_unchecked(&mut *icmp_buf));
    if !dns.is_empty() {
        let opt = &mut icmp_buf[ndp.buffer_len()..];
        opt[0] = NDP_OPTION_RDNSS;
        opt[1] = (1 + 2 * dns.len()) as u8;
        opt[2..4].fill(0);
        opt[4..8].copy_from_slice(&RDNSS_LIFETIME_SECS.to_be_bytes());
        for (chunk, server) in opt[8..].chunks_exact_mut(16).zip(&dns) {
            chunk.copy_from_slice(&server.octets());
        }
    }
    Icmpv6Packet::new_unchecked(icmp_buf).fill_checksum(&ipv6.src_addr, &ipv6.dst_addr);

    let len = eth.buffer_len() + ipv6.buffer_len() + icmp_len;
    sink.recv(&buffer[..len], &ChecksumState::NONE);
    Ok(())
}

fn neighbor_solicit(
    cfg: &mut GatewayConfig,
    frame: &EthernetRepr,
    ipv6_src: Ipv6Address,
    target: Ipv6Address,
    lladdr: Option<RawHardwareAddress>,
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    // RFC 4861 section 7.1.1.
    if ipv6_src.is_unspecified() && lladdr.is_some() {
        return Err(ServiceError::Malformed);
    }
    // Duplicate Address Detection (RFC 4862 section 5.4.3). The gateway is the
    // only other node on the link, so DAD always succeeds; learn the address.
    if ipv6_src.is_unspecified() {
        if target.is_unicast_link_local() {
            cfg.client_ip_ipv6 = Some(target);
        } else {
            cfg.client_ip_ipv6_routable = Some(target);
        }
        return Ok(());
    }
    if lladdr.is_some_and(|l| !lladdr_is_client(cfg, l)) {
        return Ok(());
    }
    // Every other node appears to be on the link, behind the gateway's MAC.
    // Don't claim the guest's own addresses.
    let target_is_client = target == ipv6_src
        || cfg.client_ip_ipv6 == Some(target)
        || cfg.client_ip_ipv6_routable == Some(target)
        || cfg.assigned_ipv6 == Some(target);
    if target_is_client || target.is_multicast() || target.is_unspecified() {
        return Ok(());
    }

    let ndp = NdiscRepr::NeighborAdvert {
        flags: NdiscNeighborFlags::OVERRIDE
            | NdiscNeighborFlags::SOLICITED
            | NdiscNeighborFlags::ROUTER,
        target_addr: target,
        lladdr: Some(RawHardwareAddress::from(cfg.gateway_mac)),
    };
    let ipv6 = Ipv6Repr {
        src_addr: target,
        dst_addr: ipv6_src,
        next_header: IpProtocol::Icmpv6,
        payload_len: ndp.buffer_len(),
        hop_limit: 255,
    };
    let eth = EthernetRepr {
        src_addr: cfg.gateway_mac,
        dst_addr: frame.src_addr,
        ethertype: EthernetProtocol::Ipv6,
    };
    let mut buffer = [0; MIN_MTU];
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth.emit(&mut eth_frame);
    let mut ipv6_packet = Ipv6Packet::new_unchecked(eth_frame.payload_mut());
    ipv6.emit(&mut ipv6_packet);
    let mut icmp = Icmpv6Packet::new_unchecked(ipv6_packet.payload_mut());
    ndp.emit(&mut icmp);
    icmp.fill_checksum(&ipv6.src_addr, &ipv6.dst_addr);
    let len = eth.buffer_len() + ipv6.buffer_len() + ndp.buffer_len();
    sink.recv(&buffer[..len], &ChecksumState::NONE);
    Ok(())
}

fn mask_prefix(addr: Ipv6Address, prefix_len: u8) -> Ipv6Address {
    let bits = u128::from_be_bytes(addr.octets());
    let mask = (!0u128)
        .checked_shl(128 - u32::from(prefix_len.min(128)))
        .unwrap_or(0);
    Ipv6Address::from_octets((bits & mask).to_be_bytes())
}
