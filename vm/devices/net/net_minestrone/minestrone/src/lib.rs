// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minestrone: a passt-style user-mode network stack.
//!
//! Like Consomme, Minestrone gives a guest network access by translating its
//! Ethernet frames to ordinary host sockets. Unlike Consomme, it does not run
//! a TCP endpoint of its own. It *translates* TCP: sequence numbers,
//! acknowledgments, and windows are mirrored between the guest's TCP and the
//! host kernel's TCP, and data stays in the host kernel's socket buffers
//! rather than in per-connection buffers here. See the `tcp` module.
//!
//! ARP, DHCPv4, DHCPv6, and NDP are answered by the `services` module. As in
//! passt, by default they give the guest the addresses and default gateways
//! of the host. There is no internal DNS resolver: the guest is handed the
//! host's nameservers. ICMP is not translated.

mod frame;
mod host;
mod services;
mod sys;
mod tcp;
#[cfg(test)]
mod tests;
mod udp;

pub use net_usermode::ChecksumState;
pub use net_usermode::Client;
pub use net_usermode::FrameSink;
pub use net_usermode::addr::InvalidCidr;
pub use services::GatewayConfig;

use net_usermode::addr::Ipv4Network;
use net_usermode::addr::is_host_local_ipv4;
use net_usermode::addr::is_host_local_ipv6;
use net_usermode::dns;
use pal_async::timer::Instant;
use pal_async::timer::PolledTimer;
use services::Disposition;
use services::GatewayServices;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::ETHERNET_HEADER_LEN;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::IPV4_HEADER_LEN;
use smoltcp::wire::IPV6_HEADER_LEN;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv6Address;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::TcpPacket;
use smoltcp::wire::TcpRepr;
use smoltcp::wire::UdpPacket;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::task::Context;
use std::time::Duration;
use thiserror::Error;

/// Size of the buffer that host data is peeked or received into.
const SCRATCH_LEN: usize = 256 * 1024;

/// The transport protocol of a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// Limits on simultaneously active guest flows. `None` means unbounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowLimits {
    /// Maximum active TCP flows, including connecting flows.
    pub tcp: Option<usize>,
    /// Maximum active UDP flows.
    pub udp: Option<usize>,
}

impl FlowLimits {
    /// No limits. Only appropriate for a trusted guest.
    pub const UNBOUNDED: Self = Self {
        tcp: None,
        udp: None,
    };
}

impl Default for FlowLimits {
    fn default() -> Self {
        Self {
            tcp: Some(128),
            udp: Some(256),
        }
    }
}

/// Configuration of a Minestrone instance.
#[derive(Debug, Clone)]
pub struct MinestroneParams {
    /// Addressing of the virtual link.
    pub gateway: GatewayConfig,
    /// Limits on simultaneously active guest flows.
    pub flow_limits: FlowLimits,
    /// If true, allow guest traffic to host-local addresses (loopback,
    /// unspecified, link-local). Traffic to the gateway address is then sent
    /// to the host's loopback address.
    pub allow_host_local_access: bool,
    /// The IPv4 gateway is the host's own default gateway rather than a
    /// virtual address, so guest traffic to it is translated like traffic to
    /// any other address unless `allow_host_local_access` is set.
    pub host_ipv4_gateway: bool,
    /// IPv6 default gateway mirrored from the host, when available.
    pub host_ipv6_gateway: Option<Ipv6Addr>,
    /// Host interface scope for link-local IPv6 resolvers.
    pub host_ipv6_interface_index: u32,
    /// Optional alias for reaching `gateway.client_ip` on the host.
    /// Disabled by default, like passt's --map-guest-addr.
    pub map_guest_addr4: Option<Ipv4Addr>,
    /// IPv6 counterpart of `map_guest_addr4`, for `gateway.assigned_ipv6`.
    pub map_guest_addr6: Option<Ipv6Addr>,
    /// DNS-only address translations: (advertised address, host resolver).
    /// These take precedence over gateway-to-loopback translation on port 53.
    pub dns_mappings: Vec<(IpAddr, IpAddr)>,
    /// Idle timeout for UDP flows.
    pub udp_timeout: Duration,
}

/// The gateway's MAC address, as in passt.
const GATEWAY_MAC: EthernetAddress = EthernetAddress([0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55]);
/// The guest's IPv4 address when the host has no usable IPv4 configuration.
const LOCAL_CLIENT_IP: Ipv4Address = Ipv4Address::new(169, 254, 2, 1);
/// The IPv4 gateway when the host has no usable IPv4 configuration.
const LOCAL_GATEWAY_IP: Ipv4Address = Ipv4Address::new(169, 254, 2, 2);
const LOCAL_PREFIX_LEN: u8 = 16;
/// The IPv6 gateway when the host has no usable IPv6 configuration.
const LOCAL_GATEWAY_IPV6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

impl MinestroneParams {
    /// Returns a configuration that mirrors the host, as passt does. For each
    /// IP version, the guest is given the address of the host interface with
    /// the first default route, and that route's gateway. The IPv6 address is
    /// assigned with DHCPv6. The guest uses the host's nameservers.
    ///
    /// With no default route, the first interface with a non-link-local route
    /// is used instead. Without a usable interface address, or on hosts other
    /// than Linux, that IP version falls back to
    /// [`local`](Self::local) addressing.
    pub fn new() -> Self {
        let mut params = Self::local();
        if let Some(v4) = host::ipv4() {
            params.gateway.client_ip = v4.addr;
            params.gateway.net_mask = Ipv4Address::from_bits(prefix_mask(v4.prefix_len));
            params.gateway.gateway_ip = v4.gateway;
            params.host_ipv4_gateway = true;
        }
        if let Some(v6) = host::ipv6() {
            params.gateway.assigned_ipv6 = Some(v6.addr);
            params.gateway.gateway_link_local_ipv6 = v6.gateway_link_local;
            params.host_ipv6_gateway = (!v6.gateway.is_unspecified()).then_some(v6.gateway);
            params.host_ipv6_interface_index = v6.interface_index;
        }
        params.configure_dns(host_nameservers());
        params
    }

    /// Returns a configuration for a host without connectivity, as passt
    /// uses: the guest is 169.254.2.1/16 with gateway 169.254.2.2, and has
    /// only its link-local IPv6 address, with router fe80::1. The guest uses
    /// the host's nameservers.
    pub fn local() -> Self {
        let mut params = Self {
            gateway: GatewayConfig {
                mtu: 1500,
                gateway_mac: GATEWAY_MAC,
                gateway_ip: LOCAL_GATEWAY_IP,
                client_mac: EthernetAddress([0, 0, 0, 0, 1, 0]),
                client_ip: LOCAL_CLIENT_IP,
                net_mask: Ipv4Address::from_bits(prefix_mask(LOCAL_PREFIX_LEN)),
                gateway_link_local_ipv6: LOCAL_GATEWAY_IPV6,
                assigned_ipv6: None,
                client_ip_ipv6: None,
                client_ip_ipv6_routable: None,
                nameservers: Vec::new(),
                internal_dns: false,
            },
            flow_limits: FlowLimits::default(),
            allow_host_local_access: true,
            host_ipv4_gateway: false,
            host_ipv6_gateway: Some(LOCAL_GATEWAY_IPV6),
            host_ipv6_interface_index: 0,
            map_guest_addr4: None,
            map_guest_addr6: None,
            dns_mappings: Vec::new(),
            udp_timeout: Duration::from_secs(300),
        };
        params.configure_dns(host_nameservers());
        params
    }

    /// Places the guest on a private IPv4 network instead. For
    /// `192.168.0.0/24`, the gateway becomes 192.168.0.1 and the guest
    /// 192.168.0.2. IPv6 is unchanged.
    pub fn set_cidr(&mut self, cidr: &str) -> Result<(), InvalidCidr> {
        let network = Ipv4Network::parse(cidr)?;
        self.gateway.gateway_ip = network.gateway;
        self.gateway.client_ip = network.client;
        self.gateway.net_mask = network.net_mask;
        self.host_ipv4_gateway = false;
        // Recompute DNS aliases for the new virtual gateway.
        self.configure_dns(host_nameservers());
        Ok(())
    }

    fn configure_dns(&mut self, nameservers: Vec<IpAddress>) {
        self.dns_mappings.clear();
        let first_v4 = nameservers.iter().find_map(|server| match server {
            IpAddress::Ipv4(addr) => Some(IpAddr::V4(*addr)),
            _ => None,
        });
        let first_v6 = nameservers.iter().find_map(|server| match server {
            IpAddress::Ipv6(addr) => Some(IpAddr::V6(*addr)),
            _ => None,
        });
        self.gateway.nameservers = nameservers
            .into_iter()
            .filter_map(|server| {
                let host: IpAddr = server.into();
                let gateway: IpAddr = match host {
                    IpAddr::V4(_) => self.gateway.gateway_ip.into(),
                    IpAddr::V6(_) => self.host_ipv6_gateway?.into(),
                };
                if self.allow_host_local_access && (host.is_loopback() || host == gateway) {
                    if gateway.is_unspecified() {
                        return None;
                    }
                    let resolver = if host.is_ipv4() { first_v4 } else { first_v6 }?;
                    if !self.dns_mappings.iter().any(|(alias, _)| *alias == gateway) {
                        self.dns_mappings.push((gateway, resolver));
                    }
                    Some(gateway.into())
                } else {
                    (!host.is_loopback()).then_some(server)
                }
            })
            .collect();
    }
}

/// Returns the IPv4 netmask with `prefix_len` leading ones.
fn prefix_mask(prefix_len: u8) -> u32 {
    (!0u32)
        .checked_shl(32 - u32::from(prefix_len.min(32)))
        .unwrap_or(0)
}

/// Reads the host's nameservers, as passt does from `/etc/resolv.conf`.
/// `configure_dns` makes host-local resolvers reachable from the guest.
fn host_nameservers() -> Vec<IpAddress> {
    dns::nameservers(dns::ScopedIpv6::Strip).unwrap_or_else(|err| {
        tracing::warn!(
            error = &err as &dyn std::error::Error,
            "failed to read host nameservers"
        );
        Vec::new()
    })
}

/// The reason a guest frame was dropped.
#[derive(Debug, Error)]
pub enum DropReason {
    /// The frame could not be parsed.
    #[error("packet parsing error")]
    Packet(#[from] smoltcp::wire::Error),
    /// The frame is malformed.
    #[error("malformed packet")]
    Malformed,
    /// A gateway service rejected the frame.
    #[error("gateway service error")]
    Service(#[from] services::ServiceError),
    /// The ethertype is not supported.
    #[error("unsupported ethertype {0}")]
    UnsupportedEthertype(EthernetProtocol),
    /// The IP protocol is not supported.
    #[error("unsupported ip protocol {0}")]
    UnsupportedIpProtocol(IpProtocol),
    /// A header checksum is invalid.
    #[error("checksum failure")]
    Checksum,
    /// IP fragments are not supported.
    #[error("fragmented packets are not supported")]
    FragmentedPacket,
    /// The destination may not be reached from the guest.
    #[error("destination address not allowed")]
    DestinationNotAllowed,
    /// The active-flow limit for the protocol was reached.
    #[error("{0:?} active-flow limit reached")]
    FlowLimit(FlowProtocol),
    /// A host socket operation failed.
    #[error("host socket error")]
    Io(#[source] std::io::Error),
}

/// A Minestrone instance.
pub struct Minestrone {
    params: MinestroneParams,
    services: GatewayServices,
    tcp: tcp::Tcp,
    udp: udp::Udp,
    timer: Option<PolledTimer>,
    scratch: Box<[u8]>,
}

impl Minestrone {
    /// Applies the frontend's negotiated IP MTU before queues start.
    pub fn set_mtu(&mut self, mtu: u16) {
        self.params.gateway.mtu = mtu;
    }
    /// Creates a new instance.
    pub fn new(params: MinestroneParams) -> Self {
        Self {
            tcp: tcp::Tcp::new(params.flow_limits.tcp),
            udp: udp::Udp::new(params.flow_limits.udp, params.udp_timeout),
            params,
            services: GatewayServices::new(),
            timer: None,
            scratch: vec![0; SCRATCH_LEN].into_boxed_slice(),
        }
    }

    /// Returns the current configuration.
    pub fn params(&self) -> &MinestroneParams {
        &self.params
    }

    /// Returns the number of active TCP and UDP flows.
    pub fn flow_counts(&self) -> (usize, usize) {
        (self.tcp.len(), self.udp.len())
    }

    /// Drops the timer, which is bound to the driver of the previous client.
    /// Call when the instance moves to a client with a different driver.
    pub fn reset_driver(&mut self) {
        self.timer = None;
    }

    /// Pairs the instance with a client for sending and polling.
    pub fn access<'a, T: Client>(&'a mut self, client: &'a mut T) -> Access<'a, T> {
        Access {
            inner: self,
            client,
        }
    }
}

/// A [`Minestrone`] instance paired with its [`Client`].
pub struct Access<'a, T> {
    inner: &'a mut Minestrone,
    client: &'a mut T,
}

/// The L3 view of a guest packet.
struct IpView<'a> {
    src: IpAddr,
    dst: IpAddr,
    protocol: IpProtocol,
    payload: &'a [u8],
}

impl<T: Client> Access<'_, T> {
    /// Polls host sockets and timers, delivering resulting frames to the
    /// client.
    pub fn poll(&mut self, cx: &mut Context<'_>) {
        let Minestrone {
            params,
            tcp,
            udp,
            timer,
            scratch,
            ..
        } = &mut *self.inner;
        let now = Instant::now();
        let cfg = &params.gateway;
        let tcp_next = tcp.poll(cx, cfg, self.client, scratch, now);
        let udp_next = udp.poll(cx, cfg, self.client, scratch, |src| {
            guest_visible(params, src)
        });
        let next = match (tcp_next, udp_next) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(deadline) = next {
            let timer = timer.get_or_insert_with(|| PolledTimer::new(self.client.driver()));
            if timer.poll_until(cx, deadline).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }

    /// Processes a frame sent by the guest.
    pub fn send(&mut self, frame: &[u8], checksum: &ChecksumState) -> Result<(), DropReason> {
        let mut pending = tcp::PendingWrites::default();
        let result = self.send_frame(frame, checksum, &mut pending);
        self.flush(pending);
        result
    }

    /// Processes a batch of frames sent by the guest, calling `on_drop` for
    /// each frame that is dropped.
    ///
    /// Guest data for each TCP flow is written to the host socket with one
    /// call per batch, so prefer this to [`Self::send`] when several frames
    /// are available.
    pub fn send_batch<'f>(
        &mut self,
        frames: impl IntoIterator<Item = (&'f [u8], ChecksumState)>,
        mut on_drop: impl FnMut(DropReason),
    ) {
        let mut pending = tcp::PendingWrites::default();
        for (frame, checksum) in frames {
            if let Err(err) = self.send_frame(frame, &checksum, &mut pending) {
                on_drop(err);
            }
        }
        self.flush(pending);
    }

    fn flush(&mut self, pending: tcp::PendingWrites<'_>) {
        let inner = &mut *self.inner;
        inner
            .tcp
            .flush(&inner.params.gateway, &mut *self.client, pending);
    }

    fn send_frame<'f>(
        &mut self,
        frame: &'f [u8],
        checksum: &ChecksumState,
        pending: &mut tcp::PendingWrites<'f>,
    ) -> Result<(), DropReason> {
        let eth = EthernetRepr::parse(&EthernetFrame::new_checked(frame)?)?;
        let payload = &frame[ETHERNET_HEADER_LEN..];
        match self.inner.services.handle_frame(
            &mut self.inner.params.gateway,
            &eth,
            payload,
            &mut *self.client,
        )? {
            Disposition::Handled => return Ok(()),
            Disposition::NotForGateway => {}
        }
        let ip = match eth.ethertype {
            EthernetProtocol::Ipv4 => parse_ipv4(payload, checksum)?,
            EthernetProtocol::Ipv6 => parse_ipv6(payload, checksum)?,
            other => return Err(DropReason::UnsupportedEthertype(other)),
        };
        match ip.protocol {
            IpProtocol::Tcp => self.handle_tcp(&ip, checksum, pending),
            IpProtocol::Udp => self.handle_udp(&ip, checksum),
            other => Err(DropReason::UnsupportedIpProtocol(other)),
        }
    }

    /// Maps a guest destination to the host address to connect to.
    fn host_destination(&self, dst: IpAddr) -> Result<IpAddr, DropReason> {
        let params = &self.inner.params;
        let cfg = &params.gateway;
        let allow = params.allow_host_local_access;
        if match dst {
            IpAddr::V4(addr) => params.map_guest_addr4 == Some(addr),
            IpAddr::V6(addr) => params.map_guest_addr6 == Some(addr),
        } {
            return match dst {
                IpAddr::V4(_) => Ok(cfg.client_ip.into()),
                IpAddr::V6(_) => cfg
                    .assigned_ipv6
                    .map(IpAddr::V6)
                    .ok_or(DropReason::DestinationNotAllowed),
            };
        }
        match dst {
            IpAddr::V4(v4)
                if !v4.is_unspecified()
                    && v4 == cfg.gateway_ip
                    && (allow || !params.host_ipv4_gateway) =>
            {
                if allow {
                    Ok(Ipv4Addr::LOCALHOST.into())
                } else {
                    Err(DropReason::DestinationNotAllowed)
                }
            }
            IpAddr::V6(v6)
                if v6 == cfg.gateway_link_local_ipv6 || Some(v6) == params.host_ipv6_gateway =>
            {
                if allow {
                    Ok(Ipv6Addr::LOCALHOST.into())
                } else {
                    Err(DropReason::DestinationNotAllowed)
                }
            }
            IpAddr::V4(v4)
                if v4.is_multicast() || v4.is_broadcast() || (!allow && is_host_local_ipv4(v4)) =>
            {
                Err(DropReason::DestinationNotAllowed)
            }
            // Link-local IPv6 needs a scope, which the guest's address can't
            // express on the host.
            IpAddr::V6(v6)
                if v6.is_multicast()
                    || v6.is_unicast_link_local()
                    || (!allow && is_host_local_ipv6(v6)) =>
            {
                Err(DropReason::DestinationNotAllowed)
            }
            other => Ok(other),
        }
    }

    fn host_destination_port(&self, dst: IpAddr, port: u16) -> Result<IpAddr, DropReason> {
        if port == services::DNS_PORT {
            if let Some((_, resolver)) = self
                .inner
                .params
                .dns_mappings
                .iter()
                .find(|(a, _)| *a == dst)
            {
                return Ok(*resolver);
            }
            if matches!(dst, IpAddr::V6(addr) if addr.is_unicast_link_local())
                && self.inner.params.gateway.nameservers.contains(&dst.into())
            {
                return Ok(dst);
            }
        }
        self.host_destination(dst)
    }

    fn host_socket_address(&self, dst: IpAddr, port: u16) -> Result<SocketAddr, DropReason> {
        let mut address = SocketAddr::new(self.host_destination_port(dst, port)?, port);
        if let SocketAddr::V6(ref mut v6) = address {
            if v6.ip().is_unicast_link_local() {
                let scope = self.inner.params.host_ipv6_interface_index;
                if scope == 0 {
                    return Err(DropReason::DestinationNotAllowed);
                }
                v6.set_scope_id(scope);
            }
        }
        Ok(address)
    }

    fn handle_tcp<'f>(
        &mut self,
        ip: &IpView<'f>,
        checksum: &ChecksumState,
        pending: &mut tcp::PendingWrites<'f>,
    ) -> Result<(), DropReason> {
        let packet = TcpPacket::new_checked(ip.payload)?;
        let (src, dst) = (IpAddress::from(ip.src), IpAddress::from(ip.dst));
        if !checksum.tcp && !packet.verify_checksum(&src, &dst) {
            return Err(DropReason::Checksum);
        }
        let repr = TcpRepr::parse(&packet, &src, &dst, &ChecksumCapabilities::ignored())?;
        let key = tcp::FlowKey {
            guest: SocketAddr::new(ip.src, repr.src_port),
            remote: SocketAddr::new(ip.dst, repr.dst_port),
        };
        let host_dst = self.host_socket_address(ip.dst, repr.dst_port)?;
        self.inner.tcp.handle(
            &self.inner.params.gateway,
            self.client,
            key,
            host_dst,
            &repr,
            pending,
        )
    }

    fn handle_udp(&mut self, ip: &IpView<'_>, checksum: &ChecksumState) -> Result<(), DropReason> {
        let packet = UdpPacket::new_checked(ip.payload)?;
        let (src, dst) = (IpAddress::from(ip.src), IpAddress::from(ip.dst));
        // A zero UDP checksum over IPv4 means none was computed.
        if !checksum.udp
            && !(ip.src.is_ipv4() && packet.checksum() == 0)
            && !packet.verify_checksum(&src, &dst)
        {
            return Err(DropReason::Checksum);
        }
        let guest = SocketAddr::new(ip.src, packet.src_port());
        let host_dst = self.host_socket_address(ip.dst, packet.dst_port())?;
        self.inner
            .udp
            .handle(self.client, guest, host_dst, packet.payload())
    }
}

/// Maps a host source address to the address the guest should see.
fn guest_visible(params: &MinestroneParams, src: SocketAddr) -> SocketAddr {
    let cfg = &params.gateway;
    if src.port() == services::DNS_PORT {
        if let Some((alias, _)) = params
            .dns_mappings
            .iter()
            .find(|(_, host)| *host == src.ip())
        {
            return SocketAddr::new(*alias, src.port());
        }
    }
    match src.ip() {
        IpAddr::V4(v4) if params.allow_host_local_access && v4 == Ipv4Addr::LOCALHOST => {
            SocketAddr::new(cfg.gateway_ip.into(), src.port())
        }
        IpAddr::V6(v6) if params.allow_host_local_access && v6 == Ipv6Addr::LOCALHOST => {
            SocketAddr::new(
                params
                    .host_ipv6_gateway
                    .unwrap_or(cfg.gateway_link_local_ipv6)
                    .into(),
                src.port(),
            )
        }
        IpAddr::V4(addr) if addr == cfg.client_ip => params
            .map_guest_addr4
            .map_or(src, |alias| SocketAddr::new(alias.into(), src.port())),
        IpAddr::V6(addr) if Some(addr) == cfg.assigned_ipv6 => params
            .map_guest_addr6
            .map_or(src, |alias| SocketAddr::new(alias.into(), src.port())),
        _ => src,
    }
}

fn parse_ipv4<'a>(payload: &'a [u8], checksum: &ChecksumState) -> Result<IpView<'a>, DropReason> {
    let ip = Ipv4Packet::new_unchecked(payload);
    if payload.len() < IPV4_HEADER_LEN || ip.version() != 4 {
        return Err(DropReason::Malformed);
    }
    let header_len = usize::from(ip.header_len());
    // With segmentation offload the total length may not describe the
    // buffer; use the buffer length instead.
    let total_len = if checksum.tso.is_some() || checksum.gso.is_some() {
        payload.len()
    } else {
        usize::from(ip.total_len())
    };
    if header_len < IPV4_HEADER_LEN || total_len < header_len || payload.len() < total_len {
        return Err(DropReason::Malformed);
    }
    if ip.more_frags() || ip.frag_offset() != 0 {
        return Err(DropReason::FragmentedPacket);
    }
    if !checksum.ipv4 && !ip.verify_checksum() {
        return Err(DropReason::Checksum);
    }
    Ok(IpView {
        src: IpAddr::V4(ip.src_addr()),
        dst: IpAddr::V4(ip.dst_addr()),
        protocol: ip.next_header(),
        payload: &payload[header_len..total_len],
    })
}

fn parse_ipv6<'a>(payload: &'a [u8], checksum: &ChecksumState) -> Result<IpView<'a>, DropReason> {
    let ip = Ipv6Packet::new_unchecked(payload);
    if payload.len() < IPV6_HEADER_LEN || ip.version() != 6 {
        return Err(DropReason::Malformed);
    }
    let total_len = if checksum.tso.is_some() || checksum.gso.is_some() {
        payload.len()
    } else {
        IPV6_HEADER_LEN + usize::from(ip.payload_len())
    };
    if payload.len() < total_len {
        return Err(DropReason::Malformed);
    }
    if ip.next_header() == IpProtocol::Ipv6Frag {
        return Err(DropReason::FragmentedPacket);
    }
    Ok(IpView {
        src: IpAddr::V6(ip.src_addr()),
        dst: IpAddr::V6(ip.dst_addr()),
        protocol: ip.next_header(),
        payload: &payload[IPV6_HEADER_LEN..total_len],
    })
}
