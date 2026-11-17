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
//! ARP, DHCPv4, DHCPv6, and NDP are answered by the `services` module. There
//! is no internal DNS resolver: the guest is handed the host's nameservers.
//! ICMP is not translated.

mod frame;
mod services;
mod sys;
mod tcp;
#[cfg(test)]
mod tests;
mod udp;

pub use services::ChecksumState;
pub use services::FrameSink;
pub use services::GatewayConfig;

use pal_async::driver::Driver;
use pal_async::timer::Instant;
use pal_async::timer::PolledTimer;
use services::Disposition;
use services::GatewayServices;
use smoltcp::phy::ChecksumCapabilities;
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
    /// Idle timeout for UDP flows.
    pub udp_timeout: Duration,
}

impl MinestroneParams {
    /// Returns the default NAT configuration: the gateway is 10.0.0.1, the
    /// guest is 10.0.0.2/24, IPv6 is configured by the guest with SLAAC, and
    /// the guest uses the host's nameservers.
    pub fn new() -> Self {
        let gateway_mac_ipv6 = EthernetAddress([0x52, 0x55, 10, 0, 1, 2]);
        Self {
            gateway: GatewayConfig {
                gateway_mac: EthernetAddress([0x52, 0x55, 10, 0, 0, 1]),
                gateway_ip: Ipv4Address::new(10, 0, 0, 1),
                client_mac: EthernetAddress([0, 0, 0, 0, 1, 0]),
                client_ip: Ipv4Address::new(10, 0, 0, 2),
                net_mask: Ipv4Address::new(255, 255, 255, 0),
                gateway_mac_ipv6,
                gateway_link_local_ipv6: services::link_local_from_mac(gateway_mac_ipv6),
                prefix_len_ipv6: 64,
                advertise_routable_ipv6: true,
                client_ip_ipv6: None,
                client_ip_ipv6_routable: None,
                nameservers: host_nameservers(),
                internal_dns: false,
            },
            flow_limits: FlowLimits::default(),
            allow_host_local_access: false,
            udp_timeout: Duration::from_secs(300),
        }
    }

    /// Sets the IPv4 network. For `192.168.0.0/24`, the gateway becomes
    /// 192.168.0.1 and the guest 192.168.0.2.
    pub fn set_cidr(&mut self, cidr: &str) -> Result<(), InvalidCidr> {
        let cidr: smoltcp::wire::Ipv4Cidr = cidr.parse().map_err(|()| InvalidCidr)?;
        if cidr.prefix_len() > 30 {
            return Err(InvalidCidr);
        }
        let base = cidr.network().address().to_bits();
        self.gateway.gateway_ip = Ipv4Address::from_bits(base + 1);
        self.gateway.client_ip = Ipv4Address::from_bits(base + 2);
        self.gateway.net_mask = cidr.netmask();
        Ok(())
    }
}

/// An error indicating that a CIDR is invalid or too small for a gateway and
/// a guest.
#[derive(Debug, Error)]
#[error("invalid CIDR")]
pub struct InvalidCidr;

/// Returns the host's nameservers that a guest can reach. Loopback servers
/// (such as systemd-resolved's stub) are skipped in favor of the upstream
/// servers they forward to.
fn host_nameservers() -> Vec<IpAddress> {
    #[cfg(unix)]
    {
        for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
            let Ok(contents) = std::fs::read(path) else {
                continue;
            };
            let Ok(config) = resolv_conf::Config::parse(contents) else {
                continue;
            };
            let servers: Vec<IpAddress> = config
                .nameservers
                .iter()
                .filter_map(|ns| match ns {
                    resolv_conf::ScopedIp::V4(a) if !a.is_loopback() => Some(IpAddress::Ipv4(*a)),
                    resolv_conf::ScopedIp::V6(a, None) if !a.is_loopback() => {
                        Some(IpAddress::Ipv6(*a))
                    }
                    _ => None,
                })
                .collect();
            if !servers.is_empty() {
                return servers;
            }
        }
        Vec::new()
    }
    #[cfg(not(unix))]
    Vec::new()
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

/// The guest-facing side of a Minestrone instance.
pub trait Client: FrameSink {
    /// Gets the driver used to poll host sockets and timers.
    fn driver(&self) -> &dyn Driver;

    /// Whether the client can complete partial TCP and UDP receive checksums.
    fn rx_checksum_supported(&self) -> bool {
        false
    }

    /// Whether the client can receive TCP GSO frames with partial checksums.
    fn rx_gso_supported(&self, _ipv6: bool) -> bool {
        false
    }
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
        let allow_local = params.allow_host_local_access;
        let udp_next = udp.poll(cx, cfg, self.client, scratch, |src| {
            guest_visible(cfg, allow_local, src)
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
        let frame = EthernetFrame::new_checked(frame)?;
        let eth = EthernetRepr::parse(&frame)?;
        let payload = frame.payload();
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
        let host_dst = self.host_destination(ip.dst)?;
        match ip.protocol {
            IpProtocol::Tcp => self.handle_tcp(&ip, host_dst, checksum),
            IpProtocol::Udp => self.handle_udp(&ip, host_dst, checksum),
            other => Err(DropReason::UnsupportedIpProtocol(other)),
        }
    }

    /// Maps a guest destination to the host address to connect to.
    fn host_destination(&self, dst: IpAddr) -> Result<IpAddr, DropReason> {
        let params = &self.inner.params;
        let cfg = &params.gateway;
        let allow = params.allow_host_local_access;
        match dst {
            IpAddr::V4(v4) if v4 == cfg.gateway_ip => {
                if allow {
                    Ok(Ipv4Addr::LOCALHOST.into())
                } else {
                    Err(DropReason::DestinationNotAllowed)
                }
            }
            IpAddr::V6(v6) if v6 == cfg.gateway_link_local_ipv6 => {
                if allow {
                    Ok(Ipv6Addr::LOCALHOST.into())
                } else {
                    Err(DropReason::DestinationNotAllowed)
                }
            }
            IpAddr::V4(v4)
                if v4.is_multicast()
                    || v4.is_broadcast()
                    || (!allow
                        && (v4.is_loopback() || v4.is_unspecified() || v4.is_link_local())) =>
            {
                Err(DropReason::DestinationNotAllowed)
            }
            // Link-local IPv6 needs a scope, which the guest's address can't
            // express on the host.
            IpAddr::V6(v6)
                if v6.is_multicast()
                    || v6.is_unicast_link_local()
                    || (!allow && (v6.is_loopback() || v6.is_unspecified())) =>
            {
                Err(DropReason::DestinationNotAllowed)
            }
            other => Ok(other),
        }
    }

    fn handle_tcp(
        &mut self,
        ip: &IpView<'_>,
        host_dst: IpAddr,
        checksum: &ChecksumState,
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
        self.inner.tcp.handle(
            &self.inner.params.gateway,
            self.client,
            key,
            SocketAddr::new(host_dst, repr.dst_port),
            &repr,
        )
    }

    fn handle_udp(
        &mut self,
        ip: &IpView<'_>,
        host_dst: IpAddr,
        checksum: &ChecksumState,
    ) -> Result<(), DropReason> {
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
        self.inner.udp.handle(
            self.client,
            guest,
            SocketAddr::new(host_dst, packet.dst_port()),
            packet.payload(),
        )
    }
}

/// Maps a host source address to the address the guest should see.
fn guest_visible(cfg: &GatewayConfig, allow_local: bool, src: SocketAddr) -> SocketAddr {
    match src.ip() {
        IpAddr::V4(v4) if allow_local && v4.is_loopback() => {
            SocketAddr::new(cfg.gateway_ip.into(), src.port())
        }
        IpAddr::V6(v6) if allow_local && v6.is_loopback() => {
            SocketAddr::new(cfg.gateway_link_local_ipv6.into(), src.port())
        }
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
