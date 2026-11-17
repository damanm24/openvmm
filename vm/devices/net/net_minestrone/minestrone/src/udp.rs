// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! UDP translation.
//!
//! Each guest source address is bound to one host socket (an
//! endpoint-independent NAT binding, RFC 4787), which sends to whatever
//! destination the guest addresses and returns datagrams from any source.

use crate::Client;
use crate::DropReason;
use crate::FlowProtocol;
use crate::frame;
use crate::services::GatewayConfig;
use pal_async::interest::InterestSlot;
use pal_async::interest::PollEvents;
use pal_async::socket::PolledSocket;
use pal_async::timer::Instant;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::UDP_HEADER_LEN;
use socket2::Domain;
use socket2::Protocol;
use socket2::Socket;
use socket2::Type;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

struct UdpFlow {
    socket: PolledSocket<UdpSocket>,
    idle_deadline: Instant,
}

pub(crate) struct Udp {
    flows: HashMap<SocketAddr, UdpFlow>,
    limit: Option<usize>,
    timeout: Duration,
}

impl Udp {
    pub fn new(limit: Option<usize>, timeout: Duration) -> Self {
        Self {
            flows: HashMap::new(),
            limit,
            timeout,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Sends a guest datagram from `guest` to `host_dst`.
    pub fn handle<C: Client + ?Sized>(
        &mut self,
        client: &C,
        guest: SocketAddr,
        host_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<(), DropReason> {
        let now = Instant::now();
        let active = self.flows.len();
        let flow = match self.flows.entry(guest) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                if self.limit.is_some_and(|max| active >= max) {
                    tracelimit::warn_ratelimited!(%guest, "udp active-flow limit reached");
                    return Err(DropReason::FlowLimit(FlowProtocol::Udp));
                }
                let (domain, bind): (Domain, SocketAddr) = match guest {
                    SocketAddr::V4(_) => (Domain::IPV4, (Ipv4Addr::UNSPECIFIED, 0).into()),
                    SocketAddr::V6(_) => (Domain::IPV6, (Ipv6Addr::UNSPECIFIED, 0).into()),
                };
                let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                    .map_err(DropReason::Io)?;
                if domain == Domain::IPV6 {
                    socket.set_only_v6(true).map_err(DropReason::Io)?;
                }
                socket.bind(&bind.into()).map_err(DropReason::Io)?;
                let socket = PolledSocket::new(client.driver(), UdpSocket::from(socket))
                    .map_err(DropReason::Io)?;
                e.insert(UdpFlow {
                    socket,
                    idle_deadline: now,
                })
            }
        };
        flow.idle_deadline = now.saturating_add(self.timeout);
        match flow.socket.get().send_to(payload, host_dst) {
            Ok(_) => Ok(()),
            // The host send buffer is full: drop, as a congested link would.
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(err) => Err(DropReason::Io(err)),
        }
    }

    /// Delivers received host datagrams to the guest and expires idle flows.
    /// Returns the earliest idle deadline.
    pub fn poll<C: Client + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        cfg: &GatewayConfig,
        client: &mut C,
        scratch: &mut [u8],
        guest_visible: impl Fn(SocketAddr) -> SocketAddr,
    ) -> Option<Instant> {
        let now = Instant::now();
        let mut next = None::<Instant>;
        self.flows.retain(|&guest, flow| {
            loop {
                let max = client.max_frame_len();
                let header = frame::l3_header_len(&guest) + UDP_HEADER_LEN;
                if max <= header {
                    break;
                }
                let (n, src) =
                    match flow
                        .socket
                        .poll_io(cx, InterestSlot::Read, PollEvents::IN, |s| {
                            s.get().recv_from(scratch)
                        }) {
                        Poll::Ready(Ok(r)) => r,
                        Poll::Ready(Err(err)) => {
                            // ICMP errors for earlier sends surface here; ignore.
                            tracing::trace!(
                                error = &err as &dyn std::error::Error,
                                "udp recv error"
                            );
                            continue;
                        }
                        Poll::Pending => break,
                    };
                if header + n > max || n > u16::MAX as usize - UDP_HEADER_LEN {
                    tracelimit::warn_ratelimited!(len = n, "dropping oversized udp datagram");
                    continue;
                }
                flow.idle_deadline = now.saturating_add(self.timeout);
                let src = guest_visible(src);
                let udp_len = (UDP_HEADER_LEN + n) as u16;
                let mut udp = [0u8; UDP_HEADER_LEN];
                udp[0..2].copy_from_slice(&src.port().to_be_bytes());
                udp[2..4].copy_from_slice(&guest.port().to_be_bytes());
                udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
                frame::send_l4(
                    client,
                    cfg,
                    src,
                    guest,
                    IpProtocol::Udp,
                    &udp,
                    &[&scratch[..n]],
                    None,
                );
            }
            if flow.idle_deadline <= now {
                return false;
            }
            next = Some(next.map_or(flow.idle_deadline, |n| n.min(flow.idle_deadline)));
            true
        });
        next
    }
}
