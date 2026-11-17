// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TCP translation between guest segments and host stream sockets.
//!
//! Each flow mirrors, rather than terminates, the connection:
//!
//! * Guest-to-host data is written directly to the host socket. Only bytes the
//!   socket accepts are acknowledged, and the advertised window is the free
//!   space in the socket's send buffer, less a margin for per-buffer
//!   overhead. A window too small to be useful is closed and reopened with an
//!   update once the socket drains. Out-of-order segments are dropped with
//!   a duplicate ACK; there is no reassembly. In-order data from a batch of
//!   guest frames is gathered per flow, without copying, and written with one
//!   vectored send. If the socket accepts only part of it, the rest is
//!   dropped and duplicate ACKs prompt the guest to retransmit it at once.
//! * Host-to-guest data is read only up to the guest's advertised window and
//!   kept until the guest acknowledges it, either in the kernel socket (Linux
//!   `SO_PEEK_OFF`) or in an [`unacked_ring::UnackedRing`].
//!   Retransmission rewinds to the oldest unacknowledged byte (go-back-N).
//!
//! Frames to the guest are only emitted from [`Tcp::poll`], once per batch of
//! guest frames, so the guest receives one ACK per batch rather than per
//! segment.

mod seq;
mod unacked_ring;

use crate::Client;
use crate::DropReason;
use crate::FlowProtocol;
use crate::frame;
use crate::services::GatewayConfig;
use crate::sys;
use pal_async::interest::InterestSlot;
use pal_async::interest::PollEvents;
use pal_async::socket::PollReady;
use pal_async::socket::PolledSocket;
use pal_async::timer::Instant;
use seq::Seq;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::TcpControl;
use smoltcp::wire::TcpPacket;
use smoltcp::wire::TcpRepr;
use smoltcp::wire::TcpSeqNumber;
use socket2::Domain;
use socket2::Protocol;
use socket2::SockAddr;
use socket2::Socket;
use socket2::Type;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::hash::RandomState;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use unacked_ring::UnackedRing;

/// Window scale advertised to guests that negotiate scaling (8 MiB window).
const OUR_WSCALE: u8 = 7;
/// RFC 6298 initial retransmission timeout.
const RTO_INIT: Duration = Duration::from_secs(1);
const RTO_MAX: Duration = Duration::from_secs(60);
const MAX_RETRIES: u8 = 8;
/// Advertised window where the send-buffer space cannot be queried.
const DEFAULT_SEND_SPACE: usize = 256 * 1024;
/// The advertised window withholds this fraction (1/N) of the free
/// send-buffer space to cover per-buffer overhead.
const SEND_SPACE_MARGIN_DIVISOR: usize = 16;
/// Send-buffer space required before reopening a closed window, to avoid
/// silly-window syndrome.
const REOPEN_SPACE: usize = 16 * 1024;
/// How often a closed window is checked for reopening when no writability
/// notification arrives.
const REOPEN_CHECK_INTERVAL: Duration = Duration::from_millis(1);
/// Ceiling for unacknowledged data held in a ring.
const RING_MAX: usize = 4 * 1024 * 1024;
const TCP_HEADER_LEN: usize = 20;
/// Largest GSO payload whose IPv4 total length fits in 16 bits.
const MAX_GSO_PAYLOAD: usize = 65535 - 20 - TCP_HEADER_LEN;
/// Duplicate ACKs that trigger the guest's fast retransmit (RFC 5681).
const DUP_ACK_THRESHOLD: usize = 3;
/// Buffers per vectored send, within Linux's `IOV_MAX`.
const MAX_IOVECS: usize = 1024;

/// A TCP flow, as the guest sees it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    pub guest: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Phase {
    /// Waiting for the host connect to complete.
    Connecting,
    /// SYN-ACK sent to the guest; waiting for its ACK.
    SynAckSent,
    Established,
}

/// Where host-to-guest data is held until the guest acknowledges it.
enum HostRx {
    /// In the kernel socket, read with `MSG_PEEK` at `SO_PEEK_OFF`.
    Peek,
    /// In a ring filled by consuming reads.
    Ring { ring: UnackedRing, eof: bool },
}

enum Verdict {
    Keep,
    /// Close the flow quietly; both sides are done.
    Remove,
    /// Abort the flow and reset the guest connection.
    Reset,
}

struct TcpFlow {
    socket: PolledSocket<Socket>,
    phase: Phase,
    host_rx: HostRx,

    // Guest to host.
    /// Next sequence number expected from the guest.
    rcv_nxt: Seq,
    /// In-order guest data after `rcv_nxt` gathered in the current batch and
    /// not yet written to the socket.
    rcv_pending: usize,
    guest_fin: bool,
    /// The host socket refused data; the advertised window is closed until it
    /// drains.
    write_blocked: bool,
    /// Without a send-space query, the first writability wait only arms the
    /// notification.
    write_armed: bool,
    /// Guest data was dropped after a partial write; send duplicate ACKs once
    /// the window reopens.
    request_retransmit: bool,
    ack_due: bool,
    our_wscale: u8,

    // Host to guest.
    isn: Seq,
    /// Oldest sequence number not acknowledged by the guest.
    snd_una: Seq,
    /// Next data sequence number to send (excluding FIN).
    snd_nxt: Seq,
    /// The guest's window, scaled.
    snd_wnd: u32,
    guest_wscale: u8,
    /// Payload size of segments sent to the guest.
    mss: usize,
    /// Sequence number at which host data ends, once the host closed.
    data_end: Option<Seq>,
    fin_sent: bool,
    fin_acked: bool,
    dup_acks: u8,
    send_synack: bool,

    rto: Duration,
    retries: u8,
    deadline: Option<Instant>,
    /// While the window is closed, when to next check whether the socket
    /// has drained.
    reopen_check: Option<Instant>,
}

/// Fields needed to emit a segment while `host_rx` is borrowed.
#[derive(Copy, Clone)]
struct SegmentHeader {
    key: FlowKey,
    ack: Seq,
    window: u16,
}

/// In-order guest data gathered per flow during a batch of guest frames,
/// borrowed from the frames until [`Tcp::flush`] writes it.
#[derive(Default)]
pub(crate) struct PendingWrites<'a> {
    flows: Vec<(FlowKey, Vec<io::IoSlice<'a>>)>,
}

impl<'a> PendingWrites<'a> {
    fn push(&mut self, key: FlowKey, data: &'a [u8]) {
        let bufs = match self.flows.iter_mut().find(|(k, _)| *k == key) {
            Some((_, bufs)) => bufs,
            None => {
                self.flows.push((key, Vec::new()));
                &mut self.flows.last_mut().expect("just pushed").1
            }
        };
        bufs.push(io::IoSlice::new(data));
    }

    fn take(&mut self, key: FlowKey) -> Vec<io::IoSlice<'a>> {
        match self.flows.iter().position(|(k, _)| *k == key) {
            Some(i) => self.flows.swap_remove(i).1,
            None => Vec::new(),
        }
    }
}

pub(crate) struct Tcp {
    flows: HashMap<FlowKey, TcpFlow>,
    limit: Option<usize>,
    isn_key: RandomState,
}

impl Tcp {
    pub fn new(limit: Option<usize>) -> Self {
        Self {
            flows: HashMap::new(),
            limit,
            isn_key: RandomState::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Handles a TCP segment from the guest. `host_dst` is the address to
    /// connect to on the host for a new flow. In-order data is added to
    /// `pending`, to be written by [`Self::flush`].
    pub fn handle<'a, C: Client + ?Sized>(
        &mut self,
        cfg: &GatewayConfig,
        client: &mut C,
        key: FlowKey,
        host_dst: SocketAddr,
        tcp: &TcpRepr<'a>,
        pending: &mut PendingWrites<'a>,
    ) -> Result<(), DropReason> {
        let Some(flow) = self.flows.get_mut(&key) else {
            if tcp.control == TcpControl::Syn && tcp.ack_number.is_none() {
                return self.connect(cfg, client, key, host_dst, tcp);
            }
            if tcp.control != TcpControl::Rst {
                reset_unknown(cfg, client, key, tcp);
            }
            return Ok(());
        };
        match flow.on_segment(tcp, key, pending) {
            Verdict::Keep => {}
            Verdict::Remove => {
                pending.take(key);
                self.flows.remove(&key);
            }
            Verdict::Reset => {
                pending.take(key);
                let flow = self.flows.remove(&key).expect("flow exists");
                flow.reset(cfg, client, key);
            }
        }
        Ok(())
    }

    /// Writes the data gathered in `pending` to the host sockets.
    pub fn flush<C: Client + ?Sized>(
        &mut self,
        cfg: &GatewayConfig,
        client: &mut C,
        pending: PendingWrites<'_>,
    ) {
        for (key, bufs) in pending.flows {
            let Some(flow) = self.flows.get_mut(&key) else {
                continue;
            };
            if flow.write_pending(&bufs).is_err() {
                let flow = self.flows.remove(&key).expect("flow exists");
                flow.reset(cfg, client, key);
            }
        }
    }

    fn connect<C: Client + ?Sized>(
        &mut self,
        cfg: &GatewayConfig,
        client: &mut C,
        key: FlowKey,
        host_dst: SocketAddr,
        syn: &TcpRepr<'_>,
    ) -> Result<(), DropReason> {
        if self.limit.is_some_and(|max| self.flows.len() >= max) {
            tracelimit::warn_ratelimited!(guest = %key.guest, remote = %key.remote, "tcp active-flow limit reached");
            reset_unknown(cfg, client, key, syn);
            return Err(DropReason::FlowLimit(FlowProtocol::Tcp));
        }
        let socket = match open_socket(host_dst) {
            Ok(s) => s,
            Err(err) => {
                reset_unknown(cfg, client, key, syn);
                return Err(DropReason::Io(err));
            }
        };
        let host_rx = if sys::set_peek_offset(&socket, 0).is_ok() {
            HostRx::Peek
        } else {
            HostRx::Ring {
                ring: UnackedRing::new(RING_MAX),
                eof: false,
            }
        };
        let socket = PolledSocket::new(client.driver(), socket).map_err(DropReason::Io)?;
        match socket.get().connect(&SockAddr::from(host_dst)) {
            Ok(()) => {}
            Err(err) if is_connect_incomplete(&err) => {}
            Err(err) => {
                tracing::debug!(error = &err as &dyn std::error::Error, %host_dst, "tcp connect failed");
                reset_unknown(cfg, client, key, syn);
                return Ok(());
            }
        }

        let isn = Seq(self.isn_key.hash_one((key, Instant::now().as_nanos())) as u32);
        let (guest_wscale, our_wscale) = match syn.window_scale {
            Some(ws) => (ws.min(14), OUR_WSCALE),
            None => (0, 0),
        };
        let default_mss = match key.guest {
            SocketAddr::V4(_) => 536,
            SocketAddr::V6(_) => 1220,
        };
        let flow = TcpFlow {
            socket,
            phase: Phase::Connecting,
            host_rx,
            rcv_nxt: Seq(syn.seq_number.0 as u32).add(1),
            rcv_pending: 0,
            guest_fin: false,
            write_blocked: false,
            write_armed: false,
            request_retransmit: false,
            ack_due: false,
            our_wscale,
            isn,
            snd_una: isn.add(1),
            snd_nxt: isn.add(1),
            snd_wnd: syn.window_len.into(),
            guest_wscale,
            mss: syn.max_seg_size.map_or(default_mss, usize::from).max(64),
            data_end: None,
            fin_sent: false,
            fin_acked: false,
            dup_acks: 0,
            send_synack: false,
            rto: RTO_INIT,
            retries: 0,
            deadline: None,
            reopen_check: None,
        };
        tracing::debug!(guest = %key.guest, remote = %key.remote, peek = matches!(flow.host_rx, HostRx::Peek), "tcp connecting");
        self.flows.insert(key, flow);
        Ok(())
    }

    /// Moves data and control between host sockets and the guest. Returns
    /// the earliest flow timer deadline.
    pub fn poll<C: Client + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        cfg: &GatewayConfig,
        client: &mut C,
        scratch: &mut [u8],
        now: Instant,
    ) -> Option<Instant> {
        let mut next = None::<Instant>;
        self.flows.retain(|&key, flow| {
            match flow.poll(cx, cfg, client, key, scratch, now) {
                Verdict::Keep => {}
                Verdict::Remove => {
                    tracing::debug!(guest = %key.guest, remote = %key.remote, "tcp closed");
                    return false;
                }
                Verdict::Reset => {
                    flow.reset(cfg, client, key);
                    return false;
                }
            }
            for d in [flow.deadline, flow.reopen_check].into_iter().flatten() {
                next = Some(next.map_or(d, |n| n.min(d)));
            }
            true
        });
        next
    }
}

fn open_socket(dst: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_tcp_nodelay(true)?;
    Ok(socket)
}

fn is_connect_incomplete(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    false
}

fn to_tcp_seq(seq: Seq) -> TcpSeqNumber {
    TcpSeqNumber(seq.0 as i32)
}

/// Returns the window to advertise for `space` bytes of free send-buffer
/// space, less a margin for the overhead charged per buffer.
fn window_for_space(space: usize) -> usize {
    space - space / SEND_SPACE_MARGIN_DIVISOR
}

/// Emits a TCP segment from the flow's remote address to the guest.
fn emit<C: Client + ?Sized>(
    cfg: &GatewayConfig,
    client: &mut C,
    key: FlowKey,
    repr: &TcpRepr<'_>,
    payload: &[&[u8]],
    tso: Option<u16>,
) {
    let mut header = [0u8; frame::MAX_TCP_HEADER_LEN];
    let len = repr.header_len();
    let unspecified = IpAddress::Ipv4(Ipv4Address::UNSPECIFIED);
    repr.emit(
        &mut TcpPacket::new_unchecked(&mut header[..len]),
        &unspecified,
        &unspecified,
        &ChecksumCapabilities::ignored(),
    );
    frame::send_l4(
        client,
        cfg,
        key.remote,
        key.guest,
        IpProtocol::Tcp,
        &header[..len],
        payload,
        tso,
    );
}

fn segment(
    key: FlowKey,
    control: TcpControl,
    seq: Seq,
    ack: Option<Seq>,
    window: u16,
) -> TcpRepr<'static> {
    TcpRepr {
        src_port: key.remote.port(),
        dst_port: key.guest.port(),
        control,
        seq_number: to_tcp_seq(seq),
        ack_number: ack.map(to_tcp_seq),
        window_len: window,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    }
}

/// Resets a guest segment that matches no flow (RFC 9293 section 3.10.7.1).
fn reset_unknown<C: Client + ?Sized>(
    cfg: &GatewayConfig,
    client: &mut C,
    key: FlowKey,
    tcp: &TcpRepr<'_>,
) {
    if client.max_frame_len() == 0 {
        return;
    }
    let seg_seq = Seq(tcp.seq_number.0 as u32);
    let repr = match tcp.ack_number {
        Some(ack) => segment(key, TcpControl::Rst, Seq(ack.0 as u32), None, 0),
        None => segment(
            key,
            TcpControl::Rst,
            Seq(0),
            Some(seg_seq.add(tcp.segment_len() as u32)),
            0,
        ),
    };
    emit(cfg, client, key, &repr, &[], None);
}

/// Returns `len` bytes starting at `offset` within the concatenation of
/// `parts` (at most two), as at most two slices.
fn sub_slices<'a>(parts: &[&'a [u8]], offset: usize, len: usize) -> ([&'a [u8]; 2], usize) {
    let mut out: [&[u8]; 2] = [&[], &[]];
    let mut count = 0;
    let mut skip = offset;
    let mut want = len;
    for part in parts {
        if want == 0 {
            break;
        }
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let take = (part.len() - skip).min(want);
        out[count] = &part[skip..skip + take];
        count += 1;
        want -= take;
        skip = 0;
    }
    (out, count)
}

impl TcpFlow {
    fn in_flight(&self) -> usize {
        self.snd_nxt.since(self.snd_una) as usize
    }

    fn fin_outstanding(&self) -> bool {
        self.fin_sent && !self.fin_acked
    }

    /// Returns the window to advertise to the guest, in bytes.
    ///
    /// Each write is charged its payload plus per-buffer overhead, so the
    /// window keeps a margin below the free send-buffer space. Otherwise a
    /// guest filling the window could overrun the socket and lose data.
    fn advertised_window(&self) -> usize {
        if self.write_blocked || self.guest_fin {
            return 0;
        }
        window_for_space(sys::send_space(self.socket.get()).unwrap_or(DEFAULT_SEND_SPACE))
    }

    fn window_field(&self, window: usize) -> u16 {
        (window >> self.our_wscale).min(u16::MAX.into()) as u16
    }

    fn on_segment<'a>(
        &mut self,
        tcp: &TcpRepr<'a>,
        key: FlowKey,
        pending: &mut PendingWrites<'a>,
    ) -> Verdict {
        if tcp.control == TcpControl::Rst {
            // Accept a reset only at the expected sequence number (RFC 5961
            // section 3), so a blind reset cannot tear down the host side.
            if Seq(tcp.seq_number.0 as u32) == self.rcv_expected() {
                let _ = self.socket.get().set_linger(Some(Duration::ZERO));
                return Verdict::Remove;
            }
            return Verdict::Keep;
        }
        match self.phase {
            Phase::Connecting => return Verdict::Keep,
            Phase::SynAckSent => {
                if tcp.control == TcpControl::Syn {
                    self.send_synack = true;
                    return Verdict::Keep;
                }
                match tcp.ack_number {
                    Some(ack) if Seq(ack.0 as u32) == self.snd_nxt => {
                        self.phase = Phase::Established;
                        self.deadline = None;
                        self.retries = 0;
                        self.rto = RTO_INIT;
                    }
                    _ => return Verdict::Keep,
                }
            }
            Phase::Established => {
                if tcp.control == TcpControl::Syn {
                    self.ack_due = true;
                    return Verdict::Keep;
                }
            }
        }

        if let Some(ack) = tcp.ack_number {
            let pure = tcp.payload.is_empty() && tcp.control == TcpControl::None;
            if self
                .on_ack(Seq(ack.0 as u32), tcp.window_len, pure)
                .is_err()
            {
                return Verdict::Reset;
            }
        }
        if self.on_data(tcp, key, pending).is_err() {
            return Verdict::Reset;
        }
        if self.guest_fin && self.fin_acked {
            return Verdict::Remove;
        }
        Verdict::Keep
    }

    fn on_ack(&mut self, ack: Seq, window: u16, pure: bool) -> Result<(), ()> {
        let end = self.snd_nxt.add(self.fin_sent.into());
        if !ack.within(self.snd_una, end) {
            return Ok(());
        }
        let data_ack = if ack.before(self.snd_nxt) {
            ack
        } else {
            self.snd_nxt
        };
        let acked = data_ack.since(self.snd_una) as usize;
        let new_wnd = u32::from(window) << self.guest_wscale;
        if acked > 0 {
            match &mut self.host_rx {
                HostRx::Peek => {
                    let mut remaining = acked;
                    while remaining > 0 {
                        match sys::discard(self.socket.get(), remaining) {
                            Ok(0) | Err(_) => return Err(()),
                            Ok(n) => remaining -= n,
                        }
                    }
                }
                HostRx::Ring { ring, .. } => ring.ack(acked).map_err(drop)?,
            }
            self.snd_una = data_ack;
            self.dup_acks = 0;
            self.retries = 0;
            self.rto = RTO_INIT;
            self.deadline = (self.in_flight() > 0 || self.fin_outstanding())
                .then(|| Instant::now().saturating_add(self.rto));
        } else if pure && new_wnd == self.snd_wnd && self.in_flight() > 0 {
            self.dup_acks = self.dup_acks.saturating_add(1);
            if self.dup_acks == 3 {
                self.rewind()?;
            }
        }
        if self.fin_sent && ack == end {
            self.fin_acked = true;
        }
        self.snd_wnd = new_wnd;
        Ok(())
    }

    /// The sequence number of the next guest byte, after any data gathered
    /// in the current batch.
    fn rcv_expected(&self) -> Seq {
        self.rcv_nxt.add(self.rcv_pending as u32)
    }

    fn on_data<'a>(
        &mut self,
        tcp: &TcpRepr<'a>,
        key: FlowKey,
        pending: &mut PendingWrites<'a>,
    ) -> Result<(), ()> {
        let fin = tcp.control == TcpControl::Fin;
        let mut data = tcp.payload;
        if data.is_empty() && !fin {
            return Ok(());
        }
        let seq = Seq(tcp.seq_number.0 as u32);
        let expected = self.rcv_expected();
        if seq.before(expected) {
            // Retransmitted data; acknowledge again and keep any new part.
            self.ack_due = true;
            let skip = expected.since(seq) as usize;
            if skip > data.len() || (skip == data.len() && !fin) {
                return Ok(());
            }
            data = &data[skip..];
        } else if seq != expected {
            // Out of order: no reassembly. A duplicate ACK prompts the guest
            // to retransmit from `rcv_nxt`.
            self.ack_due = true;
            return Ok(());
        }
        if !data.is_empty() {
            if self.guest_fin {
                return Ok(());
            }
            self.ack_due = true;
            pending.push(key, data);
            self.rcv_pending += data.len();
        }
        if fin && !self.guest_fin {
            // The FIN must follow all of the data on the host socket.
            self.write_pending(&pending.take(key))?;
            if self.rcv_nxt != seq.add(tcp.payload.len() as u32) {
                // Not all data was written; the guest retransmits the FIN.
                return Ok(());
            }
            self.guest_fin = true;
            self.rcv_nxt = self.rcv_nxt.add(1);
            self.ack_due = true;
            let _ = self.socket.get().shutdown(std::net::Shutdown::Write);
        }
        Ok(())
    }

    /// Writes the data gathered in the current batch to the host socket.
    /// Data the socket does not accept is dropped; the guest is asked to
    /// retransmit it once the window reopens.
    fn write_pending(&mut self, bufs: &[io::IoSlice<'_>]) -> Result<(), ()> {
        let total = std::mem::take(&mut self.rcv_pending);
        if total == 0 {
            return Ok(());
        }
        let mut written = 0;
        let mut result = Ok(());
        for chunk in bufs.chunks(MAX_IOVECS) {
            let len: usize = chunk.iter().map(|b| b.len()).sum();
            match self.socket.get().send_vectored(chunk) {
                Ok(n) => {
                    written += n;
                    if n < len {
                        break;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    tracing::debug!(
                        error = &err as &dyn std::error::Error,
                        "tcp host write failed"
                    );
                    result = Err(());
                    break;
                }
            }
        }
        self.rcv_nxt = self.rcv_nxt.add(written as u32);
        if result.is_ok() {
            // Data at `rcv_nxt` arriving means the guest has already resent
            // anything dropped earlier.
            self.request_retransmit = written < total;
            if written < total {
                self.write_blocked = true;
            }
        }
        result
    }

    /// Rewinds so all unacknowledged data is sent again.
    fn rewind(&mut self) -> Result<(), ()> {
        self.snd_nxt = self.snd_una;
        self.dup_acks = 0;
        match &mut self.host_rx {
            HostRx::Peek => sys::set_peek_offset(self.socket.get(), 0).map_err(drop)?,
            HostRx::Ring { ring, .. } => ring.rewind(),
        }
        if self.fin_outstanding() {
            self.fin_sent = false;
        }
        Ok(())
    }

    fn reset<C: Client + ?Sized>(&self, cfg: &GatewayConfig, client: &mut C, key: FlowKey) {
        let _ = self.socket.get().set_linger(Some(Duration::ZERO));
        if client.max_frame_len() == 0 {
            return;
        }
        let seq = if self.phase == Phase::Connecting {
            Seq(0)
        } else {
            self.snd_nxt
        };
        let repr = segment(key, TcpControl::Rst, seq, Some(self.rcv_nxt), 0);
        emit(cfg, client, key, &repr, &[], None);
    }

    fn poll<C: Client + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        cfg: &GatewayConfig,
        client: &mut C,
        key: FlowKey,
        scratch: &mut [u8],
        now: Instant,
    ) -> Verdict {
        if self.phase == Phase::Connecting {
            match self.socket.poll_ready(cx, PollEvents::OUT) {
                Poll::Pending => return Verdict::Keep,
                Poll::Ready(events) => {
                    let err = self.socket.get().take_error().ok().flatten();
                    if err.is_some() || events.has_err() {
                        tracing::debug!(remote = %key.remote, ?err, "tcp connect failed");
                        return Verdict::Reset;
                    }
                    self.phase = Phase::SynAckSent;
                    self.send_synack = true;
                }
            }
        }

        // Retransmission and persist timers.
        if self.deadline.is_some_and(|d| d <= now) {
            self.deadline = None;
            if self.phase == Phase::SynAckSent || self.in_flight() > 0 || self.fin_outstanding() {
                self.retries += 1;
                if self.retries > MAX_RETRIES {
                    return Verdict::Reset;
                }
                if self.phase == Phase::SynAckSent {
                    self.send_synack = true;
                } else if self.rewind().is_err() {
                    return Verdict::Reset;
                }
                self.rto = (self.rto * 2).min(RTO_MAX);
            } else if self.snd_wnd == 0 && self.phase == Phase::Established {
                // Zero-window probe: an old sequence number elicits an ACK
                // carrying the guest's current window.
                if client.max_frame_len() != 0 {
                    let repr = segment(
                        key,
                        TcpControl::None,
                        self.snd_nxt.add(u32::MAX),
                        Some(self.rcv_nxt),
                        self.window_field(self.advertised_window()),
                    );
                    emit(cfg, client, key, &repr, &[], None);
                }
                self.rto = (self.rto * 2).min(RTO_MAX);
                self.deadline = Some(now.saturating_add(self.rto));
            }
        }

        if self.send_synack {
            if client.max_frame_len() == 0 {
                return Verdict::Keep;
            }
            let window = self.advertised_window().min(u16::MAX.into()) as u16;
            let mss = match key.guest {
                SocketAddr::V4(_) => 1460,
                SocketAddr::V6(_) => 1440,
            };
            let mut repr = segment(key, TcpControl::Syn, self.isn, Some(self.rcv_nxt), window);
            repr.max_seg_size = Some(mss);
            if self.our_wscale != 0 {
                repr.window_scale = Some(self.our_wscale);
            }
            emit(cfg, client, key, &repr, &[], None);
            self.send_synack = false;
            self.deadline.get_or_insert(now.saturating_add(self.rto));
        }
        if self.phase != Phase::Established {
            return Verdict::Keep;
        }

        let mut window = self.advertised_window();
        if window < REOPEN_SPACE && !self.write_blocked && !self.guest_fin {
            // Avoid a silly window: close it, and send an update once the
            // socket drains, rather than leave the guest stalled on a small
            // window until its persist timer probes.
            self.write_blocked = true;
            window = 0;
        }
        if self.write_blocked {
            let write_armed = &mut self.write_armed;
            let r = self
                .socket
                .poll_io(
                    cx,
                    InterestSlot::Write,
                    PollEvents::OUT,
                    |s| match sys::send_space(s.get()) {
                        Ok(space) if window_for_space(space) < REOPEN_SPACE => {
                            Err(io::ErrorKind::WouldBlock.into())
                        }
                        Ok(_) => Ok(()),
                        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                            if std::mem::replace(write_armed, true) {
                                Ok(())
                            } else {
                                Err(io::ErrorKind::WouldBlock.into())
                            }
                        }
                        Err(err) => Err(err),
                    },
                );
            let reopened = match r {
                Poll::Ready(Ok(())) => true,
                Poll::Ready(Err(_)) => return Verdict::Reset,
                // A window closed here, while the socket still had some
                // space, may never be followed by a writability notification.
                // Check directly, which also arms the notification, and
                // periodically until the window reopens. Requiring the kernel
                // to consider the socket writable reopens the window only
                // once a useful amount of space is free.
                Poll::Pending => {
                    let socket = self.socket.get();
                    sys::poll_writable(socket).is_ok_and(|writable| writable)
                        && sys::send_space(socket)
                            .is_ok_and(|space| window_for_space(space) >= REOPEN_SPACE)
                }
            };
            if reopened {
                self.write_blocked = false;
                self.write_armed = false;
                self.reopen_check = None;
                self.ack_due = true;
                window = self.advertised_window();
            } else {
                self.reopen_check = Some(now.saturating_add(REOPEN_CHECK_INTERVAL));
            }
        }

        if self
            .send_data(cx, cfg, client, key, scratch, window, now)
            .is_err()
        {
            return Verdict::Reset;
        }
        if (self.ack_due || self.request_retransmit && !self.write_blocked)
            && client.max_frame_len() != 0
        {
            let repr = segment(
                key,
                TcpControl::None,
                self.snd_nxt.add(self.fin_sent.into()),
                Some(self.rcv_nxt),
                self.window_field(window),
            );
            emit(cfg, client, key, &repr, &[], None);
            self.ack_due = false;
            if self.request_retransmit && !self.write_blocked {
                // Guest data was dropped. Duplicates of this window update
                // trigger the guest's fast retransmit rather than waiting for
                // its retransmission timeout.
                let mut sent = 0;
                while sent < DUP_ACK_THRESHOLD && client.max_frame_len() != 0 {
                    emit(cfg, client, key, &repr, &[], None);
                    sent += 1;
                }
                self.request_retransmit = sent < DUP_ACK_THRESHOLD;
            }
        }
        if self.guest_fin && self.fin_acked {
            return Verdict::Remove;
        }
        Verdict::Keep
    }

    /// Sends host data to the guest, up to the guest's window and the
    /// available receive buffers.
    fn send_data<C: Client + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        cfg: &GatewayConfig,
        client: &mut C,
        key: FlowKey,
        scratch: &mut [u8],
        window: usize,
        now: Instant,
    ) -> Result<(), ()> {
        let hdr = SegmentHeader {
            key,
            ack: self.rcv_nxt,
            window: self.window_field(window),
        };
        let l3 = frame::l3_header_len(&key.guest) + TCP_HEADER_LEN;
        let gso = client.rx_gso_supported(key.guest.is_ipv6());
        while !self.fin_sent {
            if self.data_end == Some(self.snd_nxt) {
                if client.max_frame_len() == 0 {
                    break;
                }
                let repr = segment(
                    key,
                    TcpControl::Fin,
                    self.snd_nxt,
                    Some(hdr.ack),
                    hdr.window,
                );
                emit(cfg, client, key, &repr, &[], None);
                self.fin_sent = true;
                self.ack_due = false;
                self.deadline.get_or_insert(now.saturating_add(self.rto));
                break;
            }
            let avail = (self.snd_wnd as usize).saturating_sub(self.in_flight());
            if avail == 0 {
                if self.snd_wnd == 0 {
                    // Persist timer.
                    self.deadline.get_or_insert(now.saturating_add(self.rto));
                }
                break;
            }
            if client.max_frame_len() <= l3 {
                break;
            }
            let sent = match &mut self.host_rx {
                HostRx::Peek => {
                    let chunk = avail.min(scratch.len());
                    match self.socket.poll_peek(cx, &mut scratch[..chunk]) {
                        Poll::Pending => break,
                        Poll::Ready(Ok(0)) => {
                            self.data_end = Some(self.snd_nxt);
                            continue;
                        }
                        Poll::Ready(Ok(n)) => {
                            let sent = emit_data(
                                cfg,
                                client,
                                hdr,
                                &[&scratch[..n]],
                                self.snd_nxt,
                                self.mss,
                                gso,
                                l3,
                            );
                            if sent < n {
                                // Out of receive buffers: move the peek
                                // offset back to the first unsent byte.
                                let offset = self.in_flight() + sent;
                                sys::set_peek_offset(self.socket.get(), offset).map_err(drop)?;
                            }
                            sent
                        }
                        Poll::Ready(Err(err)) => {
                            tracing::debug!(
                                error = &err as &dyn std::error::Error,
                                "tcp host read failed"
                            );
                            return Err(());
                        }
                    }
                }
                HostRx::Ring { ring, eof } => {
                    while !*eof {
                        let room = ring.room(self.snd_wnd as usize);
                        if room == 0 {
                            break;
                        }
                        let spare = ring.spare_mut(room);
                        match self
                            .socket
                            .poll_io(cx, InterestSlot::Read, PollEvents::IN, |s| {
                                let mut sock: &Socket = s.get();
                                sock.read(spare)
                            }) {
                            Poll::Ready(Ok(0)) => *eof = true,
                            Poll::Ready(Ok(n)) => ring.commit(n),
                            Poll::Ready(Err(err)) => {
                                tracing::debug!(
                                    error = &err as &dyn std::error::Error,
                                    "tcp host read failed"
                                );
                                return Err(());
                            }
                            Poll::Pending => break,
                        }
                    }
                    let (a, b) = ring.next_unsent(avail);
                    if a.is_empty() {
                        if *eof {
                            self.data_end = Some(self.snd_nxt);
                            continue;
                        }
                        break;
                    }
                    let sent =
                        emit_data(cfg, client, hdr, &[a, b], self.snd_nxt, self.mss, gso, l3);
                    ring.mark_sent(sent);
                    sent
                }
            };
            if sent == 0 {
                break;
            }
            self.snd_nxt = self.snd_nxt.add(sent as u32);
            self.ack_due = false;
            self.deadline.get_or_insert(now.saturating_add(self.rto));
        }
        Ok(())
    }
}

/// Emits `payload` as data segments starting at `seq`, as GSO frames when the
/// client supports them. Returns the number of payload bytes sent, which is
/// less than the total when the guest runs out of receive buffers.
fn emit_data<C: Client + ?Sized>(
    cfg: &GatewayConfig,
    client: &mut C,
    hdr: SegmentHeader,
    payload: &[&[u8]],
    seq: Seq,
    mss: usize,
    gso: bool,
    l3: usize,
) -> usize {
    let total: usize = payload.iter().map(|p| p.len()).sum();
    let mut offset = 0;
    while offset < total {
        let max = client.max_frame_len();
        if max <= l3 {
            break;
        }
        let room = max - l3;
        let take = if gso {
            (total - offset).min(room).min(MAX_GSO_PAYLOAD)
        } else {
            (total - offset).min(room).min(mss)
        };
        let tso = (take > mss).then_some(mss as u16);
        let (parts, n) = sub_slices(payload, offset, take);
        let repr = segment(
            hdr.key,
            TcpControl::None,
            seq.add(offset as u32),
            Some(hdr.ack),
            hdr.window,
        );
        emit(cfg, client, hdr.key, &repr, &parts[..n], tso);
        offset += take;
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn sub_slices_spans_parts() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5];
        let parts = [&a[..], &b[..]];
        let (s, n) = sub_slices(&parts, 1, 3);
        assert_eq!(s[..n].concat(), [2, 3, 4]);
        let (s, n) = sub_slices(&parts, 3, 2);
        assert_eq!(s[..n].concat(), [4, 5]);
        let (_, n) = sub_slices(&parts, 0, 0);
        assert_eq!(n, 0);
    }
}
