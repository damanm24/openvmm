// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guest queue plumbing shared by the `net_backend` endpoints of the user-mode
//! stacks.
//!
//! An endpoint queue tracks guest receive and transmit buffers in a
//! [`QueueState`], reads transmitted frames out of guest memory, and delivers
//! frames from the stack into guest receive buffers through a
//! [`QueueClient`].

use crate::ChecksumState;
use crate::Client;
use crate::FrameSink;
use guestmem::GuestMemory;
use guestmem::GuestMemoryError;
use inspect::Inspect;
use inspect_counters::Counter;
use net_backend::BufferAccess;
use net_backend::L4Protocol;
use net_backend::RxChecksumState;
use net_backend::RxGsoProtocol;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::RxOffload;
use net_backend::RxOffloadSupport;
use net_backend::TxId;
use net_backend::TxMetadata;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use pal_async::driver::Driver;
use smoltcp::wire::ETHERNET_HEADER_LEN;
use smoltcp::wire::IPV4_HEADER_LEN;
use smoltcp::wire::IPV6_HEADER_LEN;
use smoltcp::wire::TcpPacket;
use std::collections::VecDeque;
use thiserror::Error;

#[cfg(test)]
mod tests;

/// Receive and transmit buffers of one endpoint queue.
#[derive(Default)]
pub struct QueueState {
    /// Guest receive buffers available for frames from the stack.
    pub rx_avail: VecDeque<RxId>,
    /// Receive buffers holding frames for the guest.
    pub rx_ready: VecDeque<RxId>,
    /// Segments of transmitted packets not yet processed.
    pub tx_avail: VecDeque<TxSegment>,
    /// Transmitted packets that are complete.
    pub tx_ready: VecDeque<TxId>,
}

impl Inspect for QueueState {
    fn inspect(&self, req: inspect::Request<'_>) {
        req.respond()
            .field("rx_avail", self.rx_avail.len())
            .field("rx_ready", self.rx_ready.len())
            .field("tx_avail", self.tx_avail.len())
            .field("tx_ready", self.tx_ready.len());
    }
}

/// Drop and error counters of one endpoint queue.
#[derive(Inspect, Default)]
pub struct QueueStats {
    /// Frames for the guest dropped for lack of a suitable receive buffer.
    pub rx_dropped: Counter,
    /// Guest frames dropped because of a host limit or policy.
    pub tx_dropped: Counter,
    /// Guest frames that were malformed or could not be read.
    pub tx_errors: Counter,
    /// Guest frames of an unsupported protocol.
    pub tx_unknown: Counter,
}

/// A transmitted packet at the head of [`QueueState::tx_avail`].
#[derive(Debug, Clone, Copy)]
pub struct TxPacket {
    /// The ID to complete the packet with.
    pub id: TxId,
    /// The total length of the packet in bytes.
    pub len: usize,
    /// The number of segments in the packet.
    pub segment_count: usize,
    /// The offloads requested by the guest.
    pub checksum: ChecksumState,
}

/// An error reading a transmitted packet from guest memory.
#[derive(Debug, Error)]
pub enum TxReadError {
    /// Guest memory could not be read.
    #[error("failed to read tx packet from guest memory")]
    GuestMemory(#[source] GuestMemoryError),
    /// The packet's segments are longer than its length.
    #[error("tx packet segments exceed the packet length")]
    Length,
}

/// Returns the checksum and segmentation offloads requested for a transmitted
/// packet.
pub fn tx_checksum(meta: &TxMetadata) -> ChecksumState {
    ChecksumState {
        ipv4: meta.flags.offload_ip_header_checksum(),
        tcp: meta.flags.offload_tcp_checksum(),
        udp: meta.flags.offload_udp_checksum(),
        partial: false,
        tso: meta
            .flags
            .offload_tcp_segmentation()
            .then_some(meta.max_segment_size),
        gso: meta
            .flags
            .offload_udp_segmentation()
            .then_some(meta.max_segment_size),
    }
}

impl QueueState {
    /// Adds guest receive buffers.
    pub fn rx_avail(&mut self, done: &[RxId]) {
        self.rx_avail.extend(done);
    }

    /// Moves filled receive buffers into `packets`, returning the count.
    pub fn rx_poll(&mut self, packets: &mut [RxId]) -> usize {
        let n = packets.len().min(self.rx_ready.len());
        for (x, y) in packets.iter_mut().zip(self.rx_ready.drain(..n)) {
            *x = y;
        }
        n
    }

    /// Adds transmitted packet segments.
    pub fn tx_avail(&mut self, segments: &[TxSegment]) {
        self.tx_avail.extend(segments.iter().cloned());
    }

    /// Moves completed transmit IDs into `done`, returning the count.
    pub fn tx_poll(&mut self, done: &mut [TxId]) -> usize {
        let n = done.len().min(self.tx_ready.len());
        for (x, y) in done.iter_mut().zip(self.tx_ready.drain(..n)) {
            *x = y;
        }
        n
    }

    /// Returns whether receive or transmit completions are pending.
    pub fn has_completions(&self) -> bool {
        !self.rx_ready.is_empty() || !self.tx_ready.is_empty()
    }

    /// Returns the next transmitted packet, without removing it.
    pub fn next_tx(&self) -> Option<TxPacket> {
        let head = self.tx_avail.front()?;
        let TxSegmentType::Head(meta) = &head.ty else {
            unreachable!("tx packets start with a head segment")
        };
        Some(TxPacket {
            id: meta.id,
            len: meta.len as usize,
            segment_count: meta.segment_count as usize,
            checksum: tx_checksum(meta),
        })
    }

    /// Removes the next transmitted packet, `packet`, copying its data into
    /// `dest`, which must be `packet.len` bytes. Bytes the segments don't
    /// cover are zeroed. The packet is completed even on failure.
    pub fn take_tx(
        &mut self,
        packet: &TxPacket,
        mem: &GuestMemory,
        dest: &mut [u8],
    ) -> Result<(), TxReadError> {
        assert_eq!(dest.len(), packet.len);
        let mut result = Ok(());
        let mut offset = 0;
        for segment in self.tx_avail.drain(..packet.segment_count) {
            if result.is_err() {
                continue;
            }
            let end = offset + segment.len as usize;
            let Some(dest) = dest.get_mut(offset..end) else {
                result = Err(TxReadError::Length);
                continue;
            };
            if let Err(err) = mem.read_at(segment.gpa, dest) {
                result = Err(TxReadError::GuestMemory(err));
            }
            offset = end;
        }
        // Don't expose earlier contents of `dest` if the segments are short.
        if let Some(rest) = dest.get_mut(offset..) {
            rest.fill(0);
        }
        self.tx_ready.push_back(packet.id);
        result
    }

    /// Removes and completes the next transmitted packet, `packet`, without
    /// reading it.
    pub fn drop_tx(&mut self, packet: &TxPacket) {
        self.tx_avail.drain(..packet.segment_count);
        self.tx_ready.push_back(packet.id);
    }
}

/// A [`Client`] that delivers frames from the stack into the queue's guest
/// receive buffers.
pub struct QueueClient<'a> {
    /// The queue's buffers.
    pub state: &'a mut QueueState,
    /// The queue's counters.
    pub stats: &'a mut QueueStats,
    /// Access to the guest buffers.
    pub pool: &'a mut dyn BufferAccess,
    /// The driver for host sockets and timers.
    pub driver: &'a dyn Driver,
    /// Receive offloads the frontend enabled.
    pub offloads: RxOffloadSupport,
}

impl FrameSink for QueueClient<'_> {
    fn recv(&mut self, data: &[u8], checksum: &ChecksumState) {
        self.recv_segments(&[data], checksum);
    }

    fn recv_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState) {
        let Some(rx_id) = self.state.rx_avail.pop_front() else {
            // TCP and UDP wait for `rx_mtu` to report a buffer, so this only
            // affects unbuffered protocols.
            self.stats.rx_dropped.increment();
            return;
        };
        let len: usize = segments.iter().map(|s| s.len()).sum();
        let max = self.pool.capacity(rx_id) as usize;
        if len > max {
            tracelimit::warn_ratelimited!(len, max, "dropping rx frame: too large");
            self.stats.rx_dropped.increment();
            self.state.rx_avail.push_front(rx_id);
            return;
        }
        let l3_start = ETHERNET_HEADER_LEN
            + if checksum.ipv4 {
                IPV4_HEADER_LEN
            } else {
                IPV6_HEADER_LEN
            };
        let offload = if let Some(mss) = checksum.tso {
            // The stacks generate GSO frames with fixed-size IP headers, and
            // the first segment holds every header.
            assert!(checksum.tcp && self.rx_gso_supported(!checksum.ipv4));
            let protocol = if checksum.ipv4 {
                RxGsoProtocol::TcpV4
            } else {
                RxGsoProtocol::TcpV6
            };
            let tcp_header_len =
                usize::from(TcpPacket::new_unchecked(&segments[0][l3_start..]).header_len());
            RxOffload::tcp_gso(
                protocol,
                (l3_start + tcp_header_len) as u16,
                mss,
                Some(l3_start as u16),
            )
        } else if checksum.partial {
            assert!(self.rx_checksum_supported() && checksum.tcp != checksum.udp);
            RxOffload::checksum(l3_start as u16, if checksum.tcp { 16 } else { 6 })
        } else {
            RxOffload::default()
        };
        self.pool.write_packet_segments(
            rx_id,
            &RxMetadata {
                offset: 0,
                len,
                ip_checksum: if checksum.ipv4 {
                    RxChecksumState::Good
                } else {
                    RxChecksumState::Unknown
                },
                l4_checksum: if checksum.partial || !(checksum.tcp || checksum.udp) {
                    RxChecksumState::Unknown
                } else {
                    RxChecksumState::Good
                },
                l4_protocol: if checksum.tcp {
                    L4Protocol::Tcp
                } else if checksum.udp {
                    L4Protocol::Udp
                } else {
                    L4Protocol::Unknown
                },
                offload,
                vlan: None,
            },
            segments,
        );
        self.state.rx_ready.push_back(rx_id);
    }

    fn rx_mtu(&mut self) -> usize {
        self.state
            .rx_avail
            .front()
            .map_or(0, |&rx_id| self.pool.capacity(rx_id) as usize)
    }
}

impl Client for QueueClient<'_> {
    fn driver(&self) -> &dyn Driver {
        self.driver
    }

    fn rx_checksum_supported(&self) -> bool {
        self.offloads.checksum
    }

    fn rx_gso_supported(&self, ipv6: bool) -> bool {
        self.offloads.checksum
            && if ipv6 {
                self.offloads.tcpv6_gso
            } else {
                self.offloads.tcpv4_gso
            }
    }
}
