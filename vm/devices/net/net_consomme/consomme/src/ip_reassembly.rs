// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPv4 fragment reassembly.
//!
//! When the guest sends a fragmented IPv4 packet, the fragments are collected
//! here until the complete datagram can be reconstructed. Incomplete queues
//! are expired after [`REASSEMBLY_TIMEOUT`]. Resource usage is bounded by
//! [`MAX_QUEUES`] and [`MAX_BUFFER_BYTES`] to prevent guest-driven DoS.

use crate::DropReason;
use crate::range_set::RangeSet;
use inspect::Inspect;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4FragKey;
use smoltcp::wire::Ipv4Packet;
use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

/// Maximum number of concurrent reassembly queues.
const MAX_QUEUES: usize = 16;

/// Maximum total bytes buffered across all reassembly queues.
const MAX_BUFFER_BYTES: usize = 256 * 1024;

/// How long an incomplete reassembly queue lives before expiration.
/// Matches libslirp's ~30 s (IPFRAGTTL=60 at 2 ticks/s).
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum non-contiguous ranges tracked per reassembly queue.
const MAX_RANGES: usize = 16;

/// Maximum IPv4 datagram payload (65535 - min header = 65515, but we cap the
/// buffer at 65535 to keep things simple since the header is stored separately).
const MAX_IP_PAYLOAD: usize = 65535;

/// Maximum IPv4 header length (with options).
const MAX_IPV4_HEADER: usize = 60;

/// Per-datagram reassembly state.
struct ReassemblyQueue {
    /// Reassembly buffer holding payload bytes indexed by fragment offset.
    buffer: Vec<u8>,
    /// Tracks which byte ranges have been received.
    received: RangeSet<u16, MAX_RANGES>,
    /// Total payload length, known once the final fragment (MF=0) arrives.
    total_len: Option<u16>,
    /// Copy of the IPv4 header from the first fragment (offset 0).
    first_header: [u8; MAX_IPV4_HEADER],
    /// Actual length of the saved first header.
    first_header_len: u8,
    /// Whether fragment at offset 0 has been received.
    has_first: bool,
    /// Source address of the original datagram (for ICMP errors on expiry).
    src_addr: Ipv4Address,
    /// When this queue was created.
    created: Instant,
    /// Total bytes stored in `buffer` (for global accounting).
    bytes_allocated: usize,
}

impl Inspect for ReassemblyQueue {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.field("has_first", self.has_first);
        resp.field("total_len", self.total_len);
        resp.field("bytes_allocated", self.bytes_allocated);
        resp.child("received", |req| self.received.inspect(req));
    }
}

/// Result of processing a fragment.
pub(crate) enum FragmentResult {
    /// All fragments received; contains the reassembled IP packet.
    Reassembled(Vec<u8>),
    /// Fragment stored, waiting for more.
    Buffered,
    /// Fragment was dropped.
    Dropped(DropReason),
}

/// Information about an expired reassembly queue, used to send ICMP Time
/// Exceeded back to the guest.
pub(crate) struct ExpiredQueue {
    /// Copy of the first fragment's IP header + up to 8 bytes of payload.
    /// Per RFC 792, ICMP errors include the original IP header + 8 bytes.
    pub header_and_payload: Vec<u8>,
    /// Source address of the original datagram (= destination of ICMP error).
    pub src_addr: Ipv4Address,
}

/// Top-level IPv4 fragment reassembly state.
pub(crate) struct IpReassembly {
    queues: BTreeMap<Ipv4FragKey, ReassemblyQueue>,
    total_buffer_bytes: usize,
}

impl Inspect for IpReassembly {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.field("queue_count", self.queues.len());
        resp.field("total_buffer_bytes", self.total_buffer_bytes);
        for (key, queue) in &self.queues {
            resp.child(&format!("{key:?}"), |req| queue.inspect(req));
        }
    }
}

impl IpReassembly {
    pub fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
            total_buffer_bytes: 0,
        }
    }

    /// Process an incoming IPv4 fragment. The caller has already validated
    /// that the packet is indeed a fragment (more_frags || frag_offset != 0).
    pub fn process_fragment(&mut self, pkt: &Ipv4Packet<&[u8]>) -> FragmentResult {
        let key = pkt.get_key();
        let hdr_len = pkt.header_len() as usize;
        let total_len = pkt.total_len() as usize;

        // Validate header/total length relationship.
        if total_len < hdr_len {
            return FragmentResult::Dropped(DropReason::MalformedPacket);
        }

        let payload_len = pkt.payload().len();
        let frag_offset = pkt.frag_offset(); // already in bytes (smoltcp shifts)

        // Validate that the fragment doesn't exceed the max IP datagram size.
        let frag_end = match frag_offset.checked_add(payload_len as u16) {
            Some(end) if (end as usize) <= MAX_IP_PAYLOAD => end,
            _ => return FragmentResult::Dropped(DropReason::MalformedPacket),
        };

        // Non-final fragments must have payload aligned to 8-byte boundaries.
        if pkt.more_frags() && !payload_len.is_multiple_of(8) {
            return FragmentResult::Dropped(DropReason::MalformedPacket);
        }

        // Check capacity limits before creating a new queue.
        if !self.queues.contains_key(&key) {
            if self.queues.len() >= MAX_QUEUES {
                tracelimit::warn_ratelimited!(
                    "IP reassembly: dropping fragment, max queues ({MAX_QUEUES}) reached"
                );
                return FragmentResult::Dropped(DropReason::FragmentedPacket);
            }
            if self.total_buffer_bytes >= MAX_BUFFER_BYTES {
                tracelimit::warn_ratelimited!(
                    "IP reassembly: dropping fragment, buffer limit ({MAX_BUFFER_BYTES}) reached"
                );
                return FragmentResult::Dropped(DropReason::FragmentedPacket);
            }
        }

        let src_addr = pkt.src_addr();
        let queue = self.queues.entry(key).or_insert_with(|| ReassemblyQueue {
            buffer: Vec::new(),
            received: RangeSet::new(),
            total_len: None,
            first_header: [0u8; MAX_IPV4_HEADER],
            first_header_len: 0,
            has_first: false,
            src_addr,
            created: Instant::now(),
            bytes_allocated: 0,
        });

        // Save the first fragment's IP header for later reconstruction.
        if frag_offset == 0 && !queue.has_first {
            let copy_len = hdr_len.min(MAX_IPV4_HEADER);
            queue.first_header[..copy_len].copy_from_slice(&pkt.as_ref()[..copy_len]);
            queue.first_header_len = copy_len as u8;
            queue.has_first = true;
        }

        // Record total payload length from the final fragment.
        if !pkt.more_frags() {
            queue.total_len = Some(frag_end);
        }

        // Grow buffer if needed, tracking memory globally.
        let required = frag_end as usize;
        if required > queue.buffer.len() {
            let growth = required - queue.buffer.len();
            if self.total_buffer_bytes + growth > MAX_BUFFER_BYTES {
                tracelimit::warn_ratelimited!(
                    "IP reassembly: dropping fragment, buffer limit ({MAX_BUFFER_BYTES}) reached"
                );
                return FragmentResult::Dropped(DropReason::FragmentedPacket);
            }
            queue.buffer.resize(required, 0);
            self.total_buffer_bytes += growth;
            queue.bytes_allocated += growth;
        }

        // Copy fragment payload into the reassembly buffer.
        let src = &pkt.as_ref()[hdr_len..total_len];
        queue.buffer[frag_offset as usize..frag_end as usize].copy_from_slice(src);

        // Track the received range.
        if queue.received.insert(frag_offset, frag_end).is_err() {
            tracelimit::warn_ratelimited!(
                "IP reassembly: dropping fragment, too many non-contiguous ranges"
            );
            // Remove the entire queue since it's now unreliable.
            let removed = self.queues.remove(&key).unwrap();
            self.total_buffer_bytes -= removed.bytes_allocated;
            return FragmentResult::Dropped(DropReason::FragmentedPacket);
        }

        // Check for completion.
        if let Some(tl) = queue.total_len {
            if queue.has_first && queue.received.is_complete(tl) {
                let queue = self.queues.remove(&key).unwrap();
                self.total_buffer_bytes -= queue.bytes_allocated;
                return FragmentResult::Reassembled(Self::build_packet(&queue, tl));
            }
        }

        FragmentResult::Buffered
    }

    /// Expire queues older than [`REASSEMBLY_TIMEOUT`]. Returns information
    /// about expired queues that had a first fragment, so the caller can
    /// send ICMP Time Exceeded errors.
    pub fn expire(&mut self, now: Instant) -> Vec<ExpiredQueue> {
        let mut expired = Vec::new();
        self.queues.retain(|_key, queue| {
            if now.duration_since(queue.created) <= REASSEMBLY_TIMEOUT {
                return true;
            }
            self.total_buffer_bytes -= queue.bytes_allocated;

            // If we have the first fragment, provide data for ICMP error.
            if queue.has_first {
                let hdr_len = queue.first_header_len as usize;
                // RFC 792: include original IP header + first 8 bytes of payload.
                let payload_bytes = queue.buffer.len().min(8);
                let mut data = Vec::with_capacity(hdr_len + payload_bytes);
                data.extend_from_slice(&queue.first_header[..hdr_len]);
                data.extend_from_slice(&queue.buffer[..payload_bytes]);
                expired.push(ExpiredQueue {
                    header_and_payload: data,
                    src_addr: queue.src_addr,
                });
            }

            false
        });
        // Fix up total_buffer_bytes in case retain caused underflow
        // (shouldn't happen, but be defensive).
        if self.queues.is_empty() {
            self.total_buffer_bytes = 0;
        }
        expired
    }

    /// Build the reassembled IP packet from a completed queue.
    fn build_packet(queue: &ReassemblyQueue, total_payload_len: u16) -> Vec<u8> {
        let hdr_len = queue.first_header_len as usize;
        let packet_len = hdr_len + total_payload_len as usize;
        let mut packet = Vec::with_capacity(packet_len);
        packet.extend_from_slice(&queue.first_header[..hdr_len]);
        packet.extend_from_slice(&queue.buffer[..total_payload_len as usize]);

        // Fix up the IP header: clear fragment flags, set correct total length,
        // recompute checksum.
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet[..]);
        ipv4.set_more_frags(false);
        ipv4.set_frag_offset(0);
        ipv4.set_total_len(packet_len as u16);
        ipv4.fill_checksum();

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::IpProtocol;
    use smoltcp::wire::Ipv4Packet;

    /// Build a minimal IPv4 fragment packet for testing.
    fn make_fragment(id: u16, frag_offset: u16, more_frags: bool, payload: &[u8]) -> Vec<u8> {
        let hdr_len = 20usize;
        let total_len = hdr_len + payload.len();
        let mut buf = vec![0u8; total_len];
        let mut pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        pkt.set_version(4);
        pkt.set_header_len(hdr_len as u8);
        pkt.set_total_len(total_len as u16);
        pkt.set_ident(id);
        pkt.clear_flags();
        pkt.set_dont_frag(false);
        pkt.set_more_frags(more_frags);
        pkt.set_frag_offset(frag_offset);
        pkt.set_hop_limit(64);
        pkt.set_next_header(IpProtocol::Udp);
        pkt.set_src_addr(Ipv4Address::new(10, 0, 0, 2));
        pkt.set_dst_addr(Ipv4Address::new(10, 0, 0, 1));
        pkt.payload_mut().copy_from_slice(payload);
        pkt.fill_checksum();
        buf
    }

    // ---- IpReassembly tests ----

    #[test]
    fn two_fragment_reassembly() {
        let mut reasm = IpReassembly::new();

        // First fragment: offset 0, MF=1, 16 bytes payload.
        let frag1 = make_fragment(42, 0, true, &[0xAA; 16]);
        let pkt1 = Ipv4Packet::new_unchecked(&frag1[..]);
        assert!(matches!(
            reasm.process_fragment(&pkt1),
            FragmentResult::Buffered
        ));

        // Second fragment: offset 16, MF=0, 8 bytes payload.
        let frag2 = make_fragment(42, 16, false, &[0xBB; 8]);
        let pkt2 = Ipv4Packet::new_unchecked(&frag2[..]);
        match reasm.process_fragment(&pkt2) {
            FragmentResult::Reassembled(data) => {
                let reassembled = Ipv4Packet::new_unchecked(&data[..]);
                assert_eq!(reassembled.total_len() as usize, 20 + 24);
                assert!(!reassembled.more_frags());
                assert_eq!(reassembled.frag_offset(), 0);
                assert!(reassembled.verify_checksum());
                // Verify payload contents.
                assert_eq!(&reassembled.payload()[..16], &[0xAA; 16]);
                assert_eq!(&reassembled.payload()[16..24], &[0xBB; 8]);
            }
            other => panic!("expected Reassembled, got {other:?}"),
        }
        assert_eq!(reasm.queues.len(), 0);
        assert_eq!(reasm.total_buffer_bytes, 0);
    }

    #[test]
    fn three_fragment_out_of_order() {
        let mut reasm = IpReassembly::new();

        // Send fragments 3, 1, 2.
        let frag3 = make_fragment(7, 16, false, &[0xCC; 8]);
        let frag1 = make_fragment(7, 0, true, &[0xAA; 8]);
        let frag2 = make_fragment(7, 8, true, &[0xBB; 8]);

        assert!(matches!(
            reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag3[..])),
            FragmentResult::Buffered
        ));
        assert!(matches!(
            reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag1[..])),
            FragmentResult::Buffered
        ));
        match reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag2[..])) {
            FragmentResult::Reassembled(data) => {
                let reassembled = Ipv4Packet::new_unchecked(&data[..]);
                assert_eq!(reassembled.total_len() as usize, 20 + 24);
                assert!(reassembled.verify_checksum());
                assert_eq!(&reassembled.payload()[..8], &[0xAA; 8]);
                assert_eq!(&reassembled.payload()[8..16], &[0xBB; 8]);
                assert_eq!(&reassembled.payload()[16..24], &[0xCC; 8]);
            }
            other => panic!("expected Reassembled, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_fragment() {
        let mut reasm = IpReassembly::new();
        let frag1 = make_fragment(1, 0, true, &[0xAA; 8]);
        let frag1b = make_fragment(1, 0, true, &[0xFF; 8]);
        let frag2 = make_fragment(1, 8, false, &[0xBB; 8]);

        assert!(matches!(
            reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag1[..])),
            FragmentResult::Buffered
        ));
        // Re-send first fragment with different data — should overwrite.
        assert!(matches!(
            reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag1b[..])),
            FragmentResult::Buffered
        ));
        match reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag2[..])) {
            FragmentResult::Reassembled(data) => {
                let reassembled = Ipv4Packet::new_unchecked(&data[..]);
                // Should have the overwritten data (0xFF), not original (0xAA).
                assert_eq!(&reassembled.payload()[..8], &[0xFF; 8]);
            }
            other => panic!("expected Reassembled, got {other:?}"),
        }
    }

    #[test]
    fn expiration() {
        let mut reasm = IpReassembly::new();
        let frag1 = make_fragment(99, 0, true, &[0xAA; 8]);
        assert!(matches!(
            reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag1[..])),
            FragmentResult::Buffered
        ));
        assert_eq!(reasm.queues.len(), 1);

        // Expire with a time far in the future.
        let expired = reasm.expire(Instant::now() + Duration::from_secs(60));
        assert_eq!(reasm.queues.len(), 0);
        assert_eq!(reasm.total_buffer_bytes, 0);
        // Should have one expired entry with first-fragment data.
        assert_eq!(expired.len(), 1);
        assert!(expired[0].header_and_payload.len() >= 20);
    }

    #[test]
    fn max_queues_exceeded() {
        let mut reasm = IpReassembly::new();
        // Fill up to MAX_QUEUES.
        for id in 0..MAX_QUEUES as u16 {
            let frag = make_fragment(id, 0, true, &[0x00; 8]);
            assert!(matches!(
                reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag[..])),
                FragmentResult::Buffered
            ));
        }
        // One more should be dropped.
        let frag = make_fragment(0xFFFF, 0, true, &[0x00; 8]);
        assert!(matches!(
            reasm.process_fragment(&Ipv4Packet::new_unchecked(&frag[..])),
            FragmentResult::Dropped(_)
        ));
    }

    #[test]
    fn fragment_offset_overflow() {
        let mut reasm = IpReassembly::new();
        // frag_offset near max + payload that would overflow u16.
        let frag = make_fragment(1, 65520, false, &[0x00; 40]);
        let pkt = Ipv4Packet::new_unchecked(&frag[..]);
        assert!(matches!(
            reasm.process_fragment(&pkt),
            FragmentResult::Dropped(DropReason::MalformedPacket)
        ));
    }

    #[test]
    fn non_final_fragment_alignment() {
        let mut reasm = IpReassembly::new();
        // Non-final fragment with payload not aligned to 8 bytes.
        let frag = make_fragment(1, 0, true, &[0x00; 10]);
        let pkt = Ipv4Packet::new_unchecked(&frag[..]);
        assert!(matches!(
            reasm.process_fragment(&pkt),
            FragmentResult::Dropped(DropReason::MalformedPacket)
        ));
    }

    impl core::fmt::Debug for FragmentResult {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                FragmentResult::Reassembled(v) => {
                    write!(f, "Reassembled({} bytes)", v.len())
                }
                FragmentResult::Buffered => write!(f, "Buffered"),
                FragmentResult::Dropped(r) => write!(f, "Dropped({r})"),
            }
        }
    }
}
