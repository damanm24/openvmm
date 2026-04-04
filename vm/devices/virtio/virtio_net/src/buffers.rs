// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::VirtioNetHeader;
use crate::VirtioNetHeaderFlags;
use crate::VirtioNetHeaderGso;
use crate::VirtioNetHeaderGsoProtocol;
use crate::header_size;
use guestmem::GuestMemory;
use inspect::Inspect;
use net_backend::BufferAccess;
use net_backend::RxBufferSegment;
use net_backend::RxChecksumState;
use net_backend::RxGsoType;
use net_backend::RxId;
use net_backend::RxMetadata;
use std::collections::VecDeque;
use virtio::VirtioQueueCallbackWork;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

/// A single logical receive buffer, potentially spanning multiple descriptors
/// when `VIRTIO_NET_F_MRG_RXBUF` is negotiated.
struct RxPacket {
    /// The descriptor chain(s) backing this buffer. When MRG_RXBUF is not
    /// active, this always has exactly one element.
    works: Vec<VirtioQueueCallbackWork>,
    /// Number of works that actually contain packet data (set by write_header).
    /// Zero until the header is written.
    num_buffers_used: u16,
    /// Total packet payload length (excluding virtio-net header). Zero until
    /// the header is written.
    len: u32,
    /// Total usable capacity across all works (excluding the header reserved
    /// in the first work).
    cap: u32,
}

/// Holds virtio buffers available for a network backend to send data to the client.
#[derive(Inspect)]
#[inspect(extra = "Self::inspect_extra")]
pub struct VirtioWorkPool {
    mem: GuestMemory,
    #[inspect(skip)]
    rx_packets: Vec<Option<RxPacket>>,
    /// Whether VIRTIO_NET_F_MRG_RXBUF was negotiated.
    mrg_rxbuf: bool,
    /// Spare descriptors not yet assigned to a logical buffer.
    /// Only used when `mrg_rxbuf` is true.
    #[inspect(with = "VecDeque::len")]
    spare_works: VecDeque<VirtioQueueCallbackWork>,
}

impl VirtioWorkPool {
    fn inspect_extra(&self, resp: &mut inspect::Response<'_>) {
        resp.field(
            "pending_rx_packets",
            self.rx_packets.iter().filter(|p| p.is_some()).count(),
        );
        if self.mrg_rxbuf {
            resp.field("spare_descriptors", self.spare_works.len());
        }
    }

    /// Create a new instance.
    pub fn new(mem: GuestMemory, queue_size: u16, mrg_rxbuf: bool) -> Self {
        Self {
            mem,
            rx_packets: (0..queue_size).map(|_| None).collect(),
            mrg_rxbuf,
            spare_works: VecDeque::new(),
        }
    }

    /// Returns a reference to the guest memory.
    pub fn mem(&self) -> &GuestMemory {
        &self.mem
    }

    /// Fills `buf` with the RxIds of currently available buffers. `buf` must be
    /// at least as big as the virtio queue size, passed to `new()`.
    ///
    /// Returns the number of entries written.
    pub fn fill_ready(&self, buf: &mut [RxId]) -> usize {
        assert!(buf.len() >= self.rx_packets.len());
        let mut n = 0;
        for (dest, src) in buf.iter_mut().zip(
            self.rx_packets
                .iter()
                .enumerate()
                .filter_map(|(i, e)| e.is_some().then_some(RxId(i as u32))),
        ) {
            *dest = src;
            n += 1;
        }
        n
    }

    /// Add a virtio work instance to the buffers available for use.
    ///
    /// When `mrg_rxbuf` is true, the work becomes a single-descriptor
    /// `RxPacket` that can be expanded lazily during `write_data` by
    /// pulling from the spare pool.
    ///
    /// Returns `Err` with the work item if the descriptor index is already in
    /// use or the buffer is too small for the virtio-net header.
    pub fn queue_work(
        &mut self,
        work: VirtioQueueCallbackWork,
    ) -> Result<RxId, VirtioQueueCallbackWork> {
        let idx = work.descriptor_index();
        let packet = &mut self.rx_packets[idx as usize];
        if packet.is_some() {
            tracelimit::warn_ratelimited!("dropping RX buffer: descriptor index already in use");
            return Err(work);
        }
        let payload_length = work.get_payload_length(true) as u32;
        if self.mrg_rxbuf {
            // With MRG_RXBUF, per spec each buffer must be at least
            // header-sized. The capacity advertised to the backend is just
            // this single descriptor's usable space; it will grow lazily.
            let Some(cap) = payload_length.checked_sub(header_size() as u32) else {
                tracelimit::warn_ratelimited!(
                    len = payload_length,
                    "dropping RX buffer: payload length smaller than virtio-net header size"
                );
                return Err(work);
            };
            *packet = Some(RxPacket {
                works: vec![work],
                num_buffers_used: 0,
                len: 0,
                cap,
            });
        } else {
            let Some(cap) = payload_length.checked_sub(header_size() as u32) else {
                tracelimit::warn_ratelimited!(
                    len = payload_length,
                    "dropping RX buffer: payload length smaller than virtio-net header size"
                );
                return Err(work);
            };
            *packet = Some(RxPacket {
                works: vec![work],
                num_buffers_used: 0,
                len: 0,
                cap,
            });
        }
        Ok(RxId(idx.into()))
    }

    /// Take the RX work items for the given packet, returning each with
    /// its individual used byte count. The caller is responsible for
    /// completing each descriptor via the queue.
    ///
    /// Per the virtio spec, all buffers except the last must be completely
    /// filled to their full writable length.
    #[must_use = "caller must complete the returned work via VirtioQueue::complete"]
    pub fn take_rx_work(&mut self, rx_id: RxId) -> Vec<(VirtioQueueCallbackWork, u32)> {
        let mut packet = self.rx_packets[rx_id.0 as usize]
            .take()
            .expect("valid packet index");

        if packet.len == 0 {
            tracelimit::warn_ratelimited!("dropping RX buffer: header not written");
            return packet.works.drain(..).map(|w| (w, 0)).collect();
        }

        let num_used = packet.num_buffers_used as usize;
        assert!(num_used >= 1);
        assert!(num_used <= packet.works.len());

        // Return unused works to the spare pool.
        if self.mrg_rxbuf {
            for work in packet.works.drain(num_used..) {
                self.spare_works.push_back(work);
            }
        }

        let header_bytes = header_size() as u32;
        let total_bytes = packet.len + header_bytes;
        let mut remaining = total_bytes;
        let mut result = Vec::with_capacity(num_used);

        for work in packet.works.drain(..) {
            let work_cap = work.get_payload_length(true) as u32;
            let bytes = remaining.min(work_cap);
            remaining -= bytes;
            result.push((work, bytes));
        }

        result
    }

    /// Pull additional descriptors into a packet's work chain to
    /// accommodate data that exceeds the current capacity. First drains
    /// the spare pool, then steals from other queued `rx_packets`.
    fn expand_packet_for_data(&mut self, target_idx: usize, needed: u32) {
        let mut additional_cap = 0u32;

        // First, drain the spare pool.
        while additional_cap < needed {
            let Some(spare) = self.spare_works.pop_front() else {
                break;
            };
            let spare_cap = spare.get_payload_length(true) as u32;
            additional_cap += spare_cap;
            let packet = self.rx_packets[target_idx].as_mut().unwrap();
            packet.cap += spare_cap;
            packet.works.push(spare);
        }

        // If still not enough, steal from other queued RxPackets.
        if additional_cap < needed {
            for i in 0..self.rx_packets.len() {
                if additional_cap >= needed {
                    break;
                }
                if i == target_idx {
                    continue;
                }
                if let Some(mut donor) = self.rx_packets[i].take() {
                    for work in donor.works.drain(..) {
                        let work_cap = work.get_payload_length(true) as u32;
                        additional_cap += work_cap;
                        let packet = self.rx_packets[target_idx].as_mut().unwrap();
                        packet.cap += work_cap;
                        packet.works.push(work);
                        if additional_cap >= needed {
                            break;
                        }
                    }
                    // Any remaining works from the donor go to spares.
                    for work in donor.works.drain(..) {
                        self.spare_works.push_back(work);
                    }
                }
            }
        }
    }
}

impl BufferAccess for VirtioWorkPool {
    fn guest_memory(&self) -> &GuestMemory {
        &self.mem
    }

    fn write_data(&mut self, id: RxId, data: &[u8]) {
        let data_len = data.len() as u32;

        // If MRG_RXBUF and data exceeds current capacity, expand by
        // pulling additional descriptors from spares or other packets.
        if self.mrg_rxbuf {
            let cap = self.rx_packets[id.0 as usize]
                .as_ref()
                .expect("invalid buffer index")
                .cap;
            if data_len > cap {
                let needed = data_len - cap;
                self.expand_packet_for_data(id.0 as usize, needed);
            }
        }

        let packet = self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index");

        // Scatter-write data across the descriptor chain.
        // First work: data starts after the header.
        // Subsequent works: data starts at offset 0.
        let mut data_offset = 0usize;
        let header_bytes = header_size() as u64;

        for (work_idx, work) in packet.works.iter().enumerate() {
            if data_offset >= data.len() {
                break;
            }
            let write_offset = if work_idx == 0 { header_bytes } else { 0 };
            let work_writable = work.get_payload_length(true);
            let available = work_writable.saturating_sub(write_offset) as usize;
            let chunk_len = (data.len() - data_offset).min(available);
            let chunk = &data[data_offset..data_offset + chunk_len];
            if let Err(err) = work.write_at_offset(write_offset, &self.mem, chunk) {
                tracelimit::warn_ratelimited!(
                    len = chunk.len(),
                    error = &err as &dyn std::error::Error,
                    "rx memory write failure"
                );
                return;
            }
            data_offset += chunk_len;
        }
    }

    fn push_guest_addresses(&self, id: RxId, buf: &mut Vec<RxBufferSegment>) {
        let packet = self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index");
        for work in &packet.works {
            buf.extend(
                work.payload
                    .iter()
                    .filter(|x| x.writeable)
                    .map(|p| RxBufferSegment {
                        gpa: p.address,
                        len: p.length,
                    }),
            );
        }
    }

    fn capacity(&self, id: RxId) -> u32 {
        let packet = self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index");
        if self.mrg_rxbuf {
            // With MRG_RXBUF, the effective capacity includes all
            // spare works and all other queued rx_packets that can be
            // borrowed during write_data.
            let mut total = packet.cap;
            for spare in &self.spare_works {
                total += spare.get_payload_length(true) as u32;
            }
            for (i, slot) in self.rx_packets.iter().enumerate() {
                if i == id.0 as usize {
                    continue;
                }
                if let Some(other) = slot {
                    for work in &other.works {
                        total += work.get_payload_length(true) as u32;
                    }
                }
            }
            total
        } else {
            packet.cap
        }
    }

    fn write_header(&mut self, id: RxId, metadata: &RxMetadata) {
        assert_eq!(metadata.offset, 0);
        assert!(metadata.len > 0);

        // Map RxMetadata checksum state to virtio-net header flags.
        let data_valid = metadata.ip_checksum.is_valid() && metadata.l4_checksum.is_valid();
        let needs_csum = metadata.l4_checksum == RxChecksumState::NeedsCsum;

        let flags = VirtioNetHeaderFlags::new()
            .with_data_valid(data_valid)
            .with_needs_csum(needs_csum);

        // Map GRO metadata to virtio-net header GSO fields.
        let (gso_type, gso_size, hdr_len) = match &metadata.gso {
            Some(gso) => {
                let protocol = match gso.gso_type {
                    RxGsoType::TcpV4 => VirtioNetHeaderGsoProtocol::TCPV4,
                    RxGsoType::TcpV6 => VirtioNetHeaderGsoProtocol::TCPV6,
                    RxGsoType::Udp => VirtioNetHeaderGsoProtocol::UDP,
                };
                (
                    VirtioNetHeaderGso::new().with_protocol(protocol),
                    gso.gso_size,
                    gso.hdr_len,
                )
            }
            None => (VirtioNetHeaderGso::new(), 0, 0),
        };

        // Map partial checksum offload parameters.
        let (csum_start, csum_offset) = match &metadata.csum_offload {
            Some(csum) => (csum.csum_start, csum.csum_offset),
            None => (0, 0),
        };

        // Compute how many buffers are actually needed for this packet.
        let num_buffers = if self.mrg_rxbuf {
            let packet = self.rx_packets[id.0 as usize]
                .as_ref()
                .expect("invalid buffer index");
            compute_num_buffers(packet, metadata.len as u32)
        } else {
            1
        };

        let virtio_net_header = VirtioNetHeader {
            flags: flags.into(),
            gso_type: gso_type.into(),
            hdr_len,
            gso_size,
            csum_start,
            csum_offset,
            num_buffers,
            ..FromZeros::new_zeroed()
        };
        let packet = self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index");
        if let Err(err) =
            packet.works[0].write(&self.mem, &virtio_net_header.as_bytes()[..header_size()])
        {
            tracelimit::warn_ratelimited!(
                error = &err as &dyn std::error::Error,
                "failure writing header"
            );
            return;
        }
        assert!(
            metadata.len <= packet.cap as usize,
            "packet len {} exceeds buffer capacity {}",
            metadata.len,
            packet.cap
        );
        packet.len = metadata.len as u32;
        packet.num_buffers_used = num_buffers;
    }
}

/// Compute how many buffers in the chain are needed to hold `data_len` bytes
/// of payload (not counting the header).
fn compute_num_buffers(packet: &RxPacket, data_len: u32) -> u16 {
    let header_bytes = header_size() as u32;
    let mut remaining = data_len;
    let mut count: u16 = 0;

    for (i, work) in packet.works.iter().enumerate() {
        if remaining == 0 {
            break;
        }
        count += 1;
        let work_cap = work.get_payload_length(true) as u32;
        let usable = if i == 0 {
            work_cap.saturating_sub(header_bytes)
        } else {
            work_cap
        };
        remaining = remaining.saturating_sub(usable);
    }

    // At minimum 1 buffer (for the header).
    count.max(1)
}
