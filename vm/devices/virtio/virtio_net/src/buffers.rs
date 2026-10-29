// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::VirtioNetHeader;
use crate::VirtioNetHeaderFlags;
use crate::header_size;
use guestmem::GuestMemory;
use inspect::Inspect;
use net_backend::BufferAccess;
use net_backend::ETHERNET_HEADER_LEN;
use net_backend::RxBufferSegment;
use net_backend::RxId;
use net_backend::RxMetadata;
use std::num::NonZeroU16;
use virtio::VirtioQueueCallbackWork;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

struct RxPacket {
    work: VirtioQueueCallbackWork,
    used_len: Option<u32>,
    cap: u32,
    write_failed: bool,
}

/// Holds virtio buffers available for a network backend to send data to the client.
#[derive(Inspect)]
#[inspect(extra = "Self::inspect_extra")]
pub struct VirtioWorkPool {
    mem: GuestMemory,
    mergeable_rx_buffers: bool,
    #[inspect(skip)]
    rx_packets: Vec<Option<RxPacket>>,
    rx_capacity_drops: u64,
    rx_memory_write_drops: u64,
    rx_incomplete_drops: u64,
}

impl VirtioWorkPool {
    fn inspect_extra(&self, resp: &mut inspect::Response<'_>) {
        resp.field(
            "pending_rx_packets",
            self.rx_packets.iter().filter(|p| p.is_some()).count(),
        )
        .field("rx_capacity_drops", self.rx_capacity_drops)
        .field("rx_memory_write_drops", self.rx_memory_write_drops)
        .field("rx_incomplete_drops", self.rx_incomplete_drops);
    }

    /// Create a new instance.
    pub fn new(mem: GuestMemory, queue_size: u16, mergeable_rx_buffers: bool) -> Self {
        Self {
            mem,
            mergeable_rx_buffers,
            rx_packets: (0..queue_size).map(|_| None).collect(),
            rx_capacity_drops: 0,
            rx_memory_write_drops: 0,
            rx_incomplete_drops: 0,
        }
    }

    fn header_size(&self) -> usize {
        header_size()
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
    /// Returns `Err` with the work item if the buffer is smaller than the
    /// virtio-net header and should be dropped in order.
    pub fn queue_work(
        &mut self,
        work: VirtioQueueCallbackWork,
    ) -> Result<RxId, VirtioQueueCallbackWork> {
        let idx = work.descriptor_index();
        let header_size = self.header_size();
        let packet = &mut self.rx_packets[idx as usize];
        assert!(packet.is_none(), "RX descriptor {idx} is already tracked");
        let payload_length = work.get_payload_length(true) as u32;
        let Some(cap) = payload_length
            .checked_sub(header_size as u32)
            .filter(|&cap| self.mergeable_rx_buffers || cap >= ETHERNET_HEADER_LEN)
        else {
            tracelimit::warn_ratelimited!(
                len = payload_length,
                "dropping RX buffer: insufficient capacity"
            );
            return Err(work);
        };
        *packet = Some(RxPacket {
            used_len: None,
            cap,
            write_failed: false,
            work,
        });
        Ok(RxId(idx.into()))
    }

    /// Take the RX work item for the given packet, returning it with the
    /// computed payload length. The caller is responsible for completing
    /// the descriptor via the queue.
    #[must_use = "caller must complete the returned work via VirtioQueue::complete"]
    pub fn take_rx_work(&mut self, rx_id: RxId) -> (VirtioQueueCallbackWork, u32, bool) {
        let packet = self.rx_packets[rx_id.0 as usize]
            .take()
            .expect("valid packet index");
        let dropped = packet.write_failed || packet.used_len.is_none();
        let used_len = if dropped {
            if !packet.write_failed {
                self.rx_incomplete_drops += 1;
                tracelimit::warn_ratelimited!("dropping RX buffer: packet write not completed");
            }
            0
        } else {
            packet.used_len.unwrap()
        };
        (packet.work, used_len, dropped)
    }

    fn write_rx_header(&mut self, id: RxId, metadata: &RxMetadata, buffer_count: NonZeroU16) {
        let checksum = metadata.offload.checksum_metadata();
        let needs_checksum = checksum.is_some();
        let data_valid =
            !needs_checksum && metadata.ip_checksum.is_valid() && metadata.l4_checksum.is_valid();
        let flags = VirtioNetHeaderFlags::new()
            .with_needs_csum(needs_checksum)
            .with_data_valid(data_valid);
        let (gso_type, hdr_len, gso_size) = if let Some(gso) = metadata.offload.gso() {
            let protocol = match gso.protocol {
                net_backend::RxGsoProtocol::TcpV4 => crate::VirtioNetHeaderGsoProtocol::TCPV4,
                net_backend::RxGsoProtocol::TcpV6 => crate::VirtioNetHeaderGsoProtocol::TCPV6,
            };
            (
                crate::VirtioNetHeaderGso::new()
                    .with_protocol(protocol)
                    .into_bits(),
                gso.header_len,
                gso.max_segment_size,
            )
        } else {
            (0, 0, 0)
        };
        let (csum_start, csum_offset) = checksum
            .map(|checksum| (checksum.start, checksum.offset))
            .unwrap_or_default();
        let header = VirtioNetHeader {
            flags: flags.into(),
            gso_type,
            hdr_len,
            gso_size,
            csum_start,
            csum_offset,
            num_buffers: buffer_count.get(),
            ..FromZeros::new_zeroed()
        };
        let header_size = self.header_size();
        let packet = self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index");
        if let Err(err) = packet
            .work
            .write(&self.mem, &header.as_bytes()[..header_size])
        {
            tracelimit::warn_ratelimited!(
                error = &err as &dyn std::error::Error,
                "dropping RX packet after guest header write failure"
            );
            self.fail_memory_write(id);
        }
    }

    fn fail_capacity(&mut self, id: RxId, packet_len: usize, capacity: u32) {
        self.rx_capacity_drops += 1;
        self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index")
            .write_failed = true;
        tracelimit::warn_ratelimited!(
            packet_len,
            capacity,
            "dropping RX packet larger than guest buffer"
        );
    }

    fn fail_memory_write(&mut self, id: RxId) {
        self.rx_memory_write_drops += 1;
        self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index")
            .write_failed = true;
    }
}

impl BufferAccess for VirtioWorkPool {
    fn guest_memory(&self) -> &GuestMemory {
        &self.mem
    }

    fn write_data(&mut self, id: RxId, data: &[u8]) {
        let header_size = self.header_size();
        let capacity = self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index")
            .cap;
        if data.len() > capacity as usize {
            self.fail_capacity(id, data.len(), capacity);
            return;
        }
        let result = self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index")
            .work
            .write_at_offset(header_size as u64, &self.mem, data);
        if let Err(err) = result {
            tracelimit::warn_ratelimited!(
                len = data.len(),
                error = &err as &dyn std::error::Error,
                "dropping RX packet after guest memory write failure"
            );
            self.fail_memory_write(id);
        }
    }

    fn write_packet(&mut self, id: RxId, metadata: &RxMetadata, data: &[u8]) {
        if metadata.len != data.len() {
            self.rx_incomplete_drops += 1;
            self.rx_packets[id.0 as usize]
                .as_mut()
                .expect("invalid buffer index")
                .write_failed = true;
            tracelimit::warn_ratelimited!(
                metadata_len = metadata.len,
                data_len = data.len(),
                "dropping RX packet with inconsistent metadata length"
            );
            return;
        }
        self.write_data(id, data);
        self.write_header(id, metadata);
    }

    fn write_packet_segments(&mut self, id: RxId, metadata: &RxMetadata, segments: &[&[u8]]) {
        let total_len = segments.iter().map(|segment| segment.len()).sum::<usize>();
        if metadata.len != total_len {
            self.rx_incomplete_drops += 1;
            self.rx_packets[id.0 as usize]
                .as_mut()
                .expect("invalid buffer index")
                .write_failed = true;
            tracelimit::warn_ratelimited!(
                metadata_len = metadata.len,
                data_len = total_len,
                "dropping RX packet with inconsistent segment length"
            );
            return;
        }
        let capacity = self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index")
            .cap;
        if total_len > capacity as usize {
            self.fail_capacity(id, total_len, capacity);
            return;
        }

        let mut offset = self.header_size() as u64;
        for segment in segments {
            let result = self.rx_packets[id.0 as usize]
                .as_mut()
                .expect("invalid buffer index")
                .work
                .write_at_offset(offset, &self.mem, segment);
            if let Err(err) = result {
                tracelimit::warn_ratelimited!(
                    len = segment.len(),
                    error = &err as &dyn std::error::Error,
                    "dropping RX packet after guest memory write failure"
                );
                self.fail_memory_write(id);
                return;
            }
            offset += segment.len() as u64;
        }
        self.write_header(id, metadata);
    }

    fn write_packet_across_multiple_buffers(
        &mut self,
        ids: &[RxId],
        metadata: &RxMetadata,
        segments: &[&[u8]],
    ) -> bool {
        if !self.mergeable_rx_buffers {
            return false;
        }
        let Ok(buffer_count) = u16::try_from(ids.len()) else {
            return false;
        };
        let Some(buffer_count) = NonZeroU16::new(buffer_count) else {
            return false;
        };
        let packet_len: usize = segments.iter().map(|segment| segment.len()).sum();
        let total_capacity: usize = ids
            .iter()
            .enumerate()
            .map(|(index, &id)| self.packet_buffer_capacity(id, index) as usize)
            .sum();
        if packet_len != metadata.len || packet_len > total_capacity {
            return false;
        }

        let mut segment_index = 0;
        let mut segment_offset = 0;
        for (buffer_index, &id) in ids.iter().enumerate() {
            let data_offset = if buffer_index == 0 {
                self.header_size()
            } else {
                0
            };
            let capacity = self.packet_buffer_capacity(id, buffer_index) as usize;
            let mut written = 0;
            while written < capacity && segment_index < segments.len() {
                let segment = &segments[segment_index][segment_offset..];
                let write_len = segment.len().min(capacity - written);
                let packet = self.rx_packets[id.0 as usize]
                    .as_mut()
                    .expect("invalid buffer index");
                if let Err(err) = packet.work.write_at_offset(
                    (data_offset + written) as u64,
                    &self.mem,
                    &segment[..write_len],
                ) {
                    tracelimit::warn_ratelimited!(
                        len = write_len,
                        error = &err as &dyn std::error::Error,
                        "rx memory write failure"
                    );
                }
                written += write_len;
                segment_offset += write_len;
                if segment_offset == segments[segment_index].len() {
                    segment_index += 1;
                    segment_offset = 0;
                }
            }
            self.rx_packets[id.0 as usize]
                .as_mut()
                .expect("invalid buffer index")
                .used_len = Some((data_offset + written) as u32);
        }
        self.write_rx_header(ids[0], metadata, buffer_count);
        true
    }

    fn push_guest_addresses(&self, id: RxId, buf: &mut Vec<RxBufferSegment>) {
        let packet = self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index");
        buf.extend(
            packet
                .work
                .payload
                .iter()
                .filter(|x| x.writeable)
                .map(|p| RxBufferSegment {
                    gpa: p.address,
                    len: p.length,
                }),
        );
    }

    fn capacity(&self, id: RxId) -> u32 {
        self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index")
            .cap
    }

    fn supports_multiple_buffers(&self) -> bool {
        self.mergeable_rx_buffers
    }

    fn packet_buffer_capacity(&self, id: RxId, buffer_index: usize) -> u32 {
        let capacity = self.capacity(id);
        if buffer_index == 0 {
            capacity
        } else if self.mergeable_rx_buffers {
            capacity + self.header_size() as u32
        } else {
            0
        }
    }

    fn write_header(&mut self, id: RxId, metadata: &RxMetadata) {
        assert_eq!(metadata.offset, 0);
        assert!(metadata.len > 0);

        let packet = self.rx_packets[id.0 as usize]
            .as_ref()
            .expect("invalid buffer index");
        if packet.write_failed {
            return;
        }
        if metadata.len > packet.cap as usize {
            let capacity = packet.cap;
            self.fail_capacity(id, metadata.len, capacity);
            return;
        }

        self.write_rx_header(id, metadata, NonZeroU16::MIN);
        self.rx_packets[id.0 as usize]
            .as_mut()
            .expect("invalid buffer index")
            .used_len = Some(metadata.len as u32 + self.header_size() as u32);
    }
}
