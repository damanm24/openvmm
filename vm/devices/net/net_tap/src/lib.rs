// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A TAP interface based endpoint.

#![cfg(unix)]
#![expect(missing_docs)]

pub mod resolver;
pub mod tap;

use async_trait::async_trait;
use futures::io::AsyncRead;
use inspect::InspectMut;
use net_backend::BufferAccess;
use net_backend::Endpoint;
use net_backend::L4Protocol;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxChecksumState;
use net_backend::RxCsumOffload;
use net_backend::RxGso;
use net_backend::RxGsoType;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::RxOffloadConfig;
use net_backend::TxError;
use net_backend::TxId;
use net_backend::TxMetadata;
use net_backend::TxOffloadSupport;
use net_backend::TxSegment;
use net_backend::linearize;
use net_backend::next_packet;
use pal_async::driver::Driver;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

// TODO: These virtio net header types duplicate definitions in virtio_net.
// Consider extracting a shared `virtio_net_header` crate if more consumers
// appear (e.g., vhost-user).
mod vnet_hdr {
    use bitfield_struct::bitfield;
    use zerocopy::FromBytes;
    use zerocopy::Immutable;
    use zerocopy::IntoBytes;
    use zerocopy::KnownLayout;

    /// Flags in the virtio network header.
    #[bitfield(u8)]
    #[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
    pub struct VirtioNetHdrFlags {
        pub needs_csum: bool,
        pub data_valid: bool,
        #[bits(6)]
        _reserved: u8,
    }

    /// GSO type bitfield in the virtio network header.
    #[bitfield(u8)]
    #[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
    pub struct VirtioNetHdrGso {
        #[bits(3)]
        pub protocol: VirtioNetHdrGsoProtocol,
        #[bits(4)]
        _reserved: u8,
        pub ecn: bool,
    }

    open_enum::open_enum! {
        /// GSO protocol in the virtio network header.
        #[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
        pub enum VirtioNetHdrGsoProtocol: u8 {
            NONE = 0,
            TCPV4 = 1,
            UDP = 3,
            TCPV6 = 4,
        }
    }

    impl VirtioNetHdrGsoProtocol {
        const fn from_bits(bits: u8) -> Self {
            Self(bits)
        }

        const fn into_bits(self) -> u8 {
            self.0
        }
    }

    /// The virtio network header prepended to packets when `IFF_VNET_HDR` is set.
    /// This is the 12-byte v1 format (without hash fields).
    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy, IntoBytes, Immutable, KnownLayout, FromBytes)]
    pub struct VirtioNetHdr {
        pub flags: VirtioNetHdrFlags,
        pub gso_type: VirtioNetHdrGso,
        pub hdr_len: u16,
        pub gso_size: u16,
        pub csum_start: u16,
        pub csum_offset: u16,
        pub num_buffers: u16,
    }
}
pub use vnet_hdr::*;

/// An endpoint based on a TAP interface.
pub struct TapEndpoint {
    tap: Arc<Mutex<Option<tap::Tap>>>,
}

impl TapEndpoint {
    pub fn new(tap: tap::Tap) -> Result<Self, tap::Error> {
        // RX offload configuration (TUN_F_* flags) is deferred to
        // get_queues(), where the frontend can pass an RxOffloadConfig
        // describing its capabilities. We set offloads to 0 here as a
        // safe default in case the fd had non-zero offloads from a
        // previous user.
        tap.set_offloads(0)?;

        Ok(Self {
            tap: Arc::new(Mutex::new(Some(tap))),
        })
    }
}

impl InspectMut for TapEndpoint {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond();
    }
}

#[async_trait]
impl Endpoint for TapEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "tap"
    }

    async fn get_queues(
        &mut self,
        mut config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn Queue>>,
    ) -> anyhow::Result<()> {
        assert_eq!(config.len(), 1);
        let config = config.drain(..).next().unwrap();

        // Configure RX offloads on the TAP fd based on what the frontend
        // can handle. The TUN_F_* flags are the TAP equivalent of
        // VIRTIO_NET_F_GUEST_*: they tell the kernel that our reader can
        // handle partial checksums (NEEDS_CSUM) and unsegmented GSO
        // packets.
        //
        // When no offloads are requested, the kernel completes all
        // checksums and segments all GSO packets before delivering them.
        let rx_offload_flags = rx_offload_config_to_tun_flags(config.rx_offloads.as_ref());
        {
            let tap_guard = self.tap.lock();
            let tap = tap_guard.as_ref().expect("tap device available");
            tap.set_offloads(rx_offload_flags)?;
        }

        queues.push(Box::new(TapQueue::new(
            config.driver.as_ref(),
            self.tap.clone(),
        )?));
        Ok(())
    }

    async fn stop(&mut self) {
        assert!(self.tap.lock().is_some(), "queue has not been dropped");
    }

    fn is_ordered(&self) -> bool {
        true
    }

    fn tx_offload_support(&self) -> TxOffloadSupport {
        TxOffloadSupport {
            // TAP does not support IPv4 header checksum offload, but netvsp
            // (NDIS/TAP) guests require it for LSOv4. It's relatively cheap for
            // us to compute in software, so report it. Virtio-net won't use it.
            ipv4_header: true,
            tcp: true,
            udp: true,
            tso: true,
        }
    }
}

struct TapQueue {
    slot: Arc<Mutex<Option<tap::Tap>>>,
    tap: Option<tap::PolledTap>,
    inner: Inner,
    buffer: Box<[u8]>,
}

struct Inner {
    rx_free: VecDeque<RxId>,
    rx_ready: VecDeque<RxId>,
}

impl InspectMut for TapQueue {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond();
    }
}

impl Drop for TapQueue {
    fn drop(&mut self) {
        if let Some(tap) = self.tap.take() {
            *self.slot.lock() = Some(tap.into_inner());
        }
    }
}

impl TapQueue {
    fn new(driver: &dyn Driver, slot: Arc<Mutex<Option<tap::Tap>>>) -> anyhow::Result<Self> {
        let tap = slot.lock().take().expect("queue is already in use");
        let tap = tap.polled(driver)?;
        Ok(Self {
            slot,
            tap: Some(tap),
            inner: Inner {
                rx_free: VecDeque::new(),
                rx_ready: VecDeque::new(),
            },
            buffer: vec![0; 65535 + size_of::<VirtioNetHdr>()].into_boxed_slice(),
        })
    }
}

impl Queue for TapQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, pool: &mut dyn BufferAccess) -> Poll<()> {
        if !self.inner.rx_ready.is_empty() {
            return Poll::Ready(());
        }

        let tap = if let Some(tap) = self.tap.as_mut() {
            tap
        } else {
            return Poll::Pending;
        };

        while let Some(&rx) = self.inner.rx_free.front() {
            match Pin::new(&mut *tap).poll_read(cx, &mut self.buffer) {
                Poll::Ready(Ok(read_len)) => {
                    if read_len < size_of::<VirtioNetHdr>() {
                        tracing::warn!(read_len, "tap read too short for vnet header");
                        break;
                    }
                    let (hdr, _) =
                        VirtioNetHdr::read_from_prefix(&self.buffer[..read_len]).unwrap();
                    let rx_meta = parse_vnet_hdr(&hdr);
                    let frame_start = size_of::<VirtioNetHdr>();
                    let frame_len = read_len - size_of::<VirtioNetHdr>();
                    pool.write_packet(
                        rx,
                        &RxMetadata {
                            offset: 0,
                            len: frame_len,
                            ..rx_meta
                        },
                        &self.buffer[frame_start..read_len],
                    );

                    self.inner.rx_ready.push_back(rx);
                    self.inner.rx_free.pop_front();
                }
                Poll::Ready(Err(err)) => {
                    tracing::warn!(error = &err as &dyn std::error::Error, "tap rx error");
                    break;
                }
                Poll::Pending => break,
            }
        }

        if !self.inner.rx_ready.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.inner.rx_free.extend(done);
    }

    fn rx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        // Send to the guest any packets that might have been read during poll_ready().
        let n = std::cmp::min(self.inner.rx_ready.len(), packets.len());
        for (done, id) in packets[..n].iter_mut().zip(self.inner.rx_ready.drain(..n)) {
            *done = id;
        }
        Ok(n)
    }

    fn tx_avail(
        &mut self,
        pool: &mut dyn BufferAccess,
        mut segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        let n = segments.len();
        // Synchronously send packets received from the guest to host's network.
        if let Some(tap) = self.tap.as_mut() {
            while !segments.is_empty() {
                let (meta, _segs, _rest) = next_packet(segments);
                let hdr = build_vnet_hdr(meta);
                let hdr_bytes = hdr.as_bytes();
                let mut packet = linearize(pool, &mut segments)?;

                // Fix up the IPv4 header checksum when the frontend
                // requested IPv4 header checksum offload.
                //
                // The virtio vnet header has no mechanism for IPv4 header
                // checksum offload, so we compute it in software. This
                // also covers NDIS/netvsp LSO packets, where the guest
                // driver zeroes ip_check (NDIS convention); the kernel's
                // TAP GSO engine requires a valid checksum to segment
                // the packet correctly.
                if meta.flags.offload_ip_header_checksum() && meta.flags.is_ipv4() {
                    fixup_ipv4_header_checksum(&mut packet, meta.l2_len as usize);
                }

                let bufs = [
                    std::io::IoSlice::new(hdr_bytes),
                    std::io::IoSlice::new(&packet),
                ];
                match tap.write_vectored(&bufs) {
                    Ok(bytes_written) => {
                        assert_eq!(
                            bytes_written,
                            hdr_bytes.len() + packet.len(),
                            "TAP should never partial write"
                        );
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        // dropped packet: buffer is full

                        // TODO: return partial transmit here. This relies on
                        // remembering this condition and polling for POLLOUT in
                        // poll_ready().
                    }
                    Err(err) if err.raw_os_error() == Some(libc::EIO) => {
                        // dropped packet: interface is not up
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = &err as &dyn std::error::Error,
                            "write to TAP interface failed"
                        );
                    }
                }
            }
        }
        let completed_synchronously = true;
        Ok((completed_synchronously, n))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        _done: &mut [TxId],
    ) -> Result<usize, TxError> {
        // Packets are sent synchronously so there is no no need to check here if
        // sending has been completed.
        Ok(0)
    }
}

/// Compute and write the IPv4 header checksum in place.
///
/// The IPv4 header length is derived from the IHL field in the packet itself
/// rather than trusting guest-provided metadata (`l3_len`), since that value
/// crosses a trust boundary. The IHL value is clamped to 20..60 bytes (the
/// valid range per RFC 791) and bounded by the packet length.
///
/// The virtio net header has no way to request IPv4 header checksum offload,
/// and in bridged configurations the kernel does not recompute it. When
/// netvsp (Windows/NDIS guests) sets `offload_ip_header_checksum`, we must
/// compute it in software before handing the frame to TAP.
fn fixup_ipv4_header_checksum(packet: &mut [u8], l2_len: usize) {
    // Need at least the minimum IPv4 header to read IHL.
    if packet.len() < l2_len + 20 {
        return;
    }
    // Derive header length from the IHL field in the packet, not from
    // guest-provided metadata.
    let ihl_bytes = ((packet[l2_len] & 0x0f) as usize) * 4;
    if !(20..=60).contains(&ihl_bytes) {
        return;
    }
    if packet.len() < l2_len + ihl_bytes {
        return;
    }
    let ip_hdr = &mut packet[l2_len..l2_len + ihl_bytes];
    // Zero the checksum field (bytes 10-11) before computing.
    ip_hdr[10] = 0;
    ip_hdr[11] = 0;
    // RFC 1071 ones-complement sum over the header.
    let mut sum: u32 = 0;
    for chunk in ip_hdr.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    let [hi, lo] = checksum.to_be_bytes();
    packet[l2_len + 10] = hi;
    packet[l2_len + 11] = lo;
}

/// Build a `VirtioNetHdr` from transmit metadata for the TAP device.
///
/// The virtio net header uses fully general `csum_start` / `csum_offset` fields
/// that can describe any protocol, whereas [`TxMetadata`] uses protocol-specific
/// flags (`offload_tcp_checksum`, `offload_udp_checksum`). This function bridges
/// the two by computing `csum_start` from `l2_len + l3_len` and hardcoding
/// `csum_offset` to the known offset of the checksum field within each protocol
/// header (16 for TCP, 6 for UDP).
///
/// For TSO, `gso_type` is set based on the `is_ipv4`/`is_ipv6` flags, and
/// `NEEDS_CSUM` is always set since the kernel requires the checksum to be
/// partially computed when performing segmentation.
///
/// If no offload flags are set, an all-zero header is returned, which tells the
/// TAP device that the packet requires no special handling.
fn build_vnet_hdr(meta: &TxMetadata) -> VirtioNetHdr {
    if meta.flags.offload_tcp_segmentation() {
        let protocol = if meta.flags.is_ipv4() {
            VirtioNetHdrGsoProtocol::TCPV4
        } else {
            VirtioNetHdrGsoProtocol::TCPV6
        };
        VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_needs_csum(true),
            gso_type: VirtioNetHdrGso::new().with_protocol(protocol),
            hdr_len: meta.l2_len as u16 + meta.l3_len + meta.l4_len as u16,
            gso_size: meta.max_tcp_segment_size,
            csum_start: meta.l2_len as u16 + meta.l3_len,
            csum_offset: 16, // TCP checksum field offset
            num_buffers: 0,
        }
    } else if meta.flags.offload_tcp_checksum() {
        VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_needs_csum(true),
            gso_type: VirtioNetHdrGso::new(),
            hdr_len: 0,
            gso_size: 0,
            csum_start: meta.l2_len as u16 + meta.l3_len,
            csum_offset: 16, // TCP checksum field offset
            num_buffers: 0,
        }
    } else if meta.flags.offload_udp_checksum() {
        VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_needs_csum(true),
            gso_type: VirtioNetHdrGso::new(),
            hdr_len: 0,
            gso_size: 0,
            csum_start: meta.l2_len as u16 + meta.l3_len,
            csum_offset: 6, // UDP checksum field offset
            num_buffers: 0,
        }
    } else {
        VirtioNetHdr::default()
    }
}

/// Map [`RxOffloadConfig`] to Linux `TUN_F_*` flags.
///
/// The `TUN_F_*` flags are the TAP equivalent of `VIRTIO_NET_F_GUEST_*`:
/// they tell the kernel that our reader can handle partial checksums
/// (`NEEDS_CSUM`) and unsegmented GSO packets. When the frontend has
/// negotiated the corresponding features with the guest, we enable
/// them on the TAP fd so the kernel can deliver GRO-merged packets
/// instead of segmenting them in software.
///
/// `TUN_F_CSUM` is a prerequisite for all GSO flags — the kernel
/// requires it because GSO packets always arrive with partial checksums.
fn rx_offload_config_to_tun_flags(config: Option<&RxOffloadConfig>) -> u32 {
    let Some(config) = config else {
        return 0;
    };
    let mut flags = 0u32;
    if config.checksum {
        flags |= linux_net_bindings::gen_if_tun::TUN_F_CSUM;
    }
    // TSO/UFO require TUN_F_CSUM as a prerequisite.
    if config.checksum && config.tcp4 {
        flags |= linux_net_bindings::gen_if_tun::TUN_F_TSO4;
    }
    if config.checksum && config.tcp6 {
        flags |= linux_net_bindings::gen_if_tun::TUN_F_TSO6;
    }
    if config.checksum && config.udp {
        flags |= linux_net_bindings::gen_if_tun::TUN_F_UFO;
    }
    flags
}

/// Parse a `VirtioNetHdr` from the TAP device into receive metadata.
///
/// Handles all vnet header states:
/// - `DATA_VALID` flag → checksums validated by the kernel
/// - `NEEDS_CSUM` flag → partial checksum requiring guest completion
///   (only delivered when `TUN_F_CSUM` offload is enabled)
/// - GSO types → GRO-merged packet metadata
///   (only delivered when `TUN_F_TSO*`/`TUN_F_UFO` offloads are enabled)
/// - Default → no checksum information
fn parse_vnet_hdr(hdr: &VirtioNetHdr) -> RxMetadata {
    let l4_protocol = match hdr.gso_type.protocol() {
        VirtioNetHdrGsoProtocol::TCPV4 | VirtioNetHdrGsoProtocol::TCPV6 => L4Protocol::Tcp,
        VirtioNetHdrGsoProtocol::UDP => L4Protocol::Udp,
        _ => L4Protocol::Unknown,
    };

    let (ip_checksum, l4_checksum, csum_offload) = if hdr.flags.needs_csum() {
        // Kernel is telling us the checksum field contains a partial
        // pseudo-header sum. Propagate csum_start/csum_offset so the
        // frontend can relay them to the guest.
        (
            RxChecksumState::Unknown,
            RxChecksumState::NeedsCsum,
            Some(RxCsumOffload {
                csum_start: hdr.csum_start,
                csum_offset: hdr.csum_offset,
            }),
        )
    } else if hdr.flags.data_valid() {
        (RxChecksumState::Good, RxChecksumState::Good, None)
    } else {
        (RxChecksumState::Unknown, RxChecksumState::Unknown, None)
    };

    let gso = match hdr.gso_type.protocol() {
        VirtioNetHdrGsoProtocol::TCPV4 if hdr.gso_size > 0 => Some(RxGso {
            gso_type: RxGsoType::TcpV4,
            gso_size: hdr.gso_size,
            hdr_len: hdr.hdr_len,
        }),
        VirtioNetHdrGsoProtocol::TCPV6 if hdr.gso_size > 0 => Some(RxGso {
            gso_type: RxGsoType::TcpV6,
            gso_size: hdr.gso_size,
            hdr_len: hdr.hdr_len,
        }),
        VirtioNetHdrGsoProtocol::UDP if hdr.gso_size > 0 => Some(RxGso {
            gso_type: RxGsoType::Udp,
            gso_size: hdr.gso_size,
            hdr_len: hdr.hdr_len,
        }),
        _ => None,
    };

    RxMetadata {
        offset: 0,
        len: 0,
        ip_checksum,
        l4_checksum,
        l4_protocol,
        gso,
        csum_offload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_backend::TxFlags;

    #[test]
    fn vnet_hdr_from_tx_metadata_csum() {
        let meta = TxMetadata {
            flags: TxFlags::new()
                .with_offload_tcp_checksum(true)
                .with_is_ipv4(true),
            l2_len: 14,
            l3_len: 20,
            ..Default::default()
        };
        let hdr = build_vnet_hdr(&meta);
        assert!(hdr.flags.needs_csum());
        assert!(!hdr.flags.data_valid());
        assert_eq!(hdr.csum_start, 14 + 20);
        assert_eq!(hdr.csum_offset, 16);
        assert_eq!(hdr.gso_type.protocol(), VirtioNetHdrGsoProtocol::NONE);
        assert_eq!(hdr.gso_size, 0);
    }

    #[test]
    fn vnet_hdr_from_tx_metadata_tso() {
        let meta = TxMetadata {
            flags: TxFlags::new()
                .with_offload_tcp_segmentation(true)
                .with_offload_tcp_checksum(true)
                .with_is_ipv4(true),
            l2_len: 14,
            l3_len: 20,
            l4_len: 32,
            max_tcp_segment_size: 1460,
            ..Default::default()
        };
        let hdr = build_vnet_hdr(&meta);
        assert_eq!(hdr.gso_type.protocol(), VirtioNetHdrGsoProtocol::TCPV4);
        assert_eq!(hdr.gso_size, 1460);
        assert_eq!(hdr.hdr_len, 14 + 20 + 32);
        assert!(hdr.flags.needs_csum());
        assert!(!hdr.flags.data_valid());
        assert_eq!(hdr.csum_start, 14 + 20);
        assert_eq!(hdr.csum_offset, 16);
    }

    #[test]
    fn vnet_hdr_from_tx_metadata_none() {
        let meta = TxMetadata::default();
        let hdr = build_vnet_hdr(&meta);
        assert!(!hdr.flags.needs_csum());
        assert!(!hdr.flags.data_valid());
        assert_eq!(hdr.gso_type.protocol(), VirtioNetHdrGsoProtocol::NONE);
        assert_eq!(hdr.hdr_len, 0);
        assert_eq!(hdr.gso_size, 0);
        assert_eq!(hdr.csum_start, 0);
        assert_eq!(hdr.csum_offset, 0);
    }

    #[test]
    fn vnet_hdr_from_tx_metadata_udp_csum() {
        let meta = TxMetadata {
            flags: TxFlags::new()
                .with_offload_udp_checksum(true)
                .with_is_ipv4(true),
            l2_len: 14,
            l3_len: 20,
            ..Default::default()
        };
        let hdr = build_vnet_hdr(&meta);
        assert!(hdr.flags.needs_csum());
        assert_eq!(hdr.csum_start, 14 + 20);
        assert_eq!(hdr.csum_offset, 6);
        assert_eq!(hdr.gso_type.protocol(), VirtioNetHdrGsoProtocol::NONE);
    }

    #[test]
    fn rx_metadata_from_vnet_hdr_valid() {
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_data_valid(true),
            gso_type: VirtioNetHdrGso::new().with_protocol(VirtioNetHdrGsoProtocol::TCPV4),
            ..Default::default()
        };
        let meta = parse_vnet_hdr(&hdr);
        assert_eq!(meta.ip_checksum, RxChecksumState::Good);
        assert_eq!(meta.l4_checksum, RxChecksumState::Good);
        assert_eq!(meta.l4_protocol, L4Protocol::Tcp);
    }

    #[test]
    fn rx_metadata_from_vnet_hdr_needs_csum() {
        // When TUN_F_CSUM is enabled, the kernel sends NEEDS_CSUM with
        // csum_start/csum_offset.
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_needs_csum(true),
            gso_type: VirtioNetHdrGso::new().with_protocol(VirtioNetHdrGsoProtocol::TCPV6),
            csum_start: 54,
            csum_offset: 16,
            ..Default::default()
        };
        let meta = parse_vnet_hdr(&hdr);
        assert_eq!(meta.ip_checksum, RxChecksumState::Unknown);
        assert_eq!(meta.l4_checksum, RxChecksumState::NeedsCsum);
        assert_eq!(meta.l4_protocol, L4Protocol::Tcp);
        let csum = meta.csum_offload.unwrap();
        assert_eq!(csum.csum_start, 54);
        assert_eq!(csum.csum_offset, 16);
    }

    #[test]
    fn rx_metadata_from_vnet_hdr_none() {
        let hdr = VirtioNetHdr::default();
        let meta = parse_vnet_hdr(&hdr);
        assert_eq!(meta.ip_checksum, RxChecksumState::Unknown);
        assert_eq!(meta.l4_checksum, RxChecksumState::Unknown);
        assert_eq!(meta.l4_protocol, L4Protocol::Unknown);
    }

    #[test]
    fn rx_metadata_from_vnet_hdr_udp() {
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_data_valid(true),
            gso_type: VirtioNetHdrGso::new().with_protocol(VirtioNetHdrGsoProtocol::UDP),
            ..Default::default()
        };
        let meta = parse_vnet_hdr(&hdr);
        assert_eq!(meta.l4_protocol, L4Protocol::Udp);
    }

    #[test]
    fn rx_metadata_from_vnet_hdr_gro_tcpv4() {
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdrFlags::new().with_needs_csum(true),
            gso_type: VirtioNetHdrGso::new().with_protocol(VirtioNetHdrGsoProtocol::TCPV4),
            gso_size: 1460,
            hdr_len: 54,
            csum_start: 34,
            csum_offset: 16,
            ..Default::default()
        };
        let meta = parse_vnet_hdr(&hdr);
        let gso = meta.gso.unwrap();
        assert_eq!(gso.gso_type, RxGsoType::TcpV4);
        assert_eq!(gso.gso_size, 1460);
        assert_eq!(gso.hdr_len, 54);
        assert_eq!(meta.l4_checksum, RxChecksumState::NeedsCsum);
    }

    #[test]
    fn rx_offload_flags_none() {
        assert_eq!(rx_offload_config_to_tun_flags(None), 0);
        assert_eq!(
            rx_offload_config_to_tun_flags(Some(&RxOffloadConfig::default())),
            0
        );
    }

    #[test]
    fn rx_offload_flags_checksum_only() {
        let config = RxOffloadConfig {
            checksum: true,
            ..Default::default()
        };
        assert_eq!(
            rx_offload_config_to_tun_flags(Some(&config)),
            linux_net_bindings::gen_if_tun::TUN_F_CSUM
        );
    }

    #[test]
    fn rx_offload_flags_full() {
        let config = RxOffloadConfig {
            checksum: true,
            tcp4: true,
            tcp6: true,
            udp: true,
        };
        let flags = rx_offload_config_to_tun_flags(Some(&config));
        assert_ne!(flags & linux_net_bindings::gen_if_tun::TUN_F_CSUM, 0);
        assert_ne!(flags & linux_net_bindings::gen_if_tun::TUN_F_TSO4, 0);
        assert_ne!(flags & linux_net_bindings::gen_if_tun::TUN_F_TSO6, 0);
        assert_ne!(flags & linux_net_bindings::gen_if_tun::TUN_F_UFO, 0);
    }

    #[test]
    fn rx_offload_flags_tso_without_csum_ignored() {
        // TSO flags require checksum. Without checksum, they should not be set.
        let config = RxOffloadConfig {
            checksum: false,
            tcp4: true,
            tcp6: true,
            udp: true,
        };
        assert_eq!(rx_offload_config_to_tun_flags(Some(&config)), 0);
    }

    #[test]
    fn ipv4_header_checksum_fixup() {
        // Ethernet (14) + IPv4 header (20) with zero checksum field.
        let mut packet = vec![
            // Ethernet header (14 bytes)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
            // IPv4 header (20 bytes)
            0x45, 0x00, 0x00, 0x28, // version/IHL, DSCP, total length
            0x00, 0x01, 0x00, 0x00, // id, flags, fragment offset
            0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP, checksum=0
            0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
            0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
        ];
        fixup_ipv4_header_checksum(&mut packet, 14);
        let csum = u16::from_be_bytes([packet[24], packet[25]]);
        // Verify by summing all 16-bit words of the IP header;
        // the result (with checksum included) should fold to 0xffff.
        let mut sum: u32 = 0;
        for chunk in packet[14..34].chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
        assert_ne!(csum, 0, "checksum should be non-zero");
    }
}
