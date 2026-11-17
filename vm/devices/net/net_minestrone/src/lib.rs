// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A network backend endpoint that connects a guest NIC to the host network
//! through the [`minestrone`] passt-style translator.

#![forbid(unsafe_code)]

pub mod resolver;

use async_trait::async_trait;
use inspect::Inspect;
use inspect::InspectMut;
use inspect_counters::Counter;
use minestrone::ChecksumState;
use minestrone::DropReason;
use minestrone::Minestrone;
use minestrone::MinestroneParams;
use net_backend::BufferAccess;
use net_backend::L4Protocol;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxChecksumState;
use net_backend::RxGsoProtocol;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::RxOffload;
use net_backend::RxOffloadSupport;
use net_backend::TxError;
use net_backend::TxId;
use net_backend::TxOffloadSupport;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use pal_async::driver::Driver;
use parking_lot::Mutex;
use smoltcp::wire::ETHERNET_HEADER_LEN;
use smoltcp::wire::IPV4_HEADER_LEN;
use smoltcp::wire::IPV6_HEADER_LEN;
use smoltcp::wire::TcpPacket;
use std::collections::VecDeque;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

/// Largest frame accepted from the guest, bounded by the 64 KiB TSO limit.
const MAX_TX_FRAME: usize = 64 * 1024 + 256;
/// Bytes of guest frames processed as one batch. Guest data for a TCP flow
/// within a batch is written to the host with a single call.
const TX_BATCH_LEN: usize = 1024 * 1024;

/// A Minestrone network endpoint.
#[derive(InspectMut)]
pub struct MinestroneEndpoint {
    /// Held here while no queue is active, and by the queue while it is.
    #[inspect(skip)]
    slot: Arc<Mutex<Option<Minestrone>>>,
}

impl MinestroneEndpoint {
    /// Creates an endpoint with the given configuration.
    pub fn new(params: MinestroneParams) -> Self {
        Self {
            slot: Arc::new(Mutex::new(Some(Minestrone::new(params)))),
        }
    }
}

#[async_trait]
impl net_backend::Endpoint for MinestroneEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "minestrone"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn net_backend::Queue>>,
    ) -> anyhow::Result<()> {
        let [config] = <[QueueConfig; 1]>::try_from(config)
            .map_err(|c| anyhow::anyhow!("minestrone supports one queue, got {}", c.len()))?;
        let mut minestrone = self
            .slot
            .lock()
            .take()
            .ok_or_else(|| anyhow::anyhow!("minestrone queue already active"))?;
        minestrone.reset_driver();
        queues.push(Box::new(MinestroneQueue {
            slot: self.slot.clone(),
            minestrone: Some(minestrone),
            state: QueueState::default(),
            stats: Stats::default(),
            driver: config.driver,
            enabled_rx_offloads: config.enabled_rx_offloads,
        }));
        Ok(())
    }

    async fn stop(&mut self) {
        assert!(self.slot.lock().is_some());
    }

    fn is_ordered(&self) -> bool {
        true
    }

    fn tx_offload_support(&self) -> TxOffloadSupport {
        // The guest may skip checksums and send TSO superframes: TCP payload
        // is written directly to host stream sockets, which segment it.
        TxOffloadSupport {
            ipv4_header: true,
            tcp: true,
            udp: true,
            tso: true,
            uso: false,
        }
    }
}

/// The single queue of a [`MinestroneEndpoint`].
pub struct MinestroneQueue {
    slot: Arc<Mutex<Option<Minestrone>>>,
    minestrone: Option<Minestrone>,
    state: QueueState,
    stats: Stats,
    driver: Box<dyn Driver>,
    enabled_rx_offloads: RxOffloadSupport,
}

impl Drop for MinestroneQueue {
    fn drop(&mut self) {
        *self.slot.lock() = self.minestrone.take();
    }
}

impl InspectMut for MinestroneQueue {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        req.respond()
            .field("rx_avail", self.state.rx_avail.len())
            .field("rx_ready", self.state.rx_ready.len())
            .field("tx_avail", self.state.tx_avail.len())
            .field("tx_ready", self.state.tx_ready.len())
            .field("stats", &self.stats);
    }
}

#[derive(Default)]
struct QueueState {
    rx_avail: VecDeque<RxId>,
    rx_ready: VecDeque<RxId>,
    tx_avail: VecDeque<TxSegment>,
    tx_ready: VecDeque<TxId>,
    /// Guest frames copied for the current transmit batch.
    tx_arena: Vec<u8>,
    tx_frames: Vec<(std::ops::Range<usize>, ChecksumState)>,
}

#[derive(Inspect, Default)]
struct Stats {
    rx_dropped: Counter,
    tx_dropped: Counter,
    tx_errors: Counter,
    tx_unknown: Counter,
}

impl MinestroneQueue {
    fn with_minestrone<R>(
        &mut self,
        pool: &mut dyn BufferAccess,
        f: impl FnOnce(&mut minestrone::Access<'_, Client<'_>>) -> R,
    ) -> R {
        let minestrone = self
            .minestrone
            .as_mut()
            .expect("minestrone is present while the queue exists");
        f(&mut minestrone.access(&mut Client {
            state: &mut self.state,
            stats: &mut self.stats,
            driver: self.driver.as_ref(),
            pool,
            offloads: self.enabled_rx_offloads,
        }))
    }

    fn process_tx(&mut self, pool: &mut dyn BufferAccess) {
        while !self.state.tx_avail.is_empty() {
            let mut arena = std::mem::take(&mut self.state.tx_arena);
            // Sized once; frames overwrite it without clearing.
            if arena.len() < TX_BATCH_LEN {
                arena.resize(TX_BATCH_LEN, 0);
            }
            let mut frames = std::mem::take(&mut self.state.tx_frames);
            frames.clear();
            let mut used = 0;
            while let Some(head) = self.state.tx_avail.front() {
                let TxSegmentType::Head(meta) = &head.ty else {
                    unreachable!("tx packets start with a head segment")
                };
                let tx_id = meta.id;
                let len = meta.len as usize;
                if len <= MAX_TX_FRAME && used + len > arena.len() {
                    // The batch is full.
                    break;
                }
                let segment_count = meta.segment_count as usize;
                let checksum = ChecksumState {
                    ipv4: meta.flags.offload_ip_header_checksum(),
                    tcp: meta.flags.offload_tcp_checksum(),
                    udp: meta.flags.offload_udp_checksum(),
                    partial: false,
                    tso: meta
                        .flags
                        .offload_tcp_segmentation()
                        .then_some(meta.max_segment_size),
                    gso: None,
                };

                let segments = self.state.tx_avail.drain(..segment_count);
                if len > MAX_TX_FRAME {
                    drop(segments);
                    tracelimit::warn_ratelimited!(len, "dropping oversized tx frame");
                    self.stats.tx_errors.increment();
                } else {
                    let frame = &mut arena[used..used + len];
                    let gm = pool.guest_memory();
                    let mut offset = 0;
                    let mut ok = true;
                    for segment in segments {
                        let end = offset + segment.len as usize;
                        let Some(dest) = frame.get_mut(offset..end) else {
                            break;
                        };
                        if let Err(err) = gm.read_at(segment.gpa, dest) {
                            tracelimit::error_ratelimited!(
                                error = &err as &dyn std::error::Error,
                                "failed to read tx frame from guest memory"
                            );
                            ok = false;
                        }
                        offset = end;
                    }
                    if ok {
                        // Don't expose an earlier frame's bytes if the
                        // segments are shorter than the frame.
                        frame[offset..].fill(0);
                        frames.push((used..used + len, checksum));
                        used += len;
                    } else {
                        self.stats.tx_errors.increment();
                    }
                }
                self.state.tx_ready.push_back(tx_id);
            }

            let mut drops = Vec::new();
            self.with_minestrone(pool, |m| {
                m.send_batch(
                    frames
                        .iter()
                        .map(|(range, checksum)| (&arena[range.clone()], *checksum)),
                    |err| drops.push(err),
                )
            });
            for err in &drops {
                tracing::debug!(error = err as &dyn std::error::Error, "tx frame dropped");
                self.count_drop(err);
            }
            self.state.tx_arena = arena;
            self.state.tx_frames = frames;
        }
    }

    fn count_drop(&mut self, err: &DropReason) {
        match err {
            DropReason::FlowLimit(_) | DropReason::DestinationNotAllowed | DropReason::Io(_) => {
                self.stats.tx_dropped.increment()
            }
            DropReason::UnsupportedEthertype(_)
            | DropReason::UnsupportedIpProtocol(_)
            | DropReason::Service(_) => self.stats.tx_unknown.increment(),
            DropReason::Packet(_)
            | DropReason::Malformed
            | DropReason::Checksum
            | DropReason::FragmentedPacket => self.stats.tx_errors.increment(),
        }
    }
}

impl net_backend::Queue for MinestroneQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, pool: &mut dyn BufferAccess) -> Poll<()> {
        self.process_tx(pool);
        self.with_minestrone(pool, |m| m.poll(cx));
        if !self.state.tx_ready.is_empty() || !self.state.rx_ready.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.state.rx_avail.extend(done);
    }

    fn rx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        let n = packets.len().min(self.state.rx_ready.len());
        for (x, y) in packets.iter_mut().zip(self.state.rx_ready.drain(..n)) {
            *x = y;
        }
        Ok(n)
    }

    fn tx_avail(
        &mut self,
        _pool: &mut dyn BufferAccess,
        segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        self.state.tx_avail.extend(segments.iter().cloned());
        Ok((false, segments.len()))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        done: &mut [TxId],
    ) -> Result<usize, TxError> {
        let n = done.len().min(self.state.tx_ready.len());
        for (x, y) in done.iter_mut().zip(self.state.tx_ready.drain(..n)) {
            *x = y;
        }
        Ok(n)
    }
}

struct Client<'a> {
    state: &'a mut QueueState,
    stats: &'a mut Stats,
    driver: &'a dyn Driver,
    pool: &'a mut dyn BufferAccess,
    offloads: RxOffloadSupport,
}

impl minestrone::FrameSink for Client<'_> {
    fn send_frame_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState) {
        let Some(rx_id) = self.state.rx_avail.pop_front() else {
            self.stats.rx_dropped.increment();
            return;
        };
        let len: usize = segments.iter().map(|s| s.len()).sum();
        if len > self.pool.capacity(rx_id) as usize {
            tracelimit::warn_ratelimited!(len, "dropping rx frame: too large");
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
            // Minestrone frames have fixed-size IP headers, and the first
            // segment holds all headers.
            let protocol = if checksum.ipv4 {
                RxGsoProtocol::TcpV4
            } else {
                RxGsoProtocol::TcpV6
            };
            let tcp_header_len = segments[0].get(l3_start..).map_or(20, |t| {
                usize::from(TcpPacket::new_unchecked(t).header_len())
            });
            RxOffload::tcp_gso(
                protocol,
                (l3_start + tcp_header_len) as u16,
                mss,
                Some(l3_start as u16),
            )
        } else if checksum.partial {
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

    fn max_frame_len(&mut self) -> usize {
        self.state
            .rx_avail
            .front()
            .map_or(0, |&rx_id| self.pool.capacity(rx_id) as usize)
    }
}

impl minestrone::Client for Client<'_> {
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
