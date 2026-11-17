// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A network backend endpoint that connects a guest NIC to the host network
//! through the [`minestrone`] passt-style translator.

#![forbid(unsafe_code)]

pub mod resolver;

use async_trait::async_trait;
use inspect::InspectMut;
use minestrone::ChecksumState;
use minestrone::DropReason;
use minestrone::Minestrone;
use minestrone::MinestroneParams;
use net_backend::BufferAccess;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxId;
use net_backend::RxOffloadSupport;
use net_backend::TxError;
use net_backend::TxId;
use net_backend::TxOffloadSupport;
use net_backend::TxSegment;
use net_usermode::endpoint::QueueClient;
use net_usermode::endpoint::QueueState;
use net_usermode::endpoint::QueueStats;
use pal_async::driver::Driver;
use parking_lot::Mutex;
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

    fn max_mtu(&self) -> u16 {
        65520
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn net_backend::Queue>>,
    ) -> anyhow::Result<()> {
        let [config] = <[QueueConfig; 1]>::try_from(config)
            .map_err(|c| anyhow::anyhow!("minestrone supports one queue, got {}", c.len()))?;
        anyhow::ensure!(
            (1280..=self.max_mtu()).contains(&config.mtu),
            "invalid negotiated minestrone MTU {}",
            config.mtu
        );
        let mut minestrone = self
            .slot
            .lock()
            .take()
            .ok_or_else(|| anyhow::anyhow!("minestrone queue already active"))?;
        minestrone.reset_driver();
        minestrone.set_mtu(config.mtu);
        queues.push(Box::new(MinestroneQueue {
            slot: self.slot.clone(),
            minestrone: Some(minestrone),
            state: QueueState::default(),
            stats: QueueStats::default(),
            tx_arena: Vec::new(),
            tx_frames: Vec::new(),
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
    stats: QueueStats,
    /// Guest frames copied for the current transmit batch.
    tx_arena: Vec<u8>,
    tx_frames: Vec<(std::ops::Range<usize>, ChecksumState)>,
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
        req.respond().merge(&self.state).field("stats", &self.stats);
    }
}

impl MinestroneQueue {
    fn with_minestrone<R>(
        &mut self,
        pool: &mut dyn BufferAccess,
        f: impl FnOnce(&mut minestrone::Access<'_, QueueClient<'_>>) -> R,
    ) -> R {
        let minestrone = self
            .minestrone
            .as_mut()
            .expect("minestrone is present while the queue exists");
        f(&mut minestrone.access(&mut QueueClient {
            state: &mut self.state,
            stats: &mut self.stats,
            driver: self.driver.as_ref(),
            pool,
            offloads: self.enabled_rx_offloads,
        }))
    }

    fn process_tx(&mut self, pool: &mut dyn BufferAccess) {
        while !self.state.tx_avail.is_empty() {
            let mut arena = std::mem::take(&mut self.tx_arena);
            // Sized once; frames overwrite it without clearing.
            if arena.len() < TX_BATCH_LEN {
                arena.resize(TX_BATCH_LEN, 0);
            }
            let mut frames = std::mem::take(&mut self.tx_frames);
            frames.clear();
            let mut used = 0;
            while let Some(packet) = self.state.next_tx() {
                if packet.len > MAX_TX_FRAME {
                    tracelimit::warn_ratelimited!(len = packet.len, "dropping oversized tx frame");
                    self.state.drop_tx(&packet);
                    self.stats.tx_errors.increment();
                    continue;
                }
                if used + packet.len > arena.len() {
                    // The batch is full.
                    break;
                }
                let range = used..used + packet.len;
                match self
                    .state
                    .take_tx(&packet, pool.guest_memory(), &mut arena[range.clone()])
                {
                    Ok(()) => {
                        frames.push((range, packet.checksum));
                        used += packet.len;
                    }
                    Err(err) => {
                        tracelimit::error_ratelimited!(
                            error = &err as &dyn std::error::Error,
                            "failed to read tx frame from guest memory"
                        );
                        self.stats.tx_errors.increment();
                    }
                }
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
            self.tx_arena = arena;
            self.tx_frames = frames;
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
        if self.state.has_completions() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.state.rx_avail(done);
    }

    fn rx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        packets: &mut [RxId],
    ) -> anyhow::Result<usize> {
        Ok(self.state.rx_poll(packets))
    }

    fn tx_avail(
        &mut self,
        _pool: &mut dyn BufferAccess,
        segments: &[TxSegment],
    ) -> anyhow::Result<(bool, usize)> {
        self.state.tx_avail(segments);
        Ok((false, segments.len()))
    }

    fn tx_poll(
        &mut self,
        _pool: &mut dyn BufferAccess,
        done: &mut [TxId],
    ) -> Result<usize, TxError> {
        Ok(self.state.tx_poll(done))
    }
}
