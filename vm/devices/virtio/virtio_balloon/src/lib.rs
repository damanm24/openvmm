// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Virtio traditional memory balloon device implementation.
//!
//! Implements the virtio-balloon device (device ID 5) as specified in the
//! VIRTIO 1.2 specification, §5.5 "Traditional Memory Balloon Device". The
//! balloon lets the host dynamically grow and shrink the amount of physical
//! memory available to a running guest.
//!
//! The host sets a target balloon size (`num_pages`) in config space and
//! raises a config-change interrupt. The guest driver then hands the host
//! free guest-physical page frame numbers on the inflate virtqueue; the
//! device reclaims the physical memory backing those pages via
//! [`VirtioMemoryReclaim`]. On the deflate virtqueue the guest reclaims
//! pages from the balloon; the device simply acknowledges them (the pages
//! fault back in on next guest access).
//!
//! Only the base inflate/deflate feature set is implemented; the optional
//! stats, free-page-hint, and page-reporting virtqueues are not offered.

#![forbid(unsafe_code)]

pub mod resolver;

use anyhow::Context as _;
use futures::StreamExt;
use guestmem::GuestMemory;
use inspect::InspectMut;
use pal_async::task::Spawn;
use pal_async::task::Task;
use pal_async::wait::PolledWait;
use parking_lot::Mutex;
use std::sync::Arc;
use task_control::AsyncRun;
use task_control::Cancelled;
use task_control::InspectTaskMut;
use task_control::StopTask;
use task_control::TaskControl;
use virtio::DeviceTraits;
use virtio::DeviceTraitsSharedMemory;
use virtio::QueueResources;
use virtio::VirtioDevice;
use virtio::VirtioQueue;
use virtio::VirtioQueueCallbackWork;
use virtio::queue::QueueState;
use virtio::resolve::VirtioMemoryReclaim;
use virtio::spec::VirtioDeviceFeatures;
use virtio::spec::balloon;
use virtio_resources::balloon::BalloonRequest;
use vmcore::vm_task::VmTaskDriver;
use vmcore::vm_task::VmTaskDriverSource;

/// Shared, mutable balloon config-space state.
#[derive(Debug, Default)]
struct BalloonState {
    /// Target number of 4KiB balloon pages (device-owned; read by the guest
    /// from config offset 0).
    num_pages: u32,
    /// Number of pages currently in the balloon, as reported by the guest
    /// (written to config offset 4).
    actual: u32,
}

/// Convert a target size in bytes to a 4KiB balloon page count, saturating
/// at `u32::MAX`.
fn bytes_to_pages(bytes: u64) -> u32 {
    (bytes / balloon::VIRTIO_BALLOON_PAGE_SIZE).min(u32::MAX as u64) as u32
}

/// Virtio memory balloon device.
#[derive(InspectMut)]
pub struct VirtioBalloonDevice {
    #[inspect(skip)]
    driver: VmTaskDriver,
    #[inspect(skip)]
    state: Arc<Mutex<BalloonState>>,
    #[inspect(skip)]
    reclaim: Option<Arc<dyn VirtioMemoryReclaim>>,
    #[inspect(skip)]
    config_change_recv: Option<mesh::Receiver<()>>,
    #[inspect(skip)]
    _control_task: Option<Task<()>>,
    #[inspect(mut)]
    inflate_worker: TaskControl<BalloonWorker, BalloonQueue>,
    #[inspect(mut)]
    deflate_worker: TaskControl<BalloonWorker, BalloonQueue>,
}

impl VirtioBalloonDevice {
    /// Create a new balloon device.
    ///
    /// `initial_target_bytes` is the amount of guest memory to reclaim at
    /// start. `control_recv` optionally carries runtime target changes.
    /// `reclaim` is the host memory-reclaim interface; if `None`, inflate
    /// requests are acknowledged but no physical memory is released.
    pub fn new(
        driver_source: &VmTaskDriverSource,
        initial_target_bytes: u64,
        control_recv: Option<mesh::Receiver<BalloonRequest>>,
        reclaim: Option<Arc<dyn VirtioMemoryReclaim>>,
    ) -> Self {
        let driver = driver_source.simple();
        let state = Arc::new(Mutex::new(BalloonState {
            num_pages: bytes_to_pages(initial_target_bytes),
            actual: 0,
        }));

        let (config_change_send, config_change_recv) = mesh::channel();

        let control_task = control_recv.map(|recv| {
            let state = state.clone();
            driver.spawn("virtio-balloon-control", async move {
                run_control_task(recv, state, config_change_send).await;
            })
        });

        Self {
            driver,
            state,
            reclaim,
            config_change_recv: Some(config_change_recv),
            _control_task: control_task,
            inflate_worker: TaskControl::new(BalloonWorker),
            deflate_worker: TaskControl::new(BalloonWorker),
        }
    }

    fn worker_mut(&mut self, idx: u16) -> &mut TaskControl<BalloonWorker, BalloonQueue> {
        if idx == balloon::INFLATE_QUEUE {
            &mut self.inflate_worker
        } else {
            &mut self.deflate_worker
        }
    }
}

impl VirtioDevice for VirtioBalloonDevice {
    fn traits(&self) -> DeviceTraits {
        DeviceTraits {
            device_id: virtio::spec::VirtioDeviceType::BALLOON,
            device_features: VirtioDeviceFeatures::new()
                .with_ring_event_idx(true)
                .with_ring_indirect_desc(true),
            max_queues: 2,
            device_register_length: 8,
            shared_memory: DeviceTraitsSharedMemory::default(),
        }
    }

    async fn read_registers_u32(&mut self, offset: u16) -> u32 {
        let state = self.state.lock();
        match offset {
            balloon::CONFIG_OFFSET_NUM_PAGES => state.num_pages,
            balloon::CONFIG_OFFSET_ACTUAL => state.actual,
            _ => 0,
        }
    }

    async fn write_registers_u32(&mut self, offset: u16, val: u32) {
        // The only writable config field is `actual`, which the guest driver
        // updates to reflect the balloon's current size.
        if offset == balloon::CONFIG_OFFSET_ACTUAL {
            self.state.lock().actual = val;
        }
    }

    async fn start_queue(
        &mut self,
        idx: u16,
        resources: QueueResources,
        features: &VirtioDeviceFeatures,
        initial_state: Option<QueueState>,
    ) -> anyhow::Result<()> {
        assert!(idx == balloon::INFLATE_QUEUE || idx == balloon::DEFLATE_QUEUE);

        let queue_event = PolledWait::new(&self.driver, resources.event)
            .context("failed to create polled wait")?;
        let queue = VirtioQueue::new(
            *features,
            resources.params,
            resources.guest_memory.clone(),
            resources.notify,
            queue_event,
            initial_state,
        )
        .context("failed to create virtio queue")?;

        let kind = if idx == balloon::INFLATE_QUEUE {
            QueueKind::Inflate
        } else {
            QueueKind::Deflate
        };
        let reclaim = self.reclaim.clone();
        let driver = self.driver.clone();
        let worker = self.worker_mut(idx);
        worker.insert(
            driver,
            "virtio-balloon-queue",
            BalloonQueue {
                queue,
                mem: resources.guest_memory,
                kind,
                reclaim,
            },
        );
        worker.start();
        Ok(())
    }

    async fn stop_queue(&mut self, idx: u16) -> Option<QueueState> {
        let worker = self.worker_mut(idx);
        if !worker.has_state() {
            return None;
        }
        worker.stop().await;
        Some(worker.remove().queue.queue_state())
    }

    fn config_change_receiver(&mut self) -> Option<mesh::Receiver<()>> {
        self.config_change_recv.take()
    }

    fn supports_save_restore(&self) -> bool {
        // The transport saves and restores per-queue state. The device's
        // config-space `num_pages` target is re-derived from the device
        // configuration on reconstruction (as with other virtio devices'
        // config), and `actual` is re-reported by the guest driver. A
        // balloon target set at runtime via `BalloonRequest::SetTarget` is
        // not persisted across save/restore.
        true
    }
}

/// Handle runtime balloon target-change requests.
async fn run_control_task(
    mut recv: mesh::Receiver<BalloonRequest>,
    state: Arc<Mutex<BalloonState>>,
    config_change: mesh::Sender<()>,
) {
    while let Some(req) = recv.next().await {
        match req {
            BalloonRequest::SetTarget(rpc) => {
                rpc.handle_failable_sync(|target_bytes| {
                    let pages = bytes_to_pages(target_bytes);
                    state.lock().num_pages = pages;
                    // Notify the guest that the target changed. Errors mean
                    // the transport is gone; the device is shutting down.
                    config_change.send(());
                    Ok::<(), std::convert::Infallible>(())
                });
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum QueueKind {
    Inflate,
    Deflate,
}

#[derive(InspectMut)]
struct BalloonWorker;

#[derive(InspectMut)]
struct BalloonQueue {
    queue: VirtioQueue,
    #[inspect(skip)]
    mem: GuestMemory,
    #[inspect(skip)]
    kind: QueueKind,
    #[inspect(skip)]
    reclaim: Option<Arc<dyn VirtioMemoryReclaim>>,
}

impl InspectTaskMut<BalloonQueue> for BalloonWorker {
    fn inspect_mut(&mut self, req: inspect::Request<'_>, state: Option<&mut BalloonQueue>) {
        req.respond().merge(self).merge(state);
    }
}

/// Maximum number of PFNs to process from a single descriptor chain, to
/// bound host memory allocation on malicious input. 256Ki PFNs = 1 MiB of
/// PFN data describing up to 1 GiB of guest pages.
const MAX_PFNS_PER_REQUEST: usize = 256 * 1024;

impl AsyncRun<BalloonQueue> for BalloonWorker {
    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        state: &mut BalloonQueue,
    ) -> Result<(), Cancelled> {
        loop {
            let work = stop.until_stopped(state.queue.next()).await?;
            let Some(work) = work else { break };
            match work {
                Ok(work) => {
                    process_request(state, &work);
                    state.queue.complete(work, 0);
                }
                Err(err) => {
                    tracelimit::error_ratelimited!(
                        err = &err as &dyn std::error::Error,
                        "balloon queue error"
                    );
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Process a single inflate/deflate descriptor chain.
///
/// The readable payload is a little-endian array of 32-bit page frame
/// numbers. On inflate, the physical memory backing each page is reclaimed;
/// on deflate, the pages are simply acknowledged.
fn process_request(state: &BalloonQueue, work: &VirtioQueueCallbackWork) {
    // Deflate never reclaims memory — the guest is taking pages back, and
    // they fault in on next access.
    if state.kind == QueueKind::Deflate {
        return;
    }
    let Some(reclaim) = &state.reclaim else {
        return;
    };

    let readable_len = work.get_payload_length(false) as usize;
    let count = std::cmp::min(readable_len / 4, MAX_PFNS_PER_REQUEST);
    if count == 0 {
        return;
    }

    let mut buf = vec![0u8; count * 4];
    if let Err(err) = work.read(&state.mem, &mut buf) {
        tracelimit::error_ratelimited!(
            err = &err as &dyn std::error::Error,
            "failed to read balloon PFN array from guest memory"
        );
        return;
    }

    // Coalesce consecutive PFNs into runs to minimize reclaim calls.
    let pfns = buf
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64);

    let mut run_start: Option<u64> = None;
    let mut run_end: u64 = 0;
    let flush = |start: u64, end: u64| {
        let gpa = start << balloon::VIRTIO_BALLOON_PFN_SHIFT;
        let len = (end - start) << balloon::VIRTIO_BALLOON_PFN_SHIFT;
        if let Err(err) = reclaim.reclaim(gpa, len) {
            tracelimit::warn_ratelimited!(
                err = &err as &dyn std::error::Error,
                gpa,
                len,
                "failed to reclaim balloon page range"
            );
        }
    };

    for pfn in pfns {
        match run_start {
            Some(_) if pfn == run_end => {
                run_end = pfn + 1;
            }
            Some(start) => {
                flush(start, run_end);
                run_start = Some(pfn);
                run_end = pfn + 1;
            }
            None => {
                run_start = Some(pfn);
                run_end = pfn + 1;
            }
        }
    }
    if let Some(start) = run_start {
        flush(start, run_end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;
    use mesh::rpc::RpcSend;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::wait::PolledWait;
    use pal_event::Event;
    use std::future::poll_fn;
    use std::task::Poll;
    use test_with_tracing::test;
    use virtio::QueueResources;
    use virtio::queue::QueueParams;
    use virtio::spec::VirtioDeviceFeatures;
    use virtio::spec::queue::AVAIL_ELEMENT_SIZE;
    use virtio::spec::queue::AVAIL_OFFSET_IDX;
    use virtio::spec::queue::AVAIL_OFFSET_RING;
    use virtio::spec::queue::DescriptorFlags;
    use virtio::spec::queue::SplitDescriptor;
    use virtio::spec::queue::USED_OFFSET_IDX;
    use virtio_resources::balloon::BalloonRequest;
    use vmcore::interrupt::Interrupt;
    use vmcore::vm_task::SingleDriverBackend;
    use vmcore::vm_task::VmTaskDriverSource;

    const QUEUE_SIZE: u16 = 16;
    const DESC_ADDR: u64 = 0x0000;
    const AVAIL_ADDR: u64 = 0x1000;
    const USED_ADDR: u64 = 0x2000;
    const DATA_BASE: u64 = 0x10000;
    const TOTAL_MEM_SIZE: usize = 0x40000;

    /// A memory-reclaim implementation that records the ranges it is asked
    /// to reclaim.
    #[derive(Default)]
    struct MockReclaim {
        calls: Mutex<Vec<(u64, u64)>>,
    }

    impl VirtioMemoryReclaim for MockReclaim {
        fn reclaim(&self, gpa: u64, len: u64) -> std::io::Result<()> {
            self.calls.lock().push((gpa, len));
            Ok(())
        }
    }

    fn write_descriptor(
        mem: &GuestMemory,
        index: u16,
        addr: u64,
        len: u32,
        flags: DescriptorFlags,
    ) {
        let base = DESC_ADDR + size_of::<SplitDescriptor>() as u64 * index as u64;
        mem.write_at(
            base + offset_of!(SplitDescriptor, address) as u64,
            &addr.to_le_bytes(),
        )
        .unwrap();
        mem.write_at(
            base + offset_of!(SplitDescriptor, length) as u64,
            &len.to_le_bytes(),
        )
        .unwrap();
        mem.write_at(
            base + offset_of!(SplitDescriptor, flags_raw) as u64,
            &u16::from(flags).to_le_bytes(),
        )
        .unwrap();
        mem.write_at(
            base + offset_of!(SplitDescriptor, next) as u64,
            &0u16.to_le_bytes(),
        )
        .unwrap();
    }

    fn make_available(mem: &GuestMemory, desc_index: u16, avail_idx: &mut u16) {
        let ring_offset =
            AVAIL_ADDR + AVAIL_OFFSET_RING + AVAIL_ELEMENT_SIZE * (*avail_idx % QUEUE_SIZE) as u64;
        mem.write_at(ring_offset, &desc_index.to_le_bytes())
            .unwrap();
        *avail_idx = avail_idx.wrapping_add(1);
        mem.write_at(AVAIL_ADDR + AVAIL_OFFSET_IDX, &avail_idx.to_le_bytes())
            .unwrap();
    }

    fn read_used_idx(mem: &GuestMemory) -> u16 {
        let mut buf = [0u8; 2];
        mem.read_at(USED_ADDR + USED_OFFSET_IDX, &mut buf).unwrap();
        u16::from_le_bytes(buf)
    }

    fn driver_source(driver: &DefaultDriver) -> VmTaskDriverSource {
        VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()))
    }

    async fn start_inflate_queue(
        device: &mut VirtioBalloonDevice,
        mem: &GuestMemory,
        queue_event: &Event,
        interrupt_event: &Event,
    ) {
        device
            .start_queue(
                balloon::INFLATE_QUEUE,
                QueueResources {
                    params: QueueParams {
                        size: QUEUE_SIZE,
                        enable: true,
                        desc_addr: DESC_ADDR,
                        avail_addr: AVAIL_ADDR,
                        used_addr: USED_ADDR,
                    },
                    notify: Interrupt::from_event(interrupt_event.clone()),
                    event: queue_event.clone(),
                    guest_memory: mem.clone(),
                },
                &VirtioDeviceFeatures::new(),
                None,
            )
            .await
            .unwrap();
    }

    #[async_test]
    async fn inflate_reclaims_pages(driver: DefaultDriver) {
        let mem = GuestMemory::allocate(TOTAL_MEM_SIZE);
        let reclaim = Arc::new(MockReclaim::default());
        let mut device =
            VirtioBalloonDevice::new(&driver_source(&driver), 0, None, Some(reclaim.clone()));

        let queue_event = Event::new();
        let interrupt_event = Event::new();
        start_inflate_queue(&mut device, &mem, &queue_event, &interrupt_event).await;

        // Two runs of PFNs: [0x10, 0x11, 0x12] and [0x20].
        let pfns: [u32; 4] = [0x10, 0x11, 0x12, 0x20];
        let mut buf = Vec::new();
        for pfn in pfns {
            buf.extend_from_slice(&pfn.to_le_bytes());
        }
        mem.write_at(DATA_BASE, &buf).unwrap();

        // Readable descriptor (no WRITE flag) pointing at the PFN array.
        write_descriptor(&mem, 0, DATA_BASE, buf.len() as u32, DescriptorFlags::new());
        let mut avail_idx = 0u16;
        make_available(&mem, 0, &mut avail_idx);
        queue_event.signal();

        let mut wait = PolledWait::new(&driver, interrupt_event.clone()).unwrap();
        mesh::CancelContext::new()
            .with_timeout(std::time::Duration::from_secs(5))
            .until_cancelled(async {
                loop {
                    if read_used_idx(&mem) != 0 {
                        break;
                    }
                    wait.wait().await.unwrap();
                }
            })
            .await
            .expect("timed out waiting for inflate completion");

        let calls = reclaim.calls.lock().clone();
        assert_eq!(
            calls,
            vec![
                (0x10 << 12, 3 << 12), // coalesced run 0x10..0x13
                (0x20 << 12, 1 << 12), // single page 0x20
            ]
        );
    }

    #[async_test]
    async fn config_reports_target_and_actual(driver: DefaultDriver) {
        // 8 MiB target -> 2048 4KiB pages.
        let mut device =
            VirtioBalloonDevice::new(&driver_source(&driver), 8 * 1024 * 1024, None, None);

        let traits = device.traits();
        assert_eq!(traits.device_id, virtio::spec::VirtioDeviceType::BALLOON);
        assert_eq!(traits.max_queues, 2);
        assert_eq!(traits.device_register_length, 8);

        assert_eq!(
            device
                .read_registers_u32(balloon::CONFIG_OFFSET_NUM_PAGES)
                .await,
            2048
        );
        assert_eq!(
            device
                .read_registers_u32(balloon::CONFIG_OFFSET_ACTUAL)
                .await,
            0
        );

        // The guest driver reports the current balloon size via `actual`.
        device
            .write_registers_u32(balloon::CONFIG_OFFSET_ACTUAL, 1000)
            .await;
        assert_eq!(
            device
                .read_registers_u32(balloon::CONFIG_OFFSET_ACTUAL)
                .await,
            1000
        );
    }

    #[async_test]
    async fn set_target_updates_config_and_signals(driver: DefaultDriver) {
        let (send, recv) = mesh::channel();
        let mut device = VirtioBalloonDevice::new(&driver_source(&driver), 0, Some(recv), None);

        let mut config_change = device.config_change_receiver().expect("receiver present");

        // Request a 4 MiB balloon target -> 1024 pages.
        send.call_failable(BalloonRequest::SetTarget, 4 * 1024 * 1024)
            .await
            .unwrap();

        assert_eq!(
            device
                .read_registers_u32(balloon::CONFIG_OFFSET_NUM_PAGES)
                .await,
            1024
        );

        // The device should have signaled a config change.
        let signaled = poll_fn(|cx| Poll::Ready(config_change.poll_recv(cx))).await;
        assert!(matches!(signaled, Poll::Ready(Ok(()))));
    }
}
