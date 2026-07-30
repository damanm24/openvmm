// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

pub mod resolver;

use anyhow::Context as _;
use async_trait::async_trait;
use consomme::ChecksumState;
use consomme::Consomme;
use consomme::ConsommeConfig;
use consomme::ConsommeParams;
pub use consomme::IpVersion;
use inspect::Inspect;
use inspect::InspectMut;
use inspect_counters::Counter;
use mesh::rpc::Rpc;
use mesh::rpc::RpcError;
use mesh::rpc::RpcSend;
use net_backend::BufferAccess;
use net_backend::EndpointAction;
use net_backend::L4Protocol;
use net_backend::QueueConfig;
use net_backend::RssConfig;
use net_backend::RxChecksumState;
use net_backend::RxId;
use net_backend::RxMetadata;
use net_backend::TxError;
use net_backend::TxId;
use net_backend::TxOffloadSupport;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use net_backend_resources::consomme::ConsommeRequest;
use net_backend_resources::consomme::HostPortConfig;
use net_backend_resources::consomme::HostPortProtocol;
use pal_async::driver::Driver;
use parking_lot::Mutex;
use parking_lot::MutexGuard;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use thiserror::Error;

/// Creates and binds a socket for the given protocol, address, and port.
///
/// When `ip_addr` is `None`, binds to `0.0.0.0` (IPv4 only).
pub(crate) fn create_bound_socket(
    protocol: &IpProtocol,
    ip_addr: Option<IpAddr>,
    port: u16,
) -> std::io::Result<socket2::Socket> {
    let bind_addr: SocketAddr = match ip_addr {
        Some(IpAddr::V4(ip)) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
        Some(IpAddr::V6(ip)) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
        None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
    };
    let (domain, is_ipv6) = match bind_addr {
        SocketAddr::V4(_) => (socket2::Domain::IPV4, false),
        SocketAddr::V6(_) => (socket2::Domain::IPV6, true),
    };
    let (sock_type, sock_protocol) = match protocol {
        IpProtocol::Tcp => (socket2::Type::STREAM, socket2::Protocol::TCP),
        IpProtocol::Udp => (socket2::Type::DGRAM, socket2::Protocol::UDP),
    };
    let socket = socket2::Socket::new(domain, sock_type, Some(sock_protocol))?;
    if is_ipv6 {
        socket.set_only_v6(true)?;
    }
    socket.bind(&bind_addr.into())?;
    Ok(socket)
}

fn socket_addr(socket: &socket2::Socket) -> Result<SocketAddr, consomme::BindError> {
    socket
        .local_addr()
        .map_err(consomme::BindError::Io)?
        .as_socket()
        .ok_or_else(|| consomme::BindError::Io(std::io::Error::other("invalid socket address")))
}

fn socket_family(socket: &socket2::Socket) -> Result<IpVersion, consomme::BindError> {
    let addr = socket_addr(socket)?;
    Ok(match addr.ip() {
        IpAddr::V4(_) => IpVersion::Ipv4,
        IpAddr::V6(_) => IpVersion::Ipv6,
    })
}

pub struct ConsommeEndpoint {
    shards: Arc<[Mutex<EndpointShard>]>,
    control: EndpointControl,
    config: Arc<ConsommeConfig>,
    /// Control requests originating within this process (see
    /// [`ConsommeControl`]).
    local_recv: Option<mesh::Receiver<ControlRequest>>,
    /// Port bind/unbind requests arriving from another process (e.g. from
    /// ttrpc).
    remote_recv: Option<mesh::Receiver<ConsommeRequest>>,
    /// Requests buffered until the next queue (re)start applies them. Coalesced
    /// per port so the set stays bounded.
    pending: PendingRequests,
}

const MAX_CONSOMME_QUEUES: usize = 64;

/// Requests buffered while no queue owns the consomme state.
#[derive(Default)]
struct PendingRequests {
    /// Bind/unbind requests, keyed by port; a newer request for a port replaces
    /// (and completes) an older one.
    ports: HashMap<PortKey, ConsommeRequest>,
    /// In-proc state updates, applied in order.
    state_updates: Vec<Rpc<ConsommeParamsUpdateFn, ()>>,
}

impl PendingRequests {
    fn is_empty(&self) -> bool {
        self.ports.is_empty() && self.state_updates.is_empty()
    }

    fn buffer_control(&mut self, request: ControlRequest) {
        match request {
            ControlRequest::Port(request) => self.buffer_request(request),
            ControlRequest::UpdateState(rpc) => self.state_updates.push(rpc),
        }
    }

    /// Adds a port request, coalescing it with any existing request for the
    /// same port.
    fn buffer_request(&mut self, request: ConsommeRequest) {
        let key = PortKey::for_request(&request);
        if let Some(existing) = self.ports.remove(&key) {
            let cancels = matches!(existing, ConsommeRequest::Bind(_))
                && matches!(request, ConsommeRequest::Unbind(_));
            if cancels {
                // Unbind cancels a not-yet-applied bind; complete both as no-ops.
                into_rpc(existing).complete(Ok(()));
                into_rpc(request).complete(Ok(()));
                tracing::debug!(guest_port = key.guest_port, "coalesced bind and unbind");
                return;
            }
            // Newer request wins; report the older one as superseded.
            into_rpc(existing).fail(PortRequestSuperseded);
        }
        self.ports.insert(key, request);
    }
}

/// Drains all currently-available items from `recv` into `buffer`, registering a
/// waker when nothing is ready and dropping the receiver if the channel closed.
/// Returns whether any item was read.
fn drain_receiver<T>(
    recv: &mut Option<mesh::Receiver<T>>,
    cx: &mut Context<'_>,
    channel: &'static str,
    mut buffer: impl FnMut(T),
) -> bool {
    let mut received = false;
    loop {
        let polled = recv.as_mut().map(|r| r.poll_recv(cx));
        match polled {
            Some(Poll::Ready(Ok(item))) => {
                buffer(item);
                received = true;
            }
            Some(Poll::Ready(Err(err))) => {
                tracing::warn!(
                    err = &err as &dyn std::error::Error,
                    channel,
                    "consomme request channel closed"
                );
                *recv = None;
            }
            Some(Poll::Pending) | None => break,
        }
    }
    received
}

/// Coalescing key: bind/unbind for the same protocol, family, and guest port
/// target the same forward.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PortKey {
    is_udp: bool,
    is_ipv6: bool,
    guest_port: u16,
}

impl PortKey {
    fn for_request(request: &ConsommeRequest) -> Self {
        let cfg = match request {
            ConsommeRequest::Bind(rpc) | ConsommeRequest::Unbind(rpc) => rpc.input(),
        };
        Self {
            is_udp: matches!(cfg.protocol, HostPortProtocol::Udp),
            is_ipv6: matches!(
                cfg.host_address,
                Some(net_backend_resources::consomme::HostIpAddress::Ipv6(_))
            ),
            guest_port: cfg.guest_port,
        }
    }
}

/// Configuration for a port to forward from the host to the guest.
pub struct PortForwardConfig {
    /// The protocol to forward.
    pub protocol: IpProtocol,
    /// An already-bound host socket to forward traffic from.
    pub socket: socket2::Socket,
    /// The port traffic is forwarded to on the guest.
    pub guest_port: u16,
}

struct EndpointShard {
    consomme: Consomme,
    driver: Option<Arc<dyn Driver>>,
    shard_stats: ShardStats,
    wake: Arc<ShardWake>,
}

struct EndpointControl {
    port_forwards: Vec<PortForwardConfig>,
    active_shards: usize,
    steering_seed: u64,
}

#[derive(Inspect, Default)]
struct ShardStats {
    lock_acquisitions: Counter,
    contended_acquisitions: Counter,
    local_ingest: Counter,
    foreign_ingest: Counter,
    owner_wakes: Counter,
    coalesced_wakes: Counter,
    control_ingest: Counter,
    malformed_ingest: Counter,
    migration_egress_drops: Counter,
}

struct ShardWake {
    pending: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ShardWake {
    fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    fn register(&self, cx: &Context<'_>) {
        *self.waker.lock() = Some(cx.waker().clone());
        self.pending.store(false, Ordering::Release);
    }

    fn wake(&self, stats: &mut ShardStats) {
        if self.pending.swap(true, Ordering::AcqRel) {
            stats.coalesced_wakes.increment();
            return;
        }
        stats.owner_wakes.increment();
        if let Some(waker) = self.waker.lock().as_ref() {
            waker.wake_by_ref();
        }
    }
}

impl ConsommeEndpoint {
    pub fn new(config: ConsommeConfig, params: ConsommeParams) -> Self {
        Self::with_state(config, params, Vec::new(), None, None)
    }

    /// Creates a new endpoint with ports to forward once the queue starts.
    pub fn new_with_ports(
        config: ConsommeConfig,
        params: ConsommeParams,
        ports: Vec<PortForwardConfig>,
    ) -> Self {
        Self::with_state(config, params, ports, None, None)
    }

    /// Creates a new endpoint with an in-process [`ConsommeControl`] handle for
    /// runtime bind/unbind and state updates.
    pub fn new_dynamic(config: ConsommeConfig, params: ConsommeParams) -> (Self, ConsommeControl) {
        let (send, recv) = mesh::channel();
        (
            Self::with_state(config, params, Vec::new(), None, Some(recv)),
            ConsommeControl { send },
        )
    }

    /// Creates a new endpoint with initial ports and a channel for runtime
    /// port bind/unbind requests from an external source (e.g. ttrpc server).
    pub fn new_with_port_channel(
        config: ConsommeConfig,
        params: ConsommeParams,
        ports: Vec<PortForwardConfig>,
        port_recv: mesh::Receiver<ConsommeRequest>,
    ) -> Self {
        Self::with_state(config, params, ports, Some(port_recv), None)
    }

    fn with_state(
        config: ConsommeConfig,
        params: ConsommeParams,
        ports: Vec<PortForwardConfig>,
        remote_recv: Option<mesh::Receiver<ConsommeRequest>>,
        local_recv: Option<mesh::Receiver<ControlRequest>>,
    ) -> Self {
        let config = Arc::new(config);
        let primary = Consomme::new((*config).clone(), params);
        let mut consommes = Vec::with_capacity(MAX_CONSOMME_QUEUES);
        consommes.push(primary);
        for _ in 1..MAX_CONSOMME_QUEUES {
            consommes.push(consommes[0].new_data_shard());
        }
        ConsommeEndpoint {
            shards: consommes
                .into_iter()
                .map(|consomme| {
                    Mutex::new(EndpointShard {
                        consomme,
                        driver: None,
                        shard_stats: ShardStats::default(),
                        wake: Arc::new(ShardWake::new()),
                    })
                })
                .collect::<Vec<_>>()
                .into(),
            control: EndpointControl {
                port_forwards: ports,
                active_shards: 1,
                steering_seed: consomme::random_steering_seed(),
            },
            config,
            local_recv,
            remote_recv,
            pending: PendingRequests::default(),
        }
    }

    /// Drains available requests from both channels into `pending`, registering
    /// wakers for channels with nothing ready. Returns whether any new request
    /// was read.
    fn drain_channels(&mut self, cx: &mut Context<'_>) -> bool {
        let Self {
            local_recv,
            remote_recv,
            pending,
            ..
        } = self;
        // Borrow each receiver and `pending` separately so the shared buffering
        // logic can be reused for both channels without a borrow conflict.
        let mut received = drain_receiver(local_recv, cx, "control", |request| {
            pending.buffer_control(request)
        });
        received |= drain_receiver(remote_recv, cx, "port request", |request| {
            pending.buffer_request(request)
        });
        received
    }

    fn migrate_flows(&self, active_shards: usize) {
        for source in self.shards.iter() {
            let flows = {
                let mut source = source.lock();
                let dropped = source.consomme.discard_egress();
                source
                    .shard_stats
                    .migration_egress_drops
                    .add(dropped as u64);
                source.consomme.drain_flows()
            };
            for (target, flows) in flows
                .repartition(active_shards, self.control.steering_seed)
                .into_iter()
                .enumerate()
            {
                self.shards[target].lock().consomme.insert_flows(flows);
            }
        }
    }

    fn update_all_shards(&self, update: &ConsommeParamsUpdateFn) {
        for shard in self.shards.iter() {
            shard.lock().consomme.update_params(|params| update(params));
        }
    }
}

impl InspectMut for ConsommeEndpoint {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        resp.field("active_shards", self.control.active_shards)
            .field("steering_seed", self.control.steering_seed);
        for (index, shard) in self.shards.iter().enumerate() {
            let mut shard = shard.lock();
            resp.field_mut(&index.to_string(), &mut shard.consomme);
        }
    }
}

/// Provide dynamic updates during runtime.
pub struct ConsommeControl {
    send: mesh::Sender<ControlRequest>,
}

/// Error type returned from some dynamic update functions like bind_port.
#[derive(Debug, Error)]
pub enum ConsommeMessageError {
    /// Communication error with running instance.
    #[error("communication error")]
    Mesh(RpcError),
    /// Error executing request on current network instance.
    #[error("bind error")]
    Bind(consomme::BindError),
    /// Error from a remote operation on the endpoint.
    #[error(transparent)]
    Remote(mesh::error::RemoteError),
}

/// Callback to modify network state dynamically.
pub type ConsommeParamsUpdateFn = Box<dyn Fn(&mut ConsommeParams) + Send + Sync>;

#[derive(Debug, Clone, Copy)]
pub enum IpProtocol {
    Tcp,
    Udp,
}

impl From<HostPortProtocol> for IpProtocol {
    fn from(p: HostPortProtocol) -> Self {
        match p {
            HostPortProtocol::Tcp => IpProtocol::Tcp,
            HostPortProtocol::Udp => IpProtocol::Udp,
        }
    }
}

impl From<IpProtocol> for HostPortProtocol {
    fn from(p: IpProtocol) -> Self {
        match p {
            IpProtocol::Tcp => HostPortProtocol::Tcp,
            IpProtocol::Udp => HostPortProtocol::Udp,
        }
    }
}

/// In-proc control request. A superset of the cross-proc `ConsommeRequest` that
/// also carries operations which can't cross a process boundary.
enum ControlRequest {
    /// Port bind/unbind (same as the cross-proc request).
    Port(ConsommeRequest),
    /// Update dynamic network state (in-proc only).
    UpdateState(Rpc<ConsommeParamsUpdateFn, ()>),
}

impl ConsommeControl {
    /// Binds a port to receive incoming packets.
    pub async fn bind_port(
        &self,
        protocol: IpProtocol,
        ip_addr: Option<IpAddr>,
        host_port: u16,
        guest_port: u16,
    ) -> Result<(), ConsommeMessageError> {
        self.send
            .call(
                |rpc| ControlRequest::Port(ConsommeRequest::Bind(rpc)),
                HostPortConfig {
                    protocol: protocol.into(),
                    host_address: ip_addr.map(net_backend_resources::consomme::HostIpAddress::from),
                    host_port: net_backend_resources::consomme::HostPort::Fixed(host_port),
                    guest_port,
                },
            )
            .await
            .map_err(ConsommeMessageError::Mesh)?
            .map_err(ConsommeMessageError::Remote)
    }

    /// Unbinds a port previously reserved with bind_port(); `ip_addr` (or `None`)
    /// selects the address family to unbind.
    pub async fn unbind_port(
        &self,
        protocol: IpProtocol,
        ip_addr: Option<IpAddr>,
        guest_port: u16,
    ) -> Result<(), ConsommeMessageError> {
        self.send
            .call(
                |rpc| ControlRequest::Port(ConsommeRequest::Unbind(rpc)),
                HostPortConfig {
                    protocol: protocol.into(),
                    host_address: ip_addr.map(net_backend_resources::consomme::HostIpAddress::from),
                    host_port: net_backend_resources::consomme::HostPort::Fixed(0),
                    guest_port,
                },
            )
            .await
            .map_err(ConsommeMessageError::Mesh)?
            .map_err(ConsommeMessageError::Remote)
    }

    /// Updates dynamic network state
    pub async fn update_state(
        &self,
        f: ConsommeParamsUpdateFn,
    ) -> Result<(), ConsommeMessageError> {
        self.send
            .call(ControlRequest::UpdateState, f)
            .await
            .map_err(ConsommeMessageError::Mesh)
    }
}

#[async_trait]
impl net_backend::Endpoint for ConsommeEndpoint {
    fn endpoint_type(&self) -> &'static str {
        "consomme"
    }

    async fn get_queues(
        &mut self,
        config: Vec<QueueConfig>,
        _rss: Option<&RssConfig<'_>>,
        queues: &mut Vec<Box<dyn net_backend::Queue>>,
    ) -> anyhow::Result<()> {
        if config.is_empty() || config.len() > MAX_CONSOMME_QUEUES {
            anyhow::bail!("Consomme requires between 1 and {MAX_CONSOMME_QUEUES} queues");
        }
        let active_shards = config.len();
        if active_shards != self.control.active_shards {
            self.migrate_flows(active_shards);
            self.control.active_shards = active_shards;
        }

        let mut new_queues = Vec::with_capacity(active_shards);
        for (queue_index, config) in config.into_iter().enumerate() {
            let driver: Arc<dyn Driver> = Arc::from(config.driver);
            {
                let mut shard = self.shards[queue_index].lock();
                shard.driver = Some(driver.clone());
                shard
                    .consomme
                    .access(&mut ClientNoPool { driver: &*driver })
                    .refresh_driver();
            }
            new_queues.push(Box::new(ConsommeQueue {
                shards: self.shards.clone(),
                config: self.config.clone(),
                queue_index,
                active_shards,
                steering_seed: self.control.steering_seed,
                state: QueueState {
                    rx_avail: VecDeque::new(),
                    rx_ready: VecDeque::new(),
                    tx_avail: VecDeque::new(),
                    tx_ready: VecDeque::new(),
                    tx_scratch: Vec::new(),
                },
                stats: Default::default(),
                driver,
            }) as Box<dyn net_backend::Queue>);
        }

        for shard in self.shards.iter().skip(active_shards) {
            shard.lock().driver = None;
        }

        let port_forwards = std::mem::take(&mut self.control.port_forwards);
        let primary_driver = self.shards[0]
            .lock()
            .driver
            .clone()
            .context("active primary Consomme shard has no driver")?;
        let bind_result: anyhow::Result<Vec<_>> = {
            let mut shard = self.shards[0].lock();
            let mut client = ClientNoPool {
                driver: &*primary_driver,
            };
            let mut c = shard.consomme.access(&mut client);
            c.refresh_driver();
            let mut bound: Vec<(IpProtocol, IpVersion, u16)> = Vec::new();
            for fwd in port_forwards {
                let protocol = fwd.protocol;
                let guest_port = fwd.guest_port;
                let result = match socket_family(&fwd.socket) {
                    Ok(family) => {
                        let result = match protocol {
                            IpProtocol::Tcp => c.bind_tcp_port(fwd.socket, guest_port),
                            IpProtocol::Udp => c.bind_udp_port(fwd.socket, guest_port),
                        };
                        result.map(|()| (protocol, family, guest_port))
                    }
                    Err(err) => Err(err),
                };
                match result {
                    Ok(bound_entry) => bound.push(bound_entry),
                    Err(err) => {
                        // Roll back successful binds before returning error.
                        for (protocol, family, guest_port) in &bound {
                            let _ = match protocol {
                                IpProtocol::Tcp => c.unbind_tcp_port(*family, *guest_port),
                                IpProtocol::Udp => c.unbind_udp_port(*family, *guest_port),
                            };
                        }
                        return Err(anyhow::anyhow!(err).context("failed to bind port"));
                    }
                }
            }
            Ok(bound)
        };

        // Apply requests buffered while no queue was running (see
        // `wait_for_endpoint_action`). This runs regardless of whether the
        // static port-forward binding above succeeded, so the buffered RPCs
        // always complete here instead of stalling until some unrelated future
        // request triggers the next restart.
        let pending = std::mem::take(&mut self.pending);
        let PendingRequests {
            ports,
            state_updates,
        } = pending;
        {
            let mut shard = self.shards[0].lock();
            let mut client = ClientNoPool {
                driver: &*primary_driver,
            };
            let mut c = shard.consomme.access(&mut client);
            for request in ports.into_values() {
                process_port_request(&mut c, request);
            }
        }
        for rpc in state_updates {
            rpc.handle_sync(|f| self.update_all_shards(&f));
        }

        bind_result?;

        queues.extend(new_queues);
        Ok(())
    }

    async fn stop(&mut self) {
        for shard in self.shards.iter() {
            shard.lock().driver = None;
        }
    }

    fn is_ordered(&self) -> bool {
        true
    }

    fn tx_offload_support(&self) -> TxOffloadSupport {
        TxOffloadSupport {
            ipv4_header: true,
            tcp: true,
            udp: true,
            tso: true,
            uso: true,
        }
    }

    fn multiqueue_support(&self) -> net_backend::MultiQueueSupport {
        net_backend::MultiQueueSupport {
            max_queues: MAX_CONSOMME_QUEUES as u16,
            indirection_table_size: 0,
        }
    }

    async fn wait_for_endpoint_action(&mut self) -> EndpointAction {
        std::future::poll_fn(|cx| -> Poll<EndpointAction> {
            self.drain_channels(cx);
            if !self.pending.is_empty() {
                let driver = self.shards[0].lock().driver.clone();
                if let Some(driver) = driver {
                    let pending = std::mem::take(&mut self.pending);
                    let PendingRequests {
                        ports,
                        state_updates,
                    } = pending;
                    {
                        let mut state = self.shards[0].lock();
                        let mut client = ClientNoPool { driver: &*driver };
                        let mut consomme = state.consomme.access(&mut client);
                        for request in ports.into_values() {
                            process_port_request(&mut consomme, request);
                        }
                    }
                    for rpc in state_updates {
                        rpc.handle_sync(|f| self.update_all_shards(&f));
                    }
                }
            }
            Poll::Pending
        })
        .await
    }
}

pub struct ConsommeQueue {
    shards: Arc<[Mutex<EndpointShard>]>,
    config: Arc<ConsommeConfig>,
    queue_index: usize,
    active_shards: usize,
    steering_seed: u64,
    state: QueueState,
    stats: Stats,
    driver: Arc<dyn Driver>,
}

impl InspectMut for ConsommeQueue {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let mut state = self.lock_shard(self.queue_index);
        req.respond()
            .merge(&mut state.consomme)
            .field("shard_stats", &state.shard_stats)
            .field("rx_avail", self.state.rx_avail.len())
            .field("rx_ready", self.state.rx_ready.len())
            .field("tx_avail", self.state.tx_avail.len())
            .field("tx_ready", self.state.tx_ready.len())
            .field("stats", &self.stats);
    }
}

impl ConsommeQueue {
    fn lock_shard(&self, index: usize) -> MutexGuard<'_, EndpointShard> {
        if let Some(mut state) = self.shards[index].try_lock() {
            state.shard_stats.lock_acquisitions.increment();
            state
        } else {
            let mut state = self.shards[index].lock();
            state.shard_stats.lock_acquisitions.increment();
            state.shard_stats.contended_acquisitions.increment();
            state
        }
    }

    /// Ingests a frame that has already been copied out of guest memory.
    ///
    /// This acquires exactly one shard lock, never awaits while holding it,
    /// and never accesses frontend buffers. Foreign work wakes the shard owner
    /// only after protocol processing has buffered any resulting work.
    fn ingest_frame(
        &mut self,
        data: &[u8],
        checksum: &ChecksumState,
        foreign: bool,
    ) -> Result<(), consomme::DropReason> {
        let packet_class =
            consomme::classify_frame(data, consomme::PacketDirection::GuestToRemote, &self.config);
        let target = match packet_class {
            consomme::PacketClass::Flow(flow) => {
                flow.stable_hash(self.steering_seed) as usize % self.active_shards
            }
            consomme::PacketClass::Control => 0,
            consomme::PacketClass::Drop => {
                let mut state = self.lock_shard(self.queue_index);
                if foreign {
                    state.shard_stats.foreign_ingest.increment();
                } else {
                    state.shard_stats.local_ingest.increment();
                }
                state.shard_stats.malformed_ingest.increment();
                return Err(consomme::DropReason::MalformedPacket);
            }
        };
        let foreign = foreign || target != self.queue_index;
        let mut state = self.lock_shard(target);
        if foreign {
            state.shard_stats.foreign_ingest.increment();
        } else {
            state.shard_stats.local_ingest.increment();
        }
        match packet_class {
            consomme::PacketClass::Flow(_) => {}
            consomme::PacketClass::Control => state.shard_stats.control_ingest.increment(),
            consomme::PacketClass::Drop => unreachable!(),
        }
        let driver = state.driver.clone().unwrap_or_else(|| self.driver.clone());
        let result = state
            .consomme
            .access(&mut ClientNoPool { driver: &*driver })
            .send(data, checksum);
        if foreign {
            let wake = state.wake.clone();
            wake.wake(&mut state.shard_stats);
        }
        result
    }

    fn with_consomme_no_pool<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut consomme::Access<'_, ClientNoPool<'_>>) -> R,
    {
        let mut state = self.lock_shard(self.queue_index);
        f(&mut state.consomme.access(&mut ClientNoPool {
            driver: &*self.driver,
        }))
    }

    fn drain_egress(&mut self, pool: &mut dyn BufferAccess) {
        while let Some(rx_id) = self.state.rx_avail.pop_front() {
            let Some(packet) = self.lock_shard(self.queue_index).consomme.pop_egress() else {
                self.state.rx_avail.push_front(rx_id);
                break;
            };
            let checksum = packet.checksum();
            let max = pool.capacity(rx_id) as usize;
            if packet.data().len() <= max {
                pool.write_packet_segments(
                    rx_id,
                    &RxMetadata {
                        offset: 0,
                        len: packet.data().len(),
                        ip_checksum: if checksum.ipv4 {
                            RxChecksumState::Good
                        } else {
                            RxChecksumState::Unknown
                        },
                        l4_checksum: if checksum.tcp || checksum.udp {
                            RxChecksumState::Good
                        } else {
                            RxChecksumState::Unknown
                        },
                        l4_protocol: if checksum.tcp {
                            L4Protocol::Tcp
                        } else if checksum.udp {
                            L4Protocol::Udp
                        } else {
                            L4Protocol::Unknown
                        },
                        vlan: None,
                    },
                    &[packet.data()],
                );
                self.state.rx_ready.push_back(rx_id);
            } else {
                tracing::warn!(
                    len = packet.data().len(),
                    max,
                    "dropping rx packet: too large"
                );
                self.stats.rx_dropped.increment();
                self.state.rx_avail.push_front(rx_id);
            }
            self.lock_shard(self.queue_index)
                .consomme
                .recycle_egress(packet);
        }
    }
}

/// Execute a port bind: create a socket and forward it to the consomme stack.
fn execute_bind(
    consomme: &mut consomme::Access<'_, impl consomme::SocketDriver>,
    cfg: HostPortConfig,
) -> anyhow::Result<()> {
    use net_backend_resources::consomme::HostPort;

    if cfg.guest_port == 0 {
        anyhow::bail!("guest_port must be non-zero");
    }
    let (bind_port, dynamic_sender) = match cfg.host_port {
        HostPort::Fixed(port) => {
            if port == 0 {
                anyhow::bail!(
                    "host_port must be non-zero for Fixed port (ephemeral port selection is not supported)"
                );
            }
            (port, None)
        }
        HostPort::Dynamic(sender) => (0, Some(sender)),
    };
    let protocol: IpProtocol = cfg.protocol.clone().into();
    let ip_addr = cfg.host_address.as_ref().map(|a| IpAddr::from(a.clone()));
    let socket = create_bound_socket(&protocol, ip_addr, bind_port)
        .context("failed to create and bind socket")?;
    let dynamic_port = match dynamic_sender {
        Some(sender) => {
            let addr = socket_addr(&socket).context("failed to get bound address")?;
            Some((sender, addr.port()))
        }
        None => None,
    };
    let result = match protocol {
        IpProtocol::Tcp => consomme.bind_tcp_port(socket, cfg.guest_port),
        IpProtocol::Udp => consomme.bind_udp_port(socket, cfg.guest_port),
    };
    result.context("failed to bind port")?;
    if let Some((sender, port)) = dynamic_port {
        sender.send(port);
    }
    Ok(())
}

/// Execute a port unbind.
fn execute_unbind(
    consomme: &mut consomme::Access<'_, impl consomme::SocketDriver>,
    cfg: &HostPortConfig,
) -> anyhow::Result<()> {
    use net_backend_resources::consomme::HostIpAddress;

    let protocol: IpProtocol = cfg.protocol.clone().into();
    let family = match &cfg.host_address {
        Some(HostIpAddress::Ipv4(_)) | None => IpVersion::Ipv4,
        Some(HostIpAddress::Ipv6(_)) => IpVersion::Ipv6,
    };
    let result = match protocol {
        IpProtocol::Tcp => consomme.unbind_tcp_port(family, cfg.guest_port),
        IpProtocol::Udp => consomme.unbind_udp_port(family, cfg.guest_port),
    };
    result.context("failed to unbind port")
}

/// Returned to a port request superseded by a newer one for the same port.
#[derive(Debug, Error)]
#[error("port request superseded by a newer request for the same guest port")]
struct PortRequestSuperseded;

/// Extracts the inner RPC from a `ConsommeRequest` to complete a coalesced one.
fn into_rpc(request: ConsommeRequest) -> mesh::rpc::FailableRpc<HostPortConfig, ()> {
    match request {
        ConsommeRequest::Bind(rpc) | ConsommeRequest::Unbind(rpc) => rpc,
    }
}

/// Handle a `ConsommeRequest` (shared by both in-proc and cross-proc paths).
fn process_port_request(
    consomme: &mut consomme::Access<'_, impl consomme::SocketDriver>,
    request: ConsommeRequest,
) {
    match request {
        ConsommeRequest::Bind(rpc) => {
            rpc.handle_failable_sync(
                |cfg| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    let guest_port = cfg.guest_port;
                    execute_bind(consomme, cfg)?;
                    tracing::info!(guest_port, "port forward bound");
                    Ok(())
                },
            );
        }
        ConsommeRequest::Unbind(rpc) => {
            rpc.handle_failable_sync(
                |cfg| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    execute_unbind(consomme, &cfg)?;
                    tracing::info!(guest_port = cfg.guest_port, "port forward unbound");
                    Ok(())
                },
            );
        }
    }
}

impl net_backend::Queue for ConsommeQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, pool: &mut dyn BufferAccess) -> Poll<()> {
        self.lock_shard(self.queue_index).wake.register(cx);
        while let Some(head) = self.state.tx_avail.front() {
            let TxSegmentType::Head(meta) = &head.ty else {
                unreachable!()
            };
            let tx_id = meta.id;
            let checksum = ChecksumState {
                ipv4: meta.flags.offload_ip_header_checksum(),
                tcp: meta.flags.offload_tcp_checksum(),
                udp: meta.flags.offload_udp_checksum(),
                tso: meta
                    .flags
                    .offload_tcp_segmentation()
                    .then_some(meta.max_segment_size),
                gso: meta
                    .flags
                    .offload_udp_segmentation()
                    .then_some(meta.max_segment_size),
            };

            // Reuse the scratch buffer to avoid per-packet heap allocation.
            // TSO caps the assembled packet at 64 KiB; assert so a buggy
            // upstream caller can't permanently inflate the scratch buffer
            // (and thus the queue's steady-state memory) by feeding an
            // oversized `meta.len`.
            debug_assert!(
                meta.len as usize <= 64 * 1024,
                "tx packet len {} exceeds 64 KiB TSO bound",
                meta.len
            );
            let mut buf = std::mem::take(&mut self.state.tx_scratch);
            buf.clear();
            buf.resize(meta.len as usize, 0);
            let gm = pool.guest_memory();
            let mut offset = 0;
            for segment in self.state.tx_avail.drain(..meta.segment_count as usize) {
                let dest = &mut buf[offset..offset + segment.len as usize];
                if let Err(err) = gm.read_at(segment.gpa, dest) {
                    tracing::error!(
                        error = &err as &dyn std::error::Error,
                        "memory write failure"
                    );
                }
                offset += segment.len as usize;
            }

            if let Err(err) = self.ingest_frame(&buf, &checksum, false) {
                tracing::debug!(error = &err as &dyn std::error::Error, "tx packet ignored");
                match err {
                    consomme::DropReason::SendBufferFull
                    | consomme::DropReason::DestinationNotAllowed => {
                        self.stats.tx_dropped.increment()
                    }
                    consomme::DropReason::UnsupportedEthertype(_)
                    | consomme::DropReason::UnsupportedIpProtocol(_)
                    | consomme::DropReason::UnsupportedIcmpv6(_)
                    | consomme::DropReason::UnsupportedDhcp(_)
                    | consomme::DropReason::UnsupportedArp
                    | consomme::DropReason::UnsupportedDhcpv6(_)
                    | consomme::DropReason::UnsupportedNdp(_) => self.stats.tx_unknown.increment(),
                    consomme::DropReason::Packet(_)
                    | consomme::DropReason::Ipv4Checksum
                    | consomme::DropReason::Io(_)
                    | consomme::DropReason::BadTcpState(_)
                    | consomme::DropReason::FragmentedPacket
                    | consomme::DropReason::IpLengthMismatch
                    | consomme::DropReason::MalformedPacket => self.stats.tx_errors.increment(),
                }
            }
            self.drain_egress(pool);
            self.state.tx_scratch = buf;

            self.state.tx_ready.push_back(tx_id);
        }

        self.with_consomme_no_pool(|c| c.poll(cx));
        self.drain_egress(pool);

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

struct QueueState {
    rx_avail: VecDeque<RxId>,
    rx_ready: VecDeque<RxId>,
    tx_avail: VecDeque<TxSegment>,
    tx_ready: VecDeque<TxId>,
    /// Reusable scratch buffer for assembling outbound packets from guest memory.
    /// The max TSO size is 64KB which limits the maximum size of the scratch buffer.
    tx_scratch: Vec<u8>,
}

#[derive(Inspect, Default)]
struct Stats {
    rx_dropped: Counter,
    tx_dropped: Counter,
    tx_errors: Counter,
    tx_unknown: Counter,
}

struct ClientNoPool<'a> {
    driver: &'a dyn Driver,
}

impl consomme::SocketDriver for ClientNoPool<'_> {
    fn driver(&self) -> &dyn Driver {
        self.driver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_backend::Endpoint as _;
    use net_backend_resources::consomme::HostPort;
    use pal_async::DefaultDriver;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Waker;

    fn cfg(guest_port: u16) -> HostPortConfig {
        HostPortConfig {
            protocol: HostPortProtocol::Tcp,
            host_address: None,
            host_port: HostPort::Fixed(8080),
            guest_port,
        }
    }

    fn endpoint() -> ConsommeEndpoint {
        ConsommeEndpoint::new(ConsommeConfig::new(), ConsommeParams::new().unwrap())
    }

    fn queue(endpoint: &ConsommeEndpoint, driver: DefaultDriver) -> ConsommeQueue {
        ConsommeQueue {
            shards: endpoint.shards.clone(),
            config: endpoint.config.clone(),
            queue_index: 0,
            active_shards: 1,
            steering_seed: endpoint.control.steering_seed,
            state: QueueState {
                rx_avail: VecDeque::new(),
                rx_ready: VecDeque::new(),
                tx_avail: VecDeque::new(),
                tx_ready: VecDeque::new(),
                tx_scratch: Vec::new(),
            },
            stats: Stats::default(),
            driver: Arc::new(driver),
        }
    }

    #[test]
    fn owner_wakes_are_coalesced() {
        let wake = ShardWake::new();
        let mut stats = ShardStats::default();
        let cx = Context::from_waker(Waker::noop());
        wake.register(&cx);
        wake.wake(&mut stats);
        wake.wake(&mut stats);
        assert_eq!(stats.owner_wakes.get(), 1);
        assert_eq!(stats.coalesced_wakes.get(), 1);
    }

    #[pal_async::async_test]
    async fn local_and_foreign_ingest_share_one_shard(driver: DefaultDriver) {
        let endpoint = endpoint();
        let mut queue = queue(&endpoint, driver);
        let malformed = [0u8; 1];
        let checksum = ChecksumState::default();
        let _ = queue.ingest_frame(&malformed, &checksum, false);
        let _ = queue.ingest_frame(&malformed, &checksum, true);
        let state = endpoint.shards[0].lock();
        assert_eq!(state.shard_stats.local_ingest.get(), 1);
        assert_eq!(state.shard_stats.foreign_ingest.get(), 1);
    }

    #[pal_async::async_test]
    async fn queue_recreation_preserves_endpoint_state(driver: DefaultDriver) {
        let endpoint = endpoint();
        endpoint.shards[0]
            .lock()
            .consomme
            .update_params(|params| params.allow_host_local_access = true);
        drop(queue(&endpoint, driver.clone()));
        let _replacement = queue(&endpoint, driver);
        assert!(
            endpoint.shards[0]
                .lock()
                .consomme
                .params()
                .allow_host_local_access
        );
    }

    #[pal_async::async_test]
    async fn one_queue_endpoint_starts(driver: DefaultDriver) {
        let mut endpoint = endpoint();
        let mut queues = Vec::new();
        endpoint
            .get_queues(
                vec![QueueConfig {
                    driver: Box::new(driver),
                }],
                None,
                &mut queues,
            )
            .await
            .unwrap();
        assert_eq!(queues.len(), 1);
    }

    #[pal_async::async_test]
    async fn control_update_completes_with_idle_queue(driver: DefaultDriver) {
        let (mut endpoint, control) =
            ConsommeEndpoint::new_dynamic(ConsommeConfig::new(), ConsommeParams::new().unwrap());
        endpoint.shards[0].lock().driver = Some(Arc::new(driver));
        let mut update = Box::pin(control.update_state(Box::new(|params| {
            params.allow_host_local_access = true;
        })));
        let mut action = Box::pin(endpoint.wait_for_endpoint_action());
        let mut cx = Context::from_waker(Waker::noop());

        assert!(Pin::new(&mut update).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut action).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut update).poll(&mut cx).is_ready());
        drop(action);
        assert!(
            endpoint.shards[0]
                .lock()
                .consomme
                .params()
                .allow_host_local_access
        );
    }

    #[test]
    fn unbind_cancels_pending_bind() {
        let mut ep = endpoint();
        ep.pending
            .buffer_request(ConsommeRequest::Bind(Rpc::detached(cfg(80))));
        assert_eq!(ep.pending.ports.len(), 1);
        // An unbind for the same port annihilates the not-yet-applied bind.
        ep.pending
            .buffer_request(ConsommeRequest::Unbind(Rpc::detached(cfg(80))));
        assert!(ep.pending.ports.is_empty());
    }

    #[test]
    fn newer_request_supersedes_same_port() {
        let mut ep = endpoint();
        ep.pending
            .buffer_request(ConsommeRequest::Bind(Rpc::detached(cfg(80))));
        ep.pending
            .buffer_request(ConsommeRequest::Bind(Rpc::detached(cfg(80))));
        // The two binds collapse to a single pending entry.
        assert_eq!(ep.pending.ports.len(), 1);
    }

    #[test]
    fn different_ports_are_independent() {
        let mut ep = endpoint();
        ep.pending
            .buffer_request(ConsommeRequest::Bind(Rpc::detached(cfg(80))));
        ep.pending
            .buffer_request(ConsommeRequest::Bind(Rpc::detached(cfg(81))));
        assert_eq!(ep.pending.ports.len(), 2);
    }

    #[test]
    fn drain_is_edge_triggered() {
        use std::task::Context;
        use std::task::Waker;

        let (send, recv) = mesh::channel::<ConsommeRequest>();
        let mut ep = ConsommeEndpoint::new_with_port_channel(
            ConsommeConfig::new(),
            ConsommeParams::new().unwrap(),
            Vec::new(),
            recv,
        );
        let mut cx = Context::from_waker(Waker::noop());

        // No requests yet: nothing read.
        assert!(!ep.drain_channels(&mut cx));

        // A request becomes available: read exactly once.
        send.send(ConsommeRequest::Bind(Rpc::detached(cfg(80))));
        assert!(ep.drain_channels(&mut cx));
        assert_eq!(ep.pending.ports.len(), 1);

        // Nothing new, even though `pending` is non-empty: no re-trigger (this
        // is what stops the frontend's restart-coalescing loop from spinning).
        assert!(!ep.drain_channels(&mut cx));
    }
}
