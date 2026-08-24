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
use consomme::ConsommeControl as ConsommeControlState;
use consomme::ConsommeParams;
use consomme::ConsommeShard;
pub use consomme::IpVersion;
pub use consomme::StaticDnsRecord;
pub use consomme::StaticDnsRecordError;
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
use net_backend_resources::consomme::DnsRecordConfig;
use net_backend_resources::consomme::HostIpAddress;
use net_backend_resources::consomme::HostPortConfig;
use net_backend_resources::consomme::HostPortProtocol;
use pal_async::driver::Driver;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use thiserror::Error;

const MAX_EGRESS_PACKETS: usize = 256;
const EGRESS_MTU: usize = u16::MAX as usize;

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
    endpoint_state: Arc<Mutex<EndpointState>>,
    /// In-process state updates, which cannot cross a process boundary.
    state_update_recv: Option<mesh::Receiver<StateUpdateRequest>>,
    /// Serializable requests originating either in-process or remotely.
    request_recv: Option<mesh::Receiver<ConsommeRequest>>,
    /// Requests buffered while the queue owns the consomme state, applied in
    /// order on the next queue restart.
    pending: VecDeque<PendingRequest>,
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

/// Configuration for a port to forward from the host to the guest.
pub struct PortForwardConfig {
    /// The protocol to forward.
    pub protocol: IpProtocol,
    /// An already-bound host socket to forward traffic from.
    pub socket: socket2::Socket,
    /// The port traffic is forwarded to on the guest.
    pub guest_port: u16,
}

struct EndpointState {
    control: Arc<Mutex<ConsommeControlState>>,
    initial_shard: Option<ConsommeShard>,
    shards: Vec<ShardHandle>,
    queue_count: Option<usize>,
    port_forwards: Vec<PortForwardConfig>,
}

#[derive(Clone)]
struct ShardHandle {
    state: Arc<Mutex<ShardState>>,
    wake: Arc<Mutex<Option<Waker>>>,
}

struct ShardState {
    core: ConsommeShard,
    driver: Box<dyn Driver>,
    egress: VecDeque<OwnedPacket>,
    egress_dropped: Counter,
    active: bool,
}

struct OwnedPacket {
    data: Vec<u8>,
    checksum: ChecksumState,
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
        let (request_send, request_recv) = mesh::channel();
        let (state_update_send, state_update_recv) = mesh::channel();
        (
            Self::with_state(
                config,
                params,
                Vec::new(),
                Some(request_recv),
                Some(state_update_recv),
            ),
            ConsommeControl {
                request_send,
                state_update_send,
            },
        )
    }

    /// Creates a new endpoint with initial ports and a channel for serializable
    /// runtime requests from an external source (e.g. ttrpc server).
    pub fn new_with_request_channel(
        config: ConsommeConfig,
        params: ConsommeParams,
        ports: Vec<PortForwardConfig>,
        request_recv: mesh::Receiver<ConsommeRequest>,
    ) -> Self {
        Self::with_state(config, params, ports, Some(request_recv), None)
    }

    fn with_state(
        config: ConsommeConfig,
        params: ConsommeParams,
        ports: Vec<PortForwardConfig>,
        request_recv: Option<mesh::Receiver<ConsommeRequest>>,
        state_update_recv: Option<mesh::Receiver<StateUpdateRequest>>,
    ) -> Self {
        let (control, shard) = Consomme::new(config, params).into_parts();
        ConsommeEndpoint {
            endpoint_state: Arc::new(Mutex::new(EndpointState {
                control: Arc::new(Mutex::new(control)),
                initial_shard: Some(shard),
                shards: Vec::new(),
                queue_count: None,
                port_forwards: ports,
            })),
            state_update_recv,
            request_recv,
            pending: VecDeque::new(),
        }
    }

    /// Drains available requests from both channels into `pending`, registering
    /// wakers for channels with nothing ready. Returns whether any new request
    /// was read.
    fn drain_channels(&mut self, cx: &mut Context<'_>) -> bool {
        let Self {
            state_update_recv,
            request_recv,
            pending,
            ..
        } = self;
        let mut received = drain_receiver(state_update_recv, cx, "state update", |request| {
            pending.push_back(PendingRequest::StateUpdate(request))
        });
        received |= drain_receiver(request_recv, cx, "request", |request| {
            pending.push_back(PendingRequest::Request(request))
        });
        received
    }
}

impl InspectMut for ConsommeEndpoint {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let state = self.endpoint_state.lock();
        let mut control = state.control.lock();
        control.inspect_mut(req);
    }
}

/// Provide dynamic updates during runtime.
pub struct ConsommeControl {
    request_send: mesh::Sender<ConsommeRequest>,
    state_update_send: mesh::Sender<StateUpdateRequest>,
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
    /// Error adding a static DNS record.
    #[error("dns record error: {0}")]
    DnsRecord(#[source] StaticDnsRecordError),
    /// The subnet's virtual address pool is exhausted, so no virtual address
    /// could be allocated.
    #[error("virtual address pool exhausted")]
    VirtualAddressPoolExhausted,
}

/// Callback to modify network state dynamically.
pub type ConsommeParamsUpdateFn = Box<dyn Fn(&mut ConsommeParams) + Send + Sync>;

type StateUpdateRequest = Rpc<ConsommeParamsUpdateFn, ()>;

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

/// A request buffered until the endpoint regains ownership of the Consomme state.
enum PendingRequest {
    Request(ConsommeRequest),
    StateUpdate(StateUpdateRequest),
}

impl ConsommeControl {
    /// Binds a port to receive incoming packets.
    pub async fn bind_port(
        &self,
        protocol: IpProtocol,
        ip_addr: Option<IpAddr>,
        host_port: u16,
        guest_port: u16,
    ) -> Result<u16, ConsommeMessageError> {
        let (host_port_config, assigned_port) = if host_port == 0 {
            let (send, recv) = mesh::oneshot();
            (
                net_backend_resources::consomme::HostPort::Dynamic(send),
                Some(recv),
            )
        } else {
            (
                net_backend_resources::consomme::HostPort::Fixed(host_port),
                None,
            )
        };
        self.request_send
            .call(
                ConsommeRequest::Bind,
                HostPortConfig {
                    protocol: protocol.into(),
                    host_address: ip_addr.map(HostIpAddress::from),
                    host_port: host_port_config,
                    guest_port,
                },
            )
            .await
            .map_err(ConsommeMessageError::Mesh)?
            .map_err(ConsommeMessageError::Remote)?;
        match assigned_port {
            Some(recv) => recv
                .await
                .map_err(|err| ConsommeMessageError::Mesh(RpcError::Channel(err))),
            None => Ok(host_port),
        }
    }

    /// Unbinds a port previously reserved with bind_port(); `ip_addr` (or `None`)
    /// selects the address family to unbind.
    pub async fn unbind_port(
        &self,
        protocol: IpProtocol,
        ip_addr: Option<IpAddr>,
        guest_port: u16,
    ) -> Result<(), ConsommeMessageError> {
        self.request_send
            .call(
                ConsommeRequest::Unbind,
                HostPortConfig {
                    protocol: protocol.into(),
                    host_address: ip_addr.map(HostIpAddress::from),
                    // Unbind identifies a forward by protocol, family, and guest port.
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
        self.state_update_send
            .call(|rpc| rpc, f)
            .await
            .map_err(ConsommeMessageError::Mesh)
    }

    /// Adds a static DNS record that will be returned directly
    /// if the guest sends a matching query.
    pub async fn add_dns_record(
        &self,
        record: StaticDnsRecord,
        name: String,
    ) -> Result<(), ConsommeMessageError> {
        let StaticDnsRecord::A(addr) = record;
        self.request_send
            .call(
                ConsommeRequest::AddDnsRecord,
                DnsRecordConfig { record: addr, name },
            )
            .await
            .map_err(ConsommeMessageError::Mesh)?
            .map_err(ConsommeMessageError::Remote)
    }

    /// Allocates a virtual IP address within the endpoint's subnet and routes
    /// guest traffic sent to it to `destination` on the host.
    ///
    /// Returns [`ConsommeMessageError::VirtualAddressPoolExhausted`] if the
    /// subnet's virtual address pool is exhausted.
    pub async fn create_virtual_address(
        &self,
        destination: IpAddr,
    ) -> Result<IpAddr, ConsommeMessageError> {
        self.request_send
            .call(
                ConsommeRequest::CreateVirtualAddress,
                HostIpAddress::from(destination),
            )
            .await
            .map_err(ConsommeMessageError::Mesh)?
            .map(IpAddr::from)
            .ok_or(ConsommeMessageError::VirtualAddressPoolExhausted)
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
        if config.is_empty() {
            anyhow::bail!("consomme requires at least one data queue");
        }

        let (control, shard_handles, port_forwards) = {
            let mut endpoint_state = self.endpoint_state.lock();
            match endpoint_state.queue_count {
                Some(queue_count) if queue_count != config.len() => {
                    anyhow::bail!(
                        "changing consomme queue count from {queue_count} to {} is not supported",
                        config.len()
                    );
                }
                Some(_) => {}
                None => {
                    endpoint_state.queue_count = Some(config.len());
                }
            }

            if endpoint_state
                .shards
                .iter()
                .any(|shard| shard.state.lock().active)
            {
                anyhow::bail!("consomme data queues are already running");
            }

            if endpoint_state.shards.is_empty() {
                let mut initial_shard = Some(
                    endpoint_state
                        .initial_shard
                        .take()
                        .context("initial consomme shard is unavailable")?,
                );
                for (index, config) in config.into_iter().enumerate() {
                    let core = if index == 0 {
                        initial_shard.take().unwrap()
                    } else {
                        endpoint_state.control.lock().new_shard()
                    };
                    endpoint_state.shards.push(ShardHandle {
                        state: Arc::new(Mutex::new(ShardState {
                            core,
                            driver: config.driver,
                            egress: VecDeque::new(),
                            egress_dropped: Counter::new(),
                            active: true,
                        })),
                        wake: Arc::new(Mutex::new(None)),
                    });
                }
            } else {
                for (shard, config) in endpoint_state.shards.iter().zip(config) {
                    let mut state = shard.state.lock();
                    state.driver = config.driver;
                    state.active = true;
                }
            }

            (
                endpoint_state.control.clone(),
                endpoint_state.shards.clone(),
                std::mem::take(&mut endpoint_state.port_forwards),
            )
        };

        let shards: Arc<[ShardHandle]> = shard_handles.into();
        let mut data_queues = Vec::with_capacity(shards.len());
        for index in 0..shards.len() {
            data_queues.push(Box::new(ConsommeQueue {
                control: control.clone(),
                shards: shards.clone(),
                index,
                state: QueueState {
                    rx_avail: VecDeque::new(),
                    rx_ready: VecDeque::new(),
                    tx_avail: VecDeque::new(),
                    tx_ready: VecDeque::new(),
                    tx_scratch: Vec::new(),
                },
                stats: Default::default(),
            }));
        }

        for queue in &mut data_queues {
            queue.with_consomme_no_pool(|c| c.refresh_driver());
        }

        let control_queue = &mut data_queues[0];
        let bind_result: Result<Vec<_>, _> = control_queue.with_consomme_no_pool(|c| {
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
        });

        // Apply requests buffered while the queue owned the Consomme state (see
        // `wait_for_endpoint_action`). This runs regardless of whether the
        // static port-forward binding above succeeded, so the buffered RPCs
        // always complete here instead of stalling until some unrelated future
        // request triggers the next restart.
        let pending = std::mem::take(&mut self.pending);
        control_queue.with_consomme_no_pool(|c| {
            for request in pending {
                match request {
                    PendingRequest::Request(request) => process_request(c, request),
                    PendingRequest::StateUpdate(rpc) => {
                        rpc.handle_sync(|f| {
                            c.update_params(f);
                            c.update_dns_nameservers();
                        });
                    }
                }
            }
        });

        bind_result?;

        queues.extend(
            data_queues
                .into_iter()
                .map(|queue| queue as Box<dyn net_backend::Queue>),
        );
        Ok(())
    }

    async fn stop(&mut self) {
        assert!(
            self.endpoint_state
                .lock()
                .shards
                .iter()
                .all(|shard| !shard.state.lock().active)
        );
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
            max_queues: 64,
            indirection_table_size: 0,
        }
    }

    async fn wait_for_endpoint_action(&mut self) -> EndpointAction {
        std::future::poll_fn(|cx| {
            if self.drain_channels(cx) && !self.pending.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        EndpointAction::RestartRequired
    }
}

pub struct ConsommeQueue {
    control: Arc<Mutex<ConsommeControlState>>,
    shards: Arc<[ShardHandle]>,
    index: usize,
    state: QueueState,
    stats: Stats,
}

impl InspectMut for ConsommeQueue {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        let mut control = self.control.lock();
        let mut shard = self.shards[self.index].state.lock();
        req.respond()
            .merge(&mut *control)
            .merge(&mut shard.core)
            .field("egress_depth", shard.egress.len())
            .field("egress_dropped", &shard.egress_dropped)
            .field("rx_avail", self.state.rx_avail.len())
            .field("rx_ready", self.state.rx_ready.len())
            .field("tx_avail", self.state.tx_avail.len())
            .field("tx_ready", self.state.tx_ready.len())
            .field("stats", &self.stats);
    }
}

impl Drop for ConsommeQueue {
    fn drop(&mut self) {
        self.shards[self.index].state.lock().active = false;
    }
}

impl ConsommeQueue {
    fn with_consomme_no_pool<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut consomme::Access<'_, ClientNoPool<'_>>) -> R,
    {
        let mut control = self.control.lock();
        let mut shard = self.shards[self.index].state.lock();
        let ShardState { core, driver, .. } = &mut *shard;
        f(&mut control.access(
            core,
            &mut ClientNoPool {
                driver: driver.as_ref(),
            },
        ))
    }

    fn with_consomme<F, R>(&self, shard_index: usize, f: F) -> R
    where
        F: FnOnce(&mut consomme::Access<'_, CoreClient<'_>>) -> R,
    {
        let mut control = self.control.lock();
        let mut shard = self.shards[shard_index].state.lock();
        let ShardState {
            core,
            driver,
            egress,
            egress_dropped,
            ..
        } = &mut *shard;
        f(&mut control.access(
            core,
            &mut CoreClient {
                egress,
                egress_dropped,
                driver: driver.as_ref(),
            },
        ))
    }

    fn wake_shard(&self, shard_index: usize) {
        if let Some(waker) = self.shards[shard_index].wake.lock().take() {
            waker.wake();
        }
    }

    fn shard_for_packet(&self, data: &[u8]) -> usize {
        self.control
            .lock()
            .shard_for_packet(data, self.shards.len())
    }

    fn drain_egress(&mut self, pool: &mut dyn BufferAccess) {
        while let Some(rx_id) = self.state.rx_avail.pop_front() {
            let packet = self.shards[self.index].state.lock().egress.pop_front();
            let Some(packet) = packet else {
                self.state.rx_avail.push_front(rx_id);
                break;
            };

            let max = pool.capacity(rx_id) as usize;
            if packet.data.len() > max {
                self.stats.rx_dropped.increment();
                self.state.rx_avail.push_front(rx_id);
                continue;
            }

            pool.write_packet(
                rx_id,
                &RxMetadata {
                    offset: 0,
                    len: packet.data.len(),
                    ip_checksum: if packet.checksum.ipv4 {
                        RxChecksumState::Good
                    } else {
                        RxChecksumState::Unknown
                    },
                    l4_checksum: if packet.checksum.tcp || packet.checksum.udp {
                        RxChecksumState::Good
                    } else {
                        RxChecksumState::Unknown
                    },
                    l4_protocol: if packet.checksum.tcp {
                        L4Protocol::Tcp
                    } else if packet.checksum.udp {
                        L4Protocol::Udp
                    } else {
                        L4Protocol::Unknown
                    },
                    vlan: None,
                },
                &packet.data,
            );
            self.state.rx_ready.push_back(rx_id);
        }
    }
}

/// Execute a port bind: create a socket and forward it to the consomme stack.
fn execute_bind(
    consomme: &mut consomme::Access<'_, impl consomme::Client>,
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
    consomme: &mut consomme::Access<'_, impl consomme::Client>,
    cfg: &HostPortConfig,
) -> anyhow::Result<()> {
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

/// Handle a request that may have originated in-process or remotely.
fn process_request(
    consomme: &mut consomme::Access<'_, impl consomme::Client>,
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
        ConsommeRequest::CreateVirtualAddress(rpc) => {
            rpc.handle_sync(|destination| {
                consomme
                    .create_virtual_address(destination.into())
                    .map(HostIpAddress::from)
            });
        }
        ConsommeRequest::AddDnsRecord(rpc) => {
            rpc.handle_failable_sync(|cfg: DnsRecordConfig| {
                consomme.add_dns_record(StaticDnsRecord::A(cfg.record), &cfg.name)
            });
        }
    }
}

impl net_backend::Queue for ConsommeQueue {
    fn poll_ready(&mut self, cx: &mut Context<'_>, pool: &mut dyn BufferAccess) -> Poll<()> {
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

            let shard_index = self.shard_for_packet(&buf);
            if let Err(err) = self.with_consomme(shard_index, |c| c.send(&buf, &checksum)) {
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
            self.wake_shard(shard_index);
            self.state.tx_scratch = buf;

            self.state.tx_ready.push_back(tx_id);
        }

        self.with_consomme(self.index, |c| c.poll(cx));
        self.drain_egress(pool);

        if !self.state.tx_ready.is_empty() || !self.state.rx_ready.is_empty() {
            Poll::Ready(())
        } else {
            *self.shards[self.index].wake.lock() = Some(cx.waker().clone());
            self.drain_egress(pool);
            if !self.state.rx_ready.is_empty() {
                self.shards[self.index].wake.lock().take();
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    fn rx_avail(&mut self, _pool: &mut dyn BufferAccess, done: &[RxId]) {
        self.state.rx_avail.extend(done);
        self.wake_shard(self.index);
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

struct CoreClient<'a> {
    egress: &'a mut VecDeque<OwnedPacket>,
    egress_dropped: &'a mut Counter,
    driver: &'a dyn Driver,
}

/// Minimal client for consomme operations that don't need BufferAccess
/// (e.g., refresh_driver, timer/socket management).
struct ClientNoPool<'a> {
    driver: &'a dyn Driver,
}

impl consomme::Client for ClientNoPool<'_> {
    fn driver(&self) -> &dyn Driver {
        self.driver
    }

    fn recv(&mut self, _data: &[u8], _checksum: &ChecksumState) {}

    fn rx_mtu(&mut self) -> usize {
        0
    }
}

impl consomme::Client for CoreClient<'_> {
    fn driver(&self) -> &dyn Driver {
        self.driver
    }

    fn recv(&mut self, data: &[u8], checksum: &ChecksumState) {
        self.recv_segments(&[data], checksum);
    }

    fn recv_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState) {
        if self.egress.len() >= MAX_EGRESS_PACKETS {
            self.egress_dropped.increment();
            return;
        }
        let len: usize = segments.iter().map(|s| s.len()).sum();
        if len > EGRESS_MTU {
            self.egress_dropped.increment();
            return;
        }
        let mut data = Vec::with_capacity(len);
        for segment in segments {
            data.extend_from_slice(segment);
        }
        self.egress.push_back(OwnedPacket {
            data,
            checksum: *checksum,
        });
    }

    fn rx_mtu(&mut self) -> usize {
        if self.egress.len() < MAX_EGRESS_PACKETS {
            EGRESS_MTU
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_backend_resources::consomme::HostPort;
    use pal_async::DefaultDriver;

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

    #[pal_async::async_test]
    async fn core_client_owns_egress_bytes(driver: DefaultDriver) {
        let mut egress = VecDeque::new();
        let mut egress_dropped = Counter::new();
        let checksum = ChecksumState {
            ipv4: true,
            tcp: true,
            udp: false,
            tso: None,
            gso: None,
        };
        let mut client = CoreClient {
            egress: &mut egress,
            egress_dropped: &mut egress_dropped,
            driver: &driver,
        };

        consomme::Client::recv_segments(&mut client, &[b"abc", b"def"], &checksum);

        let packet = egress.pop_front().unwrap();
        assert_eq!(packet.data, b"abcdef");
        assert!(packet.checksum.ipv4);
        assert!(packet.checksum.tcp);
    }

    #[pal_async::async_test]
    async fn creates_one_data_queue_per_config(driver: DefaultDriver) {
        let mut ep = endpoint();
        let make_configs = || {
            (0..3)
                .map(|_| QueueConfig {
                    driver: Box::new(driver.clone()),
                })
                .collect()
        };

        let mut queues = Vec::new();
        net_backend::Endpoint::get_queues(&mut ep, make_configs(), None, &mut queues)
            .await
            .unwrap();

        assert_eq!(queues.len(), 3);
        assert_eq!(ep.endpoint_state.lock().shards.len(), 3);
        assert!(
            ep.endpoint_state
                .lock()
                .shards
                .iter()
                .all(|shard| shard.state.lock().active)
        );

        drop(queues);
        assert!(
            ep.endpoint_state
                .lock()
                .shards
                .iter()
                .all(|shard| !shard.state.lock().active)
        );

        let mut restarted_queues = Vec::new();
        net_backend::Endpoint::get_queues(&mut ep, make_configs(), None, &mut restarted_queues)
            .await
            .unwrap();
        assert_eq!(restarted_queues.len(), 3);
    }

    #[test]
    fn requests_for_same_port_remain_ordered() {
        let mut ep = endpoint();
        ep.pending
            .push_back(PendingRequest::Request(ConsommeRequest::Bind(
                Rpc::detached(cfg(80)),
            )));
        ep.pending
            .push_back(PendingRequest::Request(ConsommeRequest::Unbind(
                Rpc::detached(cfg(80)),
            )));

        assert!(matches!(
            ep.pending.pop_front(),
            Some(PendingRequest::Request(ConsommeRequest::Bind(_)))
        ));
        assert!(matches!(
            ep.pending.pop_front(),
            Some(PendingRequest::Request(ConsommeRequest::Unbind(_)))
        ));
    }

    #[test]
    fn virtual_address_uses_remote_channel() {
        use std::task::Context;
        use std::task::Waker;

        let (send, recv) = mesh::channel::<ConsommeRequest>();
        let mut ep = ConsommeEndpoint::new_with_request_channel(
            ConsommeConfig::new(),
            ConsommeParams::new().unwrap(),
            Vec::new(),
            recv,
        );
        send.send(ConsommeRequest::CreateVirtualAddress(Rpc::detached(
            HostIpAddress::Ipv4(Ipv4Addr::LOCALHOST),
        )));

        assert!(ep.drain_channels(&mut Context::from_waker(Waker::noop())));
        assert!(matches!(
            ep.pending.pop_front(),
            Some(PendingRequest::Request(
                ConsommeRequest::CreateVirtualAddress(_)
            ))
        ));
    }

    #[test]
    fn drain_is_edge_triggered() {
        use std::task::Context;
        use std::task::Waker;

        let (send, recv) = mesh::channel::<ConsommeRequest>();
        let mut ep = ConsommeEndpoint::new_with_request_channel(
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
        assert_eq!(ep.pending.len(), 1);

        // Nothing new, even though `pending` is non-empty: no re-trigger (this
        // is what stops the frontend's restart-coalescing loop from spinning).
        assert!(!ep.drain_channels(&mut cx));
    }
}
