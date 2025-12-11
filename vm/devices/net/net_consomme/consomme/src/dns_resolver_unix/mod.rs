// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DNS resolver using Unix libc resolver APIs.
//!
//! This module provides a DNS resolver for Unix systems (Linux, macOS)
//! using the libc `res_send()` function which handles raw DNS wire format.
//!
//! ## API Selection
//!
//! We use `res_send()` rather than `res_query()` because:
//! - `res_send()` accepts pre-formatted DNS queries in wire format
//! - `res_send()` returns raw DNS responses in wire format
//! - This avoids the need to parse and rebuild DNS messages
//!
//! ## Threading Model
//!
//! Since `res_send()` is a blocking call, queries are executed on
//! background threads using `std::thread::spawn()`. Results are
//! queued for polling by the main thread.

mod resolver;

use crate::DnsResponse;
use crate::DropReason;
use parking_lot::Mutex;
use resolver::QueryContext;
use resolver::ResolverBackend;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Shared state between the DnsResolver and background threads.
struct SharedState {
    /// Queue of completed DNS responses ready to be sent.
    response_queue: Mutex<VecDeque<DnsResponse>>,
    /// Set of pending request IDs (for cancellation tracking).
    pending_requests: Mutex<HashSet<u64>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            response_queue: Mutex::new(VecDeque::new()),
            pending_requests: Mutex::new(HashSet::new()),
        }
    }
}

/// DNS resolver that manages active DNS queries using Unix libc resolver APIs.
///
/// This resolver uses `res_send()` to forward raw DNS queries to the system
/// resolver and receive raw DNS responses back.
///
/// # Example
///
/// ```ignore
/// let resolver = DnsResolver::new()?;
///
/// // Submit a DNS query
/// resolver.handle_dns(
///     dns_query_bytes,
///     IpProtocol::Udp,
///     src_addr, dst_addr,
///     src_port, dst_port,
///     gateway_mac, client_mac,
/// )?;
///
/// // Poll for responses
/// while let Some(response) = resolver.poll_responses(IpProtocol::Udp) {
///     // Send response back to client
/// }
/// ```
pub struct DnsResolver {
    /// Shared state for responses and pending request tracking.
    shared_state: Arc<SharedState>,
    /// Next request ID to assign.
    next_id: AtomicU64,
}

impl DnsResolver {
    /// Creates a new DNS resolver instance.
    ///
    /// Initializes the libc resolver by calling `res_init()`.
    pub fn new() -> Result<Self, std::io::Error> {
        // Initialize the resolver (reads /etc/resolv.conf)
        resolver::init_resolver()?;

        Ok(Self {
            shared_state: Arc::new(SharedState::new()),
            next_id: AtomicU64::new(0),
        })
    }

    /// Submits a DNS query for resolution.
    ///
    /// The query is executed asynchronously on a background thread.
    /// Results can be retrieved via `poll_responses()`.
    pub fn handle_dns(
        &mut self,
        dns_query: &[u8],
        protocol: IpProtocol,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        gateway_mac: EthernetAddress,
        client_mac: EthernetAddress,
    ) -> Result<(), DropReason> {
        // Validate DNS header (minimum 12 bytes)
        if dns_query.len() < 12 {
            tracing::error!(len = dns_query.len(), "DNS query too short");
            return Err(DropReason::DnsError);
        }

        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // Track this request as pending
        self.shared_state.pending_requests.lock().insert(request_id);

        let context = QueryContext {
            id: request_id,
            protocol,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            gateway_mac,
            client_mac,
        };

        // Create a backend and execute the query
        let backend = ResolverBackend::new();
        backend.query(dns_query, context, self.shared_state.clone());

        Ok(())
    }

    /// Polls for completed DNS responses matching the given protocol.
    ///
    /// Returns `None` if the protocol is not UDP or TCP, or if no responses
    /// are available for the specified protocol.
    pub fn poll_responses(&mut self, protocol: IpProtocol) -> Option<DnsResponse> {
        if protocol != IpProtocol::Udp && protocol != IpProtocol::Tcp {
            return None;
        }

        let mut queue = self.shared_state.response_queue.lock();
        match queue.front() {
            Some(resp) if resp.protocol == protocol => queue.pop_front(),
            _ => None,
        }
    }

    /// Cancels all pending DNS queries.
    ///
    /// Note: Since `res_send()` is blocking and cannot be interrupted,
    /// this only prevents completed queries from being returned.
    /// In-flight queries will complete but their results will be discarded.
    pub fn cancel_all(&mut self) {
        // Clear pending requests - background threads will check this
        // before queuing their results
        self.shared_state.pending_requests.lock().clear();

        // Clear any already-queued responses
        self.shared_state.response_queue.lock().clear();
    }
}

impl Drop for DnsResolver {
    fn drop(&mut self) {
        self.cancel_all();
    }
}
