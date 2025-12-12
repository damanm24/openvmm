// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DNS backend trait and shared types.
//!
//! This module defines the common interface for DNS backend implementations
//! and shared data structures used across backends.

use crate::dns_resolver_common::DnsResponse;
use crate::dns_resolver_common::DropReason;
use crate::dns_resolver_common::EthernetAddress;
use crate::dns_resolver_common::IpProtocol;
use crate::dns_resolver_common::Ipv4Address;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::collections::VecDeque;
use windows_sys::Win32::NetworkManagement::Dns::DNS_QUERY_CANCEL;
use windows_sys::Win32::NetworkManagement::Dns::DNS_QUERY_RAW_CANCEL;

/// Unified cancel handle that supports both Raw and Ex APIs.
pub(super) struct CancelHandle {
    /// The actual cancel handle.
    pub handle: CancelHandleInner,
}

/// The inner cancel handle type.
pub(super) enum CancelHandleInner {
    /// Cancel handle for DnsQueryRaw API.
    Raw(DNS_QUERY_RAW_CANCEL),
    /// Cancel handle for DnsQueryEx API.
    Ex(DNS_QUERY_CANCEL),
}

/// Shared state between the DnsResolver and backend callbacks.
///
/// This is wrapped in Arc for thread-safe sharing with async callbacks.
pub(super) struct SharedState {
    /// Queue of completed DNS responses ready to be sent.
    pub response_queue: Mutex<VecDeque<DnsResponse>>,
    /// Active cancel handles for pending queries.
    pub active_cancel_handles: Mutex<HashMap<u64, CancelHandle>>,
}

impl SharedState {
    /// Create a new shared state instance with the specified configuration.
    pub fn new() -> Self {
        Self {
            response_queue: Mutex::new(VecDeque::new()),
            active_cancel_handles: Mutex::new(HashMap::new()),
        }
    }
}

/// Common context for all DNS queries.
///
/// Contains the information needed to route a DNS response back to the client.
pub(super) use crate::dns_resolver_common::QueryContext;

/// Trait for DNS backend implementations.
///
/// Each backend handles DNS queries using a specific Windows API
/// (DnsQueryRaw or DnsQueryEx).
pub(super) trait DnsBackend: Send {
    /// Submit a DNS query for async resolution.
    ///
    /// The response will be queued to the shared state's response_queue
    /// when the query completes.
    fn query(
        &mut self,
        dns_query: &[u8],
        protocol: IpProtocol,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        gateway_mac: EthernetAddress,
        client_mac: EthernetAddress,
    ) -> Result<(), DropReason>;

    /// Cancel all pending DNS queries.
    fn cancel_all(&mut self);
}

/// Thread-safe request ID generator.
pub(super) use crate::dns_resolver_common::RequestIdGenerator;
