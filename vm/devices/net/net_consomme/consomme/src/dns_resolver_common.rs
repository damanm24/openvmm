// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common types and utilities shared between Unix and Windows DNS resolvers.
//!
//! This module provides platform-independent code used by both the Unix
//! (`dns_resolver_unix`) and Windows (`dns_resolver_windows`) DNS resolver
//! implementations.

pub use crate::DnsResponse;
pub use crate::DropReason;

pub use smoltcp::wire::EthernetAddress;
pub use smoltcp::wire::IpProtocol;
pub use smoltcp::wire::Ipv4Address;
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Minimum size for a valid DNS header (RFC 1035).
pub const DNS_HEADER_SIZE: usize = 12;

/// Maximum size for a DNS response buffer.
/// This is the maximum size for a DNS message over UDP (65535 bytes).
pub const MAX_DNS_RESPONSE_SIZE: usize = 65535;

/// Context for a DNS query, containing routing information.
///
/// This struct contains all the information needed to route a DNS response
/// back to the client after the query completes.
#[derive(Clone, Debug)]
pub struct QueryContext {
    /// Unique request ID for tracking.
    pub id: u64,
    /// Transport protocol (UDP or TCP).
    pub protocol: IpProtocol,
    /// Source IP address (the client).
    pub src_addr: Ipv4Address,
    /// Destination IP address (the gateway/DNS server).
    pub dst_addr: Ipv4Address,
    /// Source port (the client's port).
    pub src_port: u16,
    /// Destination port (DNS port, usually 53).
    pub dst_port: u16,
    /// Gateway MAC address.
    pub gateway_mac: EthernetAddress,
    /// Client MAC address.
    pub client_mac: EthernetAddress,
}

impl QueryContext {
    /// Create a DnsResponse from this context and response data.
    pub fn to_response(&self, response_data: Vec<u8>) -> DnsResponse {
        DnsResponse {
            src_addr: self.src_addr,
            dst_addr: self.dst_addr,
            src_port: self.src_port,
            dst_port: self.dst_port,
            gateway_mac: self.gateway_mac,
            client_mac: self.client_mac,
            response_data,
            protocol: self.protocol,
        }
    }
}

/// Thread-safe request ID generator.
///
/// Generates unique, monotonically increasing request IDs for tracking
/// DNS queries.
pub struct RequestIdGenerator {
    next_id: AtomicU64,
}

impl RequestIdGenerator {
    /// Create a new ID generator starting from 0.
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
        }
    }

    /// Generate the next unique request ID.
    pub fn next(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for RequestIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Poll for a DNS response matching the given protocol from a queue.
///
/// Returns `Some(response)` if a response matching the protocol is at the
/// front of the queue, removing it from the queue. Returns `None` if the
/// queue is empty, the front response doesn't match the protocol, or the
/// protocol is not UDP or TCP.
pub fn poll_response_queue(
    queue: &mut VecDeque<DnsResponse>,
    protocol: IpProtocol,
) -> Option<DnsResponse> {
    if protocol != IpProtocol::Udp && protocol != IpProtocol::Tcp {
        return None;
    }

    match queue.front() {
        Some(resp) if resp.protocol == protocol => queue.pop_front(),
        _ => None,
    }
}

/// Validate that a DNS query has the minimum required header size.
///
/// Returns `true` if the query is at least [`DNS_HEADER_SIZE`] bytes.
pub fn validate_dns_header(dns_query: &[u8]) -> bool {
    dns_query.len() >= DNS_HEADER_SIZE
}

/// Build a SERVFAIL error response for a failed query.
///
/// This creates a minimal DNS response with RCODE=SERVFAIL (2).
/// Used when the underlying DNS resolution fails.
///
/// # Arguments
///
/// * `query` - The original DNS query bytes (must be at least 12 bytes)
///
/// # Returns
///
/// A DNS response with SERVFAIL RCODE, or an empty Vec if the query is malformed.
pub fn build_servfail_response(query: &[u8]) -> Vec<u8> {
    // We need at least the DNS header (12 bytes) to build a response
    if query.len() < DNS_HEADER_SIZE {
        // Return an empty response if the query is malformed
        return Vec::new();
    }

    let mut response = Vec::with_capacity(query.len());

    // Copy transaction ID from query (bytes 0-1)
    response.extend_from_slice(&query[0..2]);

    // Build flags: QR=1 (response), OPCODE=0, AA=0, TC=0, RD=query.RD, RA=1, RCODE=2 (SERVFAIL)
    let rd = query[2] & 0x01; // Preserve RD bit from query
    let flags_byte1 = 0x80 | rd; // QR=1, RD preserved
    let flags_byte2 = 0x82; // RA=1, RCODE=2 (SERVFAIL)
    response.push(flags_byte1);
    response.push(flags_byte2);

    // Copy QDCOUNT from query (bytes 4-5)
    response.extend_from_slice(&query[4..6]);

    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    // Copy the question section if present
    if query.len() > DNS_HEADER_SIZE {
        response.extend_from_slice(&query[DNS_HEADER_SIZE..]);
    }

    response
}
