// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! libc resolver backend implementation.
//!
//! This module provides FFI bindings to the libc resolver functions
//! (`res_init`, `res_send`) and a thread-based backend for executing
//! DNS queries asynchronously.

// UNSAFETY: FFI calls to libc resolver functions.
#![expect(unsafe_code)]

use super::SharedState;
use crate::DnsResponse;
use pal_async::driver::Driver;
use pal_async::task::Spawn;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use std::sync::Arc;

/// Maximum size for a DNS response buffer.
/// This is the maximum size for a DNS message over UDP (65535 bytes).
const MAX_DNS_RESPONSE_SIZE: usize = 65535;

/// Context for a DNS query, containing routing information.
#[derive(Clone, Debug)]
pub(super) struct QueryContext {
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
    fn to_response(&self, response_data: Vec<u8>) -> DnsResponse {
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

// FFI declarations for libc resolver functions.
//
// On Linux, these are in libresolv (linked via -lresolv).
// On macOS, these are in libSystem (no extra linking needed).
//
// Note: We use the thread-safe versions where available. The resolver
// state `_res` is thread-local on modern systems, so concurrent calls
// from different threads are safe.

#[cfg(target_os = "linux")]
mod ffi {
    use libc::c_int;

    // On Linux, res_init and res_send are in libresolv.
    // The resolver state (_res) is thread-local.
    unsafe extern "C" {
        /// Initialize the resolver state.
        /// Reads /etc/resolv.conf and populates the thread-local _res structure.
        /// Returns 0 on success, -1 on error.
        pub safe fn res_init() -> c_int;

        /// Send a pre-formatted DNS query and receive the response.
        ///
        /// # Arguments
        /// * `msg` - Pointer to the DNS query message in wire format
        /// * `msglen` - Length of the query message
        /// * `answer` - Buffer to receive the DNS response
        /// * `anslen` - Size of the answer buffer
        ///
        /// # Returns
        /// The length of the response on success, or -1 on error.
        pub fn res_send(msg: *const u8, msglen: c_int, answer: *mut u8, anslen: c_int) -> c_int;
    }
}

#[cfg(target_os = "macos")]
mod ffi {
    use libc::c_int;

    // On macOS, resolver functions are in libSystem.
    // We use res_9_init and res_9_send which are the modern variants.
    // The older res_init/res_send are deprecated.
    unsafe extern "C" {
        /// Initialize the resolver state (macOS variant).
        #[link_name = "res_9_init"]
        pub safe fn res_init() -> c_int;

        /// Send a pre-formatted DNS query and receive the response (macOS variant).
        #[link_name = "res_9_send"]
        pub fn res_send(msg: *const u8, msglen: c_int, answer: *mut u8, anslen: c_int) -> c_int;
    }
}

// For other Unix-like systems (FreeBSD, etc.), use standard names
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod ffi {
    use libc::c_int;

    unsafe extern "C" {
        pub safe fn res_init() -> c_int;
        pub fn res_send(msg: *const u8, msglen: c_int, answer: *mut u8, anslen: c_int) -> c_int;
    }
}

/// Initialize the libc resolver.
///
/// This must be called once before using `res_send()`.
/// Reads configuration from /etc/resolv.conf.
pub fn init_resolver() -> Result<(), std::io::Error> {
    // res_init() is declared as safe and initializes thread-local state.
    let result = ffi::res_init();

    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Execute a DNS query using res_send.
///
/// This is a blocking call that sends the query to the system resolver
/// and waits for a response.
///
/// # Arguments
/// * `query` - The DNS query in wire format
///
/// # Returns
/// The DNS response in wire format, or an error.
fn execute_query(query: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut response_buffer = vec![0u8; MAX_DNS_RESPONSE_SIZE];

    // SAFETY: We're passing valid pointers and lengths to res_send.
    // The function reads from query and writes to response_buffer.
    let response_len = unsafe {
        ffi::res_send(
            query.as_ptr(),
            query.len() as libc::c_int,
            response_buffer.as_mut_ptr(),
            response_buffer.len() as libc::c_int,
        )
    };

    if response_len < 0 {
        return Err(std::io::Error::last_os_error());
    }

    response_buffer.truncate(response_len as usize);
    Ok(response_buffer)
}

/// Build a SERVFAIL error response for a failed query.
///
/// This creates a minimal DNS response with RCODE=SERVFAIL (2).
fn build_error_response(query: &[u8]) -> Vec<u8> {
    // We need at least the DNS header (12 bytes) to build a response
    if query.len() < 12 {
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
    if query.len() > 12 {
        response.extend_from_slice(&query[12..]);
    }

    response
}

/// Backend for executing DNS queries using the VmTaskDriver.
pub(super) struct ResolverBackend<'a> {
    /// The driver used for spawning async tasks.
    driver: &'a dyn Driver,
}

impl<'a> ResolverBackend<'a> {
    /// Create a new resolver backend with the given driver.
    pub fn new(driver: &'a dyn Driver) -> Self {
        Self { driver }
    }

    /// Execute a DNS query asynchronously.
    ///
    /// Uses the VmTaskDriver to spawn an async task to execute the query using `res_send()`.
    /// The result is queued to the shared state's response queue.
    pub fn query(&self, dns_query: &[u8], context: QueryContext, shared_state: Arc<SharedState>) {
        // Clone the query data for the async task
        let query_data = dns_query.to_vec();
        let request_id = context.id;

        // Use the driver's spawner to create an async task
        let spawner = self.driver as &dyn Spawn;
        spawner
            .spawn(format!("dns-query-{}", request_id), async move {
                // Initialize resolver for this task (thread-local state)
                // This is safe to call multiple times.
                if ffi::res_init() == -1 {
                    tracing::warn!(request_id, "Failed to initialize resolver for task");
                }

                // Execute the query
                let response_data = match execute_query(&query_data) {
                    Ok(data) => {
                        tracing::debug!(
                            request_id,
                            response_len = data.len(),
                            "DNS query completed successfully"
                        );
                        data
                    }
                    Err(e) => {
                        tracing::warn!(
                            request_id,
                            error = %e,
                            "DNS query failed, returning SERVFAIL"
                        );
                        build_error_response(&query_data)
                    }
                };

                // Check if this request is still pending (not cancelled)
                let is_pending = shared_state
                    .pending_requests
                    .lock()
                    .expect("pending_requests mutex poisoned")
                    .remove(&request_id);

                if is_pending && !response_data.is_empty() {
                    // Queue the response
                    let response = context.to_response(response_data);
                    shared_state
                        .response_queue
                        .lock()
                        .expect("response_queue mutex poisoned")
                        .push_back(response);
                } else if !is_pending {
                    tracing::debug!(request_id, "DNS query completed but request was cancelled");
                }
            })
            .detach();
    }
}
