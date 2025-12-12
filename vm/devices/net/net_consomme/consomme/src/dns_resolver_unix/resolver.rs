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
use crate::dns_resolver_common::build_servfail_response;
use crate::dns_resolver_common::MAX_DNS_RESPONSE_SIZE;
use crate::dns_resolver_common::QueryContext;
use std::sync::Arc;

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



/// Backend for executing DNS queries using threads.
pub(super) struct ResolverBackend;

impl ResolverBackend {
    /// Create a new resolver backend.
    pub fn new() -> Self {
        Self
    }

    /// Execute a DNS query asynchronously using a background thread.
    ///
    /// Spawns a thread to execute the blocking query using `res_send()`.
    /// The result is queued to the shared state's response queue.
    pub fn query(&self, dns_query: &[u8], context: QueryContext, shared_state: Arc<SharedState>) {
        // Clone the query data for the thread
        let query_data = dns_query.to_vec();
        let request_id = context.id;

        // Spawn a thread to execute the blocking DNS query
        std::thread::spawn(move || {
            // Initialize resolver for this thread (thread-local state)
            // This is safe to call multiple times.
            if ffi::res_init() == -1 {
                tracing::warn!(request_id, "Failed to initialize resolver for thread");
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
                    build_servfail_response(&query_data)
                }
            };

            // Check if this request is still pending (not cancelled)
            let mut pending = shared_state.pending_requests.lock();
            let is_pending = pending.remove(&request_id);
            drop(pending);

            if is_pending && !response_data.is_empty() {
                // Queue the response
                let response = context.to_response(response_data);
                let mut queue = shared_state.response_queue.lock();
                queue.push_back(response);
            } else if !is_pending {
                tracing::debug!(request_id, "DNS query completed but request was cancelled");
            }
        });
    }
}
