// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Async vhost-user transport.
//!
//! On Unix, messages are carried over a Unix domain socket with SCM_RIGHTS fd
//! passing. On Windows, messages are carried over an AF_UNIX socket and handles
//! are transferred with `DuplicateHandle`; see the `windows` module for details.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("i/o error")]
    Io(#[source] io::Error),
    #[error("connection closed")]
    Closed,
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(u32),
    #[error("invalid transport frame: {0}")]
    InvalidFrame(&'static str),
    #[error("handle transfer failed")]
    HandleTransfer(#[source] io::Error),
}

impl From<io::Error> for SocketError {
    fn from(e: io::Error) -> Self {
        SocketError::Io(e)
    }
}

/// Maximum payload size to accept (4 MB, generous upper bound).
const MAX_PAYLOAD_SIZE: u32 = 4 * 1024 * 1024;
