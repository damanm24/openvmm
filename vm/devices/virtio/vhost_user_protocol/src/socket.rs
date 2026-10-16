// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Async vhost-user transport.
//!
//! On Unix, messages are carried over a Unix domain socket with SCM_RIGHTS fd
//! passing. On Windows, an AF_UNIX socket bootstraps a mesh connection, which
//! carries messages and handles over ALPC.

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
    #[cfg(windows)]
    #[error("mesh transport failed")]
    Mesh(#[source] mesh::RecvError),
}

impl From<io::Error> for SocketError {
    fn from(e: io::Error) -> Self {
        SocketError::Io(e)
    }
}

/// Maximum payload size to accept (4 MB, generous upper bound).
const MAX_PAYLOAD_SIZE: u32 = 4 * 1024 * 1024;
