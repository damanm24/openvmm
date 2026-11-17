// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host TCP socket operations that `socket2` does not expose.
//!
//! On Linux, unacknowledged host-to-guest data stays in the kernel socket and
//! is read with `MSG_PEEK` at the socket's peek offset (`SO_PEEK_OFF`, TCP
//! support since Linux 6.9). Acknowledged data is discarded with `MSG_TRUNC`,
//! which also moves the peek offset back. Elsewhere these return
//! [`std::io::ErrorKind::Unsupported`] and the translator keeps unacknowledged
//! data in a ring instead.

// UNSAFETY: setsockopt, ioctl, and recv calls on a borrowed socket descriptor.
#![cfg_attr(target_os = "linux", expect(unsafe_code))]

use socket2::Socket;
use std::io;

/// Sets the socket's peek offset. Subsequent `MSG_PEEK` reads start at this
/// offset and advance it.
pub(crate) fn set_peek_offset(socket: &Socket, offset: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let offset = libc::c_int::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: the descriptor is valid for the borrow of `socket`, and the
        // option value points to a live c_int of the given size.
        let r = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEEK_OFF,
                std::ptr::from_ref(&offset).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, offset);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Discards up to `len` bytes from the front of the socket's receive queue
/// without copying them. Returns the number discarded.
pub(crate) fn discard(socket: &Socket, len: usize) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: with MSG_TRUNC on a TCP socket the kernel does not access
        // the buffer, so a null pointer is permitted.
        let r = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                std::ptr::null_mut(),
                len,
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(r as usize)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, len);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Returns the free space in the socket's send buffer: how much more data
/// the guest may send before a write would block.
pub(crate) fn send_space(socket: &Socket) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let sndbuf = socket.send_buffer_size()?;
        let mut queued: libc::c_int = 0;
        // SAFETY: SIOCOUTQ writes one c_int to the provided pointer.
        let r = unsafe { libc::ioctl(socket.as_raw_fd(), libc::TIOCOUTQ, &mut queued) };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sndbuf.saturating_sub(queued.max(0) as usize))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        Err(io::ErrorKind::Unsupported.into())
    }
}
