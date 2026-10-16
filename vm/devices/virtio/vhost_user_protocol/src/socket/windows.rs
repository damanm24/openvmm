// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows AF_UNIX transport for vhost-user.
//!
//! Windows AF_UNIX sockets do not support SCM_RIGHTS, so handles are
//! transferred out of band with `DuplicateHandle`. On connection, each endpoint
//! looks up the peer's process ID with `SIO_AF_UNIX_GETPEERPID` and tries to
//! open the peer with `PROCESS_DUP_HANDLE`. Every frame carries a flag that
//! says whether the sender was able to open the receiver. Handles sent from A
//! to B are transferred as follows:
//!
//! * If B can open A, B duplicates the handles out of A ("pull"). A must keep
//!   the handles open until B has processed the message, e.g. by waiting for
//!   a `REPLY_ACK`.
//! * Otherwise, if A can open B, A duplicates the handles into B ("push").
//! * Otherwise, the handles cannot be transferred and the send fails.
//!
//! An endpoint learns whether its peer can open it from the first frame it
//! receives, so it cannot send handles before then. vhost-user satisfies this:
//! the frontend receives replies to its feature negotiation before it sends
//! any handles, and the backend only sends handles in replies.
//!
//! Every frame also carries the sender's process ID. Handles are only
//! duplicated to or from the peer if that ID matches the process that
//! connected the socket. If the socket was handed off to another process after
//! connecting (for example, to a worker process over mesh), handle transfer
//! fails rather than duplicating handles in the wrong process.
//!
//! The OS access check ensures that the more privileged endpoint performs the
//! duplication. Neither endpoint gains access to a more privileged peer's
//! process. A receiver that can open its peer accepts only pulled handles. This
//! prevents a less privileged peer from claiming that arbitrary values in the
//! receiver's own handle table were pushed to it.
//!
//! Each frame is laid out as follows, with all fields in little-endian order:
//!
//! ```text
//! FrameHeader | VhostUserMsgHeader | payload | [u64; handle_count]
//! ```

// UNSAFETY: Win32 calls for peer lookup and handle duplication.
#![expect(unsafe_code)]

use super::MAX_PAYLOAD_SIZE;
use super::SocketError;
use crate::protocol::VHOST_USER_MAX_FDS;
use crate::protocol::VhostUserMsgHeader;
use futures::AsyncRead;
use futures::AsyncWrite;
use pal_async::socket::PolledSocket;
use std::future::poll_fn;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::AsRawSocket;
use std::os::windows::io::AsSocket;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::os::windows::io::RawHandle;
use std::pin::Pin;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::OnceLock;
use unix_socket::UnixStream;
use windows_sys::Win32::Foundation::DUPLICATE_CLOSE_SOURCE;
use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Networking::WinSock::SIO_AF_UNIX_GETPEERPID;
use windows_sys::Win32::Networking::WinSock::WSAGetLastError;
use windows_sys::Win32::Networking::WinSock::WSAIoctl;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::PROCESS_DUP_HANDLE;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// Trait for types that can be sent as an OS handle over the socket.
pub use std::os::windows::io::AsHandle as AsOsHandle;

/// An owned OS handle received from (or sent to) the peer.
pub type OwnedOsHandle = OwnedHandle;

/// Reusable receive state for [`VhostUserSocket::recv_message`].
///
/// Handles are carried in-band on Windows, so no per-connection receive state
/// is needed. This type exists for API parity with Unix.
pub struct MessageReceiver(());

impl MessageReceiver {
    /// Creates a new receiver. `_max_handles` is unused on Windows.
    pub fn new(_max_handles: usize) -> Self {
        Self(())
    }
}

const FRAME_MAGIC: u32 = u32::from_le_bytes(*b"vuWH");

/// The sender can open the receiver's process with `PROCESS_DUP_HANDLE`.
const FRAME_FLAG_CAN_OPEN_PEER: u8 = 1;

const TRANSFER_NONE: u8 = 0;
/// Handle values are valid in the receiver's process.
const TRANSFER_PUSHED: u8 = 1;
/// Handle values are valid in the sender's process.
const TRANSFER_PULL: u8 = 2;

#[repr(C)]
#[derive(Copy, Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
struct FrameHeader {
    magic: u32,
    flags: u8,
    transfer: u8,
    handle_count: u8,
    reserved: u8,
    /// The sender's process ID.
    pid: u32,
}

/// Peer properties learned from the first frame received.
#[derive(Copy, Clone, PartialEq, Eq)]
struct PeerInfo {
    can_open_us: bool,
    pid: u32,
}

/// Async vhost-user socket for sending and receiving protocol messages.
pub struct VhostUserSocket {
    socket: parking_lot::Mutex<PolledSocket<UnixStream>>,
    /// The process that connected the peer end of the socket and its handle,
    /// opened with `PROCESS_DUP_HANDLE`, if permitted.
    peer_process: Option<(u32, OwnedHandle)>,
    /// Learned from the first frame received.
    peer_info: OnceLock<PeerInfo>,
}

impl VhostUserSocket {
    /// Wrap a connected `UnixStream` in an async vhost-user socket.
    pub fn new(socket: PolledSocket<UnixStream>) -> Self {
        let peer_process = peer_process_id(socket.get()).and_then(|pid| {
            open_process_for_dup(pid)
                .map(|handle| (pid, handle))
                .inspect_err(|err| {
                    tracing::debug!(
                        pid,
                        error = err as &dyn std::error::Error,
                        "cannot open vhost-user peer for handle duplication"
                    );
                })
        });
        Self {
            socket: parking_lot::Mutex::new(socket),
            peer_process: peer_process.ok(),
            peer_info: OnceLock::new(),
        }
    }

    /// Receive a vhost-user message (header + payload + optional handles).
    pub async fn recv_message(
        &self,
        _receiver: &mut MessageReceiver,
    ) -> Result<(VhostUserMsgHeader, Vec<u8>, Vec<OwnedHandle>), SocketError> {
        let mut frame = FrameHeader::new_zeroed();
        if !self.read_exact(frame.as_mut_bytes()).await? {
            return Err(SocketError::Closed);
        }
        if frame.magic != FRAME_MAGIC {
            return Err(SocketError::InvalidFrame("bad frame magic"));
        }
        let info = PeerInfo {
            can_open_us: frame.flags & FRAME_FLAG_CAN_OPEN_PEER != 0,
            pid: frame.pid,
        };
        if *self.peer_info.get_or_init(|| info) != info {
            return Err(SocketError::InvalidFrame("peer identity changed"));
        }
        let handle_count = frame.handle_count as usize;
        if handle_count > VHOST_USER_MAX_FDS {
            return Err(SocketError::InvalidFrame("too many handles"));
        }

        let mut hdr = VhostUserMsgHeader::new_zeroed();
        if !self.read_exact(hdr.as_mut_bytes()).await? {
            return Err(SocketError::Closed);
        }
        if hdr.size > MAX_PAYLOAD_SIZE {
            return Err(SocketError::PayloadTooLarge(hdr.size));
        }
        let mut payload = vec![0u8; hdr.size as usize];
        if !payload.is_empty() && !self.read_exact(&mut payload).await? {
            return Err(SocketError::Closed);
        }

        let mut values = [0u64; VHOST_USER_MAX_FDS];
        let values = &mut values[..handle_count];
        if !values.is_empty() && !self.read_exact(values.as_mut_bytes()).await? {
            return Err(SocketError::Closed);
        }

        let handles = self.receive_handles(frame.transfer, values)?;
        Ok((hdr, payload, handles))
    }

    /// Send a vhost-user message (header + payload + optional handles).
    pub async fn send_message(
        &self,
        header: &VhostUserMsgHeader,
        payload: &[u8],
        handles: &[impl AsOsHandle],
    ) -> Result<(), SocketError> {
        assert!(
            handles.len() <= VHOST_USER_MAX_FDS,
            "too many handles: {} > {}",
            handles.len(),
            VHOST_USER_MAX_FDS
        );

        let (transfer, values) = self.prepare_handles(handles)?;

        let mut buf = Vec::with_capacity(
            size_of::<FrameHeader>()
                + size_of::<VhostUserMsgHeader>()
                + payload.len()
                + values.len() * size_of::<u64>(),
        );
        buf.extend_from_slice(
            FrameHeader {
                magic: FRAME_MAGIC,
                flags: if self.peer_process.is_some() {
                    FRAME_FLAG_CAN_OPEN_PEER
                } else {
                    0
                },
                transfer,
                handle_count: values.len() as u8,
                reserved: 0,
                // SAFETY: no safety requirements.
                pid: unsafe { GetCurrentProcessId() },
            }
            .as_bytes(),
        );
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(values.as_bytes());

        let result = self.write_all(&buf).await;
        if result.is_err() && transfer == TRANSFER_PUSHED {
            // The peer will never see these handles, so close them in the
            // peer process to avoid leaking them there.
            if let Ok(peer) = self.verified_peer_process() {
                for &value in &values {
                    close_remote_handle(peer, value as usize as HANDLE);
                }
            }
        }
        result
    }

    /// Chooses the transfer mode for outgoing handles and, for push mode,
    /// duplicates them into the peer. Returns the transfer mode and the handle
    /// values to send.
    fn prepare_handles(&self, handles: &[impl AsOsHandle]) -> Result<(u8, Vec<u64>), SocketError> {
        if handles.is_empty() {
            return Ok((TRANSFER_NONE, Vec::new()));
        }

        let peer_info = self.peer_info.get().ok_or_else(|| {
            SocketError::HandleTransfer(io::Error::other(
                "cannot send handles before receiving a message from the peer",
            ))
        })?;

        if peer_info.can_open_us {
            let values = handles
                .iter()
                .map(|h| h.as_handle().as_raw_handle() as usize as u64)
                .collect();
            return Ok((TRANSFER_PULL, values));
        }

        let peer = self.verified_peer_process()?;

        let mut values = Vec::with_capacity(handles.len());
        for handle in handles {
            // SAFETY: the source handle is valid for the duration of the call,
            // and both process handles are valid.
            match unsafe {
                duplicate_handle(
                    GetCurrentProcess(),
                    handle.as_handle().as_raw_handle(),
                    peer.as_raw_handle(),
                )
            } {
                Ok(remote) => values.push(remote as usize as u64),
                Err(err) => {
                    for &value in &values {
                        close_remote_handle(peer, value as usize as HANDLE);
                    }
                    return Err(SocketError::HandleTransfer(err));
                }
            }
        }
        Ok((TRANSFER_PUSHED, values))
    }

    /// Converts received handle values into owned handles in this process.
    fn receive_handles(
        &self,
        transfer: u8,
        values: &[u64],
    ) -> Result<Vec<OwnedHandle>, SocketError> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        let mut handles = Vec::with_capacity(values.len());
        match (transfer, &self.peer_process) {
            (TRANSFER_PULL, Some(_)) => {
                let peer = self.verified_peer_process()?;
                for &value in values {
                    let value = usize::try_from(value)
                        .map_err(|_| SocketError::InvalidFrame("invalid handle value"))?;
                    // SAFETY: duplicating from the peer process does not
                    // affect any handles in this process. The returned
                    // handle is newly created and owned by this process.
                    let handle = unsafe {
                        let raw = duplicate_handle(
                            peer.as_raw_handle(),
                            value as RawHandle,
                            GetCurrentProcess(),
                        )
                        .map_err(SocketError::HandleTransfer)?;
                        OwnedHandle::from_raw_handle(raw)
                    };
                    handles.push(handle);
                }
            }
            (TRANSFER_PUSHED, None) => {
                // The peer could open this process but this process cannot
                // open the peer, so the peer is at least as privileged as
                // this process. Trust it to have pushed valid, newly
                // duplicated handles.
                for &value in values {
                    let value = usize::try_from(value)
                        .map_err(|_| SocketError::InvalidFrame("invalid handle value"))?;
                    if value == 0 || value as RawHandle == INVALID_HANDLE_VALUE {
                        return Err(SocketError::InvalidFrame("invalid handle value"));
                    }
                    // SAFETY: the peer duplicated this handle into this
                    // process for this message, transferring ownership.
                    handles.push(unsafe { OwnedHandle::from_raw_handle(value as RawHandle) });
                }
            }
            // Do not take ownership of the values: if they were not really
            // pushed, they may alias unrelated handles in this process.
            (TRANSFER_PUSHED, Some(_)) => {
                return Err(SocketError::InvalidFrame(
                    "peer pushed handles but pull mode is required",
                ));
            }
            (TRANSFER_PULL, None) => {
                return Err(SocketError::HandleTransfer(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cannot open peer process to pull handles",
                )));
            }
            _ => return Err(SocketError::InvalidFrame("invalid handle transfer mode")),
        }
        Ok(handles)
    }

    /// Returns the peer process handle, if this process can open the peer and
    /// the peer is the process that connected the socket.
    fn verified_peer_process(&self) -> Result<&OwnedHandle, SocketError> {
        let Some((connected_pid, process)) = &self.peer_process else {
            return Err(SocketError::HandleTransfer(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "neither endpoint can duplicate handles into the other",
            )));
        };
        let Some(peer_pid) = self.peer_info.get().map(|info| info.pid) else {
            return Err(SocketError::HandleTransfer(io::Error::other(
                "cannot transfer handles before the peer has sent a message",
            )));
        };
        if peer_pid != *connected_pid {
            return Err(SocketError::HandleTransfer(io::Error::other(format!(
                "vhost-user peer process {peer_pid} is not the process that \
                 connected the socket ({connected_pid}); handles cannot be \
                 transferred over a socket handed off to another process"
            ))));
        }
        Ok(process)
    }

    /// Reads exactly `buf.len()` bytes. Returns `Ok(false)` if the socket was
    /// closed before any bytes were read.
    async fn read_exact(&self, buf: &mut [u8]) -> Result<bool, SocketError> {
        let mut read = 0;
        while read < buf.len() {
            let n =
                poll_fn(|cx| Pin::new(&mut *self.socket.lock()).poll_read(cx, &mut buf[read..]))
                    .await?;
            if n == 0 {
                if read == 0 {
                    return Ok(false);
                }
                return Err(SocketError::Closed);
            }
            read += n;
        }
        Ok(true)
    }

    async fn write_all(&self, mut buf: &[u8]) -> Result<(), SocketError> {
        while !buf.is_empty() {
            let n = poll_fn(|cx| Pin::new(&mut *self.socket.lock()).poll_write(cx, buf)).await?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            buf = &buf[n..];
        }
        Ok(())
    }
}

/// Duplicates `source` from `source_process` into `target_process` with the
/// same access.
///
/// # Safety
/// The process handles must be valid. If `source_process` is the current
/// process, `source` must be a valid handle.
unsafe fn duplicate_handle(
    source_process: RawHandle,
    source: RawHandle,
    target_process: RawHandle,
) -> io::Result<RawHandle> {
    let mut target: HANDLE = null_mut();
    // SAFETY: guaranteed by caller.
    let ok = unsafe {
        DuplicateHandle(
            source_process,
            source,
            target_process,
            &mut target,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(target)
}

/// Closes a handle in the peer process that was previously pushed to it.
fn close_remote_handle(peer: &OwnedHandle, handle: HANDLE) {
    // SAFETY: closing a handle in another process that this process created
    // there and that the peer has not been told about.
    unsafe {
        DuplicateHandle(
            peer.as_raw_handle(),
            handle,
            null_mut(),
            null_mut(),
            0,
            0,
            DUPLICATE_CLOSE_SOURCE,
        );
    }
}

fn open_process_for_dup(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: calling as documented; the returned handle is owned.
    unsafe {
        let handle = OpenProcess(PROCESS_DUP_HANDLE, 0, pid);
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedHandle::from_raw_handle(handle))
    }
}

/// Returns the process ID of the other end of a connected AF_UNIX socket.
fn peer_process_id(socket: &UnixStream) -> io::Result<u32> {
    let mut pid: u32 = 0;
    let mut returned = 0;
    // SAFETY: the socket is valid and the output buffer is valid for writes
    // of its stated size.
    let r = unsafe {
        WSAIoctl(
            socket.as_socket().as_raw_socket() as usize,
            SIO_AF_UNIX_GETPEERPID,
            null(),
            0,
            (&raw mut pid).cast(),
            size_of::<u32>() as u32,
            &mut returned,
            null_mut(),
            None,
        )
    };
    if r != 0 {
        // SAFETY: no safety requirements.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_event::Event;

    fn socket_pair(driver: &DefaultDriver) -> (VhostUserSocket, VhostUserSocket) {
        let (a, b) = UnixStream::pair().unwrap();
        (
            VhostUserSocket::new(PolledSocket::new(driver, a).unwrap()),
            VhostUserSocket::new(PolledSocket::new(driver, b).unwrap()),
        )
    }

    fn header(size: usize) -> VhostUserMsgHeader {
        VhostUserMsgHeader {
            request: 1,
            flags: 1,
            size: size as u32,
        }
    }

    async fn send(socket: &VhostUserSocket, payload: &[u8], handles: &[impl AsOsHandle]) {
        socket
            .send_message(&header(payload.len()), payload, handles)
            .await
            .unwrap();
    }

    async fn recv(socket: &VhostUserSocket) -> Result<(Vec<u8>, Vec<OwnedHandle>), SocketError> {
        let (_, payload, handles) = socket
            .recv_message(&mut MessageReceiver::new(VHOST_USER_MAX_FDS))
            .await?;
        Ok((payload, handles))
    }

    #[async_test]
    async fn round_trip_without_handles(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver);
        send(&a, b"abc", &[] as &[OwnedHandle]).await;
        let (payload, handles) = recv(&b).await.unwrap();
        assert_eq!(payload, b"abc");
        assert!(handles.is_empty());
    }

    /// Within one process both endpoints can open each other, so handles are
    /// pulled.
    #[async_test]
    async fn round_trip_with_handles(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver);
        assert!(a.peer_process.is_some() && b.peer_process.is_some());
        send(&b, &[], &[] as &[OwnedHandle]).await;
        recv(&a).await.unwrap();
        assert!(a.peer_info.get().unwrap().can_open_us);

        let event = Event::new();
        send(&a, &[], &[&event]).await;
        let (_, mut handles) = recv(&b).await.unwrap();
        assert_eq!(handles.len(), 1);
        let received = Event::from(handles.pop().unwrap());
        event.signal();
        assert!(received.try_wait());
    }

    #[async_test]
    async fn handles_require_received_frame(driver: DefaultDriver) {
        let (a, _b) = socket_pair(&driver);
        let event = Event::new();
        let err = a
            .send_message(&header(0), &[], &[&event])
            .await
            .unwrap_err();
        assert!(matches!(err, SocketError::HandleTransfer(_)));
    }

    #[async_test]
    async fn rejects_spoofed_push(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver);
        let event = Event::new();
        // Forge a frame that claims the handle was pushed into `b`.
        let value = event.as_handle().as_raw_handle() as usize as u64;
        let mut buf = Vec::new();
        buf.extend_from_slice(
            FrameHeader {
                magic: FRAME_MAGIC,
                flags: FRAME_FLAG_CAN_OPEN_PEER,
                transfer: TRANSFER_PUSHED,
                handle_count: 1,
                reserved: 0,
                pid: std::process::id(),
            }
            .as_bytes(),
        );
        buf.extend_from_slice(header(0).as_bytes());
        buf.extend_from_slice(value.as_bytes());
        a.write_all(&buf).await.unwrap();
        let err = recv(&b).await.unwrap_err();
        assert!(matches!(err, SocketError::InvalidFrame(_)));
        // The event handle must not have been taken over and closed.
        event.signal();
        assert!(event.try_wait());
    }

    /// Handles must not be pulled from the connecting process when a different
    /// process is using the socket.
    #[async_test]
    async fn rejects_pull_after_handoff(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver);
        let event = Event::new();
        let value = event.as_handle().as_raw_handle() as usize as u64;
        let mut buf = Vec::new();
        buf.extend_from_slice(
            FrameHeader {
                magic: FRAME_MAGIC,
                flags: 0,
                transfer: TRANSFER_PULL,
                handle_count: 1,
                reserved: 0,
                pid: std::process::id() + 4,
            }
            .as_bytes(),
        );
        buf.extend_from_slice(header(0).as_bytes());
        buf.extend_from_slice(value.as_bytes());
        a.write_all(&buf).await.unwrap();
        let err = recv(&b).await.unwrap_err();
        assert!(matches!(err, SocketError::HandleTransfer(_)));
        // `b` must not push handles into the mismatched peer either.
        let err = b
            .send_message(&header(0), &[], &[&event])
            .await
            .unwrap_err();
        assert!(matches!(err, SocketError::HandleTransfer(_)));
    }

    #[async_test]
    async fn connect_by_path(driver: DefaultDriver) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vhost.sock");
        let mut listener =
            PolledSocket::new(&driver, unix_socket::UnixListener::bind(&path).unwrap()).unwrap();
        let client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let client = VhostUserSocket::new(PolledSocket::new(&driver, client).unwrap());
        let server = VhostUserSocket::new(PolledSocket::new(&driver, server).unwrap());
        assert!(client.peer_process.is_some() && server.peer_process.is_some());
        send(&client, b"hello", &[] as &[OwnedHandle]).await;
        let (payload, _) = recv(&server).await.unwrap();
        assert_eq!(payload, b"hello");
    }
}
