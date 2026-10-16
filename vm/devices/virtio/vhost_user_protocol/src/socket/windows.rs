// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows vhost-user transport over mesh.
//!
//! The frontend invites the backend into a dedicated mesh over the connected
//! AF_UNIX socket. Messages and OS handles then travel over mesh's ALPC
//! transport. No vhost-specific handle duplication or push/pull protocol is
//! needed.
//!
//! The frontend creates the mesh directory so that a user-owned VMM can invite
//! either a user-owned or elevated backend. The bootstrap socket must be
//! restricted to intended participants.
//!
//! TODO: Support an elevated frontend with a non-elevated backend if required;
//! the mesh directory currently uses the frontend's default security.

use super::MAX_PAYLOAD_SIZE;
use super::SocketError;
use crate::protocol::VHOST_USER_MAX_FDS;
use crate::protocol::VhostUserMsgHeader;
use mesh::BidirChannel;
use mesh::MeshPayload;
use mesh_remote::windows::AlpcNode;
use pal_async::driver::SpawnDriver;
use pal_async::socket::PolledSocket;
use std::future::poll_fn;
use std::io;
use std::os::windows::io::OwnedHandle;
use unix_socket::UnixStream;

/// Trait for types that can be sent as an OS handle over the connection.
pub use std::os::windows::io::AsHandle as AsOsHandle;

/// An owned OS handle received from (or sent to) the peer.
pub type OwnedOsHandle = OwnedHandle;

/// Receive state placeholder for API parity with Unix.
pub struct MessageReceiver(());

impl MessageReceiver {
    /// Creates a new receiver.
    pub fn new(_max_handles: usize) -> Self {
        Self(())
    }
}

#[derive(MeshPayload)]
struct TransportMessage {
    request: u32,
    flags: u32,
    payload: Vec<u8>,
    handles: Vec<OwnedHandle>,
}

/// A vhost-user connection using mesh for messages and handle transfer.
pub struct VhostUserSocket {
    channel: parking_lot::Mutex<BidirChannel<TransportMessage, TransportMessage>>,
    _close: mesh::OneshotSender<()>,
}

impl VhostUserSocket {
    /// Establish the frontend side of a connected bootstrap socket.
    pub async fn connect(
        driver: impl SpawnDriver + Clone,
        socket: PolledSocket<UnixStream>,
    ) -> Result<Self, SocketError> {
        let node = AlpcNode::new_named(driver.clone()).map_err(io::Error::other)?;
        let (channel, remote) = BidirChannel::<TransportMessage, TransportMessage>::new_pair();
        node.invite_over_socket(socket, remote.into())
            .await
            .map_err(io::Error::other)?;
        Ok(Self::from_channel(driver, node, channel))
    }

    /// Establish the backend side of a connected bootstrap socket.
    pub async fn accept(
        driver: impl SpawnDriver + Clone,
        socket: PolledSocket<UnixStream>,
    ) -> Result<Self, SocketError> {
        let (channel, remote) = BidirChannel::<TransportMessage, TransportMessage>::new_pair();
        let node = AlpcNode::join_by_stream(driver.clone(), socket, remote.into())
            .await
            .map_err(io::Error::other)?;
        Ok(Self::from_channel(driver, node, channel))
    }

    fn from_channel(
        driver: impl SpawnDriver,
        node: AlpcNode,
        channel: BidirChannel<TransportMessage, TransportMessage>,
    ) -> Self {
        let (close, closed) = mesh::oneshot();
        driver
            .spawn("vhost-user mesh", async move {
                // Dropping the socket closes its channel before releasing
                // this signal. Drain the mesh before dropping its ALPC node.
                let _ = closed.await;
                node.shutdown().await;
            })
            .detach();
        Self {
            channel: parking_lot::Mutex::new(channel),
            _close: close,
        }
    }

    /// Receive a vhost-user message and any attached OS handles.
    pub async fn recv_message(
        &self,
        _receiver: &mut MessageReceiver,
    ) -> Result<(VhostUserMsgHeader, Vec<u8>, Vec<OwnedHandle>), SocketError> {
        let message = poll_fn(|cx| self.channel.lock().poll_recv(cx))
            .await
            .map_err(|err| match err {
                mesh::RecvError::Closed => SocketError::Closed,
                err => SocketError::Mesh(err),
            })?;
        if message.payload.len() > MAX_PAYLOAD_SIZE as usize {
            return Err(SocketError::InvalidFrame("payload too large"));
        }
        if message.handles.len() > VHOST_USER_MAX_FDS {
            return Err(SocketError::InvalidFrame("too many handles"));
        }
        let header = VhostUserMsgHeader {
            request: message.request,
            flags: message.flags,
            size: message.payload.len() as u32,
        };
        Ok((header, message.payload, message.handles))
    }

    /// Send a vhost-user message and any attached OS handles.
    pub async fn send_message(
        &self,
        header: &VhostUserMsgHeader,
        payload: &[u8],
        handles: &[impl AsOsHandle],
    ) -> Result<(), SocketError> {
        if payload.len() > MAX_PAYLOAD_SIZE as usize || payload.len() != header.size as usize {
            return Err(SocketError::InvalidFrame("invalid payload size"));
        }
        if handles.len() > VHOST_USER_MAX_FDS {
            return Err(SocketError::InvalidFrame("too many handles"));
        }
        let handles = handles
            .iter()
            .map(|handle| handle.as_handle().try_clone_to_owned())
            .collect::<io::Result<Vec<_>>>()?;
        let channel = self.channel.lock();
        if channel.is_peer_closed() {
            return Err(SocketError::Closed);
        }
        channel.send(TransportMessage {
            request: header.request,
            flags: header.flags,
            payload: payload.to_vec(),
            handles,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_event::Event;
    use test_with_tracing::test;

    async fn socket_pair(driver: &DefaultDriver) -> (VhostUserSocket, VhostUserSocket) {
        let (a, b) = UnixStream::pair().unwrap();
        let (a, b) = futures::join!(
            VhostUserSocket::connect(driver.clone(), PolledSocket::new(driver, a).unwrap()),
            VhostUserSocket::accept(driver.clone(), PolledSocket::new(driver, b).unwrap()),
        );
        (a.unwrap(), b.unwrap())
    }

    fn header(size: usize) -> VhostUserMsgHeader {
        VhostUserMsgHeader {
            request: 1,
            flags: 1,
            size: size as u32,
        }
    }

    #[async_test]
    async fn round_trip_without_handles(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver).await;
        a.send_message(&header(3), b"abc", &[] as &[OwnedHandle])
            .await
            .unwrap();
        let (hdr, payload, handles) = b.recv_message(&mut MessageReceiver::new(0)).await.unwrap();
        assert_eq!(hdr.size, 3);
        assert_eq!(payload, b"abc");
        assert!(handles.is_empty());
    }

    #[async_test]
    async fn handles_remain_valid_after_sender_closes_them(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver).await;
        let event = Event::new();
        let sender_handle = event.as_handle().try_clone_to_owned().unwrap();
        a.send_message(&header(0), &[], &[sender_handle])
            .await
            .unwrap();
        let (_, _, mut handles) = b.recv_message(&mut MessageReceiver::new(1)).await.unwrap();
        let received = Event::from(handles.pop().unwrap());
        event.signal();
        assert!(received.try_wait());
    }

    #[async_test]
    async fn transfers_file_handle(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver).await;
        let mut file = tempfile::tempfile().unwrap();
        use std::io::Read;
        use std::io::Seek;
        use std::io::Write;
        file.write_all(b"shared").unwrap();
        file.rewind().unwrap();
        a.send_message(&header(0), &[], &[file]).await.unwrap();
        let (_, _, mut handles) = b.recv_message(&mut MessageReceiver::new(1)).await.unwrap();
        let mut received = std::fs::File::from(handles.pop().unwrap());
        let mut contents = String::new();
        received.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "shared");
    }

    #[async_test]
    async fn disconnect_is_reported(driver: DefaultDriver) {
        let (a, b) = socket_pair(&driver).await;
        drop(a);
        assert!(matches!(
            b.recv_message(&mut MessageReceiver::new(0)).await,
            Err(SocketError::Closed | SocketError::Mesh(_))
        ));
    }

    #[async_test]
    async fn backend_can_send_handles(driver: DefaultDriver) {
        let (frontend, backend) = socket_pair(&driver).await;
        let event = Event::new();
        backend
            .send_message(&header(0), &[], &[&event])
            .await
            .unwrap();
        let (_, _, mut handles) = frontend
            .recv_message(&mut MessageReceiver::new(1))
            .await
            .unwrap();
        let received = Event::from(handles.pop().unwrap());
        received.signal();
        assert!(event.try_wait());
    }

    #[async_test]
    async fn rejects_invalid_payload_size(driver: DefaultDriver) {
        let (a, _b) = socket_pair(&driver).await;
        assert!(matches!(
            a.send_message(&header(1), &[], &[] as &[OwnedHandle]).await,
            Err(SocketError::InvalidFrame(_))
        ));
    }
}
