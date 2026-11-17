// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests driving guest TCP through the translator to host loopback
//! sockets. On Linux 6.9 and later these exercise the `SO_PEEK_OFF` path;
//! elsewhere, the unacknowledged-data ring.

use crate::ChecksumState;
use crate::Client;
use crate::FrameSink;
use crate::Minestrone;
use crate::MinestroneParams;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::driver::Driver;
use pal_async::timer::PolledTimer;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::TcpControl;
use smoltcp::wire::TcpPacket;
use smoltcp::wire::TcpRepr;
use smoltcp::wire::TcpSeqNumber;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::TcpListener;
use std::task::Poll;
use std::time::Duration;

const GUEST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 40000);

struct TestClient {
    driver: DefaultDriver,
    frames: Vec<Vec<u8>>,
}

impl FrameSink for TestClient {
    fn send_frame_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState) {
        // Without client checksum support, every frame must be complete.
        assert!(!checksum.partial && checksum.tso.is_none());
        self.frames.push(segments.concat());
    }

    fn max_frame_len(&mut self) -> usize {
        1514
    }
}

impl Client for TestClient {
    fn driver(&self) -> &dyn Driver {
        &self.driver
    }
}

/// A TCP segment received by the guest.
struct Segment {
    control: TcpControl,
    seq: u32,
    ack: Option<u32>,
    window: u16,
    payload: Vec<u8>,
}

fn parse(frame: &[u8]) -> Segment {
    let eth = EthernetFrame::new_checked(frame).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
    let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
    assert!(ip.verify_checksum());
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    let (src, dst) = (
        IpAddress::from(ip.src_addr()),
        IpAddress::from(ip.dst_addr()),
    );
    assert!(tcp.verify_checksum(&src, &dst), "bad tcp checksum");
    let repr = TcpRepr::parse(&tcp, &src, &dst, &ChecksumCapabilities::default()).unwrap();
    Segment {
        control: repr.control,
        seq: repr.seq_number.0 as u32,
        ack: repr.ack_number.map(|a| a.0 as u32),
        window: repr.window_len,
        payload: repr.payload.to_vec(),
    }
}

fn guest_frame(
    remote: SocketAddrV4,
    control: TcpControl,
    seq: u32,
    ack: Option<u32>,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: GUEST.port(),
        dst_port: remote.port(),
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
        window_len: window,
        window_scale: None,
        max_seg_size: (control == TcpControl::Syn).then_some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    };
    let ip = Ipv4Repr {
        src_addr: *GUEST.ip(),
        dst_addr: *remote.ip(),
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: smoltcp::wire::EthernetAddress([0, 0, 0, 0, 1, 0]),
        dst_addr: smoltcp::wire::EthernetAddress([0x52, 0x55, 10, 0, 0, 1]),
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut buf = vec![0; eth.buffer_len() + ip.buffer_len() + tcp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut buf);
    eth.emit(&mut frame);
    let mut ipp = Ipv4Packet::new_unchecked(frame.payload_mut());
    let caps = ChecksumCapabilities::default();
    ip.emit(&mut ipp, &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(ipp.payload_mut()),
        &IpAddress::Ipv4(ip.src_addr),
        &IpAddress::Ipv4(ip.dst_addr),
        &caps,
    );
    buf
}

struct Harness {
    minestrone: Minestrone,
    client: TestClient,
    timer: PolledTimer,
}

impl Harness {
    fn new(driver: DefaultDriver) -> Self {
        let mut params = MinestroneParams::new();
        params.allow_host_local_access = true;
        Self {
            minestrone: Minestrone::new(params),
            timer: PolledTimer::new(&driver),
            client: TestClient {
                driver,
                frames: Vec::new(),
            },
        }
    }

    fn send(&mut self, frame: &[u8]) {
        self.minestrone
            .access(&mut self.client)
            .send(frame, &ChecksumState::NONE)
            .unwrap();
    }

    /// Polls until at least one frame is sent to the guest, then returns all
    /// frames sent so far.
    async fn recv(&mut self) -> Vec<Segment> {
        for _ in 0..500 {
            std::future::poll_fn(|cx| {
                self.minestrone.access(&mut self.client).poll(cx);
                Poll::Ready(())
            })
            .await;
            if !self.client.frames.is_empty() {
                return self.client.frames.drain(..).map(|f| parse(&f)).collect();
            }
            self.timer.sleep(Duration::from_millis(2)).await;
        }
        panic!("timed out waiting for guest frames");
    }
}

#[async_test]
async fn tcp_round_trip_respects_guest_window(driver: DefaultDriver) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let mut h = Harness::new(driver);

    // Handshake: the SYN-ACK only arrives once the host connect completes.
    const GUEST_ISN: u32 = 1000;
    const GUEST_WINDOW: u16 = 4096;
    h.send(&guest_frame(
        remote,
        TcpControl::Syn,
        GUEST_ISN,
        None,
        GUEST_WINDOW,
        &[],
    ));
    let syn_ack = h.recv().await.remove(0);
    assert_eq!(syn_ack.control, TcpControl::Syn);
    assert_eq!(syn_ack.ack, Some(GUEST_ISN + 1));
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Guest to host: data is written through and acknowledged.
    let mut guest_seq = GUEST_ISN + 1;
    let mut guest_ack = syn_ack.seq.wrapping_add(1);
    h.send(&guest_frame(
        remote,
        TcpControl::None,
        guest_seq,
        Some(guest_ack),
        GUEST_WINDOW,
        b"hello",
    ));
    guest_seq += 5;
    let mut buf = [0; 5];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    let ack = h.recv().await.pop().unwrap();
    assert_eq!(ack.ack, Some(guest_seq));
    assert!(ack.window > 0);

    // Host to guest: never more than the guest's window is in flight.
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    server.write_all(&data).unwrap();
    server.shutdown(std::net::Shutdown::Write).unwrap();
    let mut received = Vec::new();
    let mut fin = false;
    while !fin {
        for seg in h.recv().await {
            if !seg.payload.is_empty() {
                assert_eq!(seg.seq, guest_ack, "out of order or retransmitted data");
                received.extend_from_slice(&seg.payload);
                guest_ack = guest_ack.wrapping_add(seg.payload.len() as u32);
            }
            if seg.control == TcpControl::Fin {
                assert_eq!(seg.seq, guest_ack);
                guest_ack = guest_ack.wrapping_add(1);
                fin = true;
            }
        }
        h.send(&guest_frame(
            remote,
            TcpControl::None,
            guest_seq,
            Some(guest_ack),
            GUEST_WINDOW,
            &[],
        ));
    }
    assert!(received == data, "received data differs");

    // Guest closes; the host sees EOF and the flow is released.
    h.send(&guest_frame(
        remote,
        TcpControl::Fin,
        guest_seq,
        Some(guest_ack),
        GUEST_WINDOW,
        &[],
    ));
    assert_eq!(server.read(&mut buf).unwrap(), 0);
    assert_eq!(h.minestrone.flow_counts(), (0, 0));
}

#[async_test]
async fn tcp_window_bounds_in_flight_data(driver: DefaultDriver) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port());
    let mut h = Harness::new(driver);
    const WINDOW: u16 = 3000;
    h.send(&guest_frame(remote, TcpControl::Syn, 0, None, WINDOW, &[]));
    let syn_ack = h.recv().await.remove(0);
    let (mut server, _) = listener.accept().unwrap();
    let ack = syn_ack.seq.wrapping_add(1);
    h.send(&guest_frame(
        remote,
        TcpControl::None,
        1,
        Some(ack),
        WINDOW,
        &[],
    ));

    server.write_all(&[7; 20_000]).unwrap();
    // Without acknowledgments, exactly one window of data is sent, then the
    // translator waits.
    let mut in_flight = 0;
    for _ in 0..3 {
        in_flight += h
            .recv()
            .await
            .iter()
            .map(|s| s.payload.len())
            .sum::<usize>();
        if in_flight >= WINDOW.into() {
            break;
        }
    }
    assert_eq!(in_flight, usize::from(WINDOW));
    for _ in 0..20 {
        std::future::poll_fn(|cx| {
            h.minestrone.access(&mut h.client).poll(cx);
            Poll::Ready(())
        })
        .await;
        h.timer.sleep(Duration::from_millis(2)).await;
    }
    assert!(h.client.frames.is_empty(), "sent beyond the guest window");

    // Acknowledging part of the window releases exactly that much more.
    h.send(&guest_frame(
        remote,
        TcpControl::None,
        1,
        Some(ack.wrapping_add(1000)),
        WINDOW,
        &[],
    ));
    let more: usize = h.recv().await.iter().map(|s| s.payload.len()).sum();
    assert_eq!(more, 1000);
}

#[async_test]
async fn tcp_connect_failure_resets_guest(driver: DefaultDriver) {
    // Bind then drop a listener to find a port that refuses connections.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let remote = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut h = Harness::new(driver);
    h.send(&guest_frame(remote, TcpControl::Syn, 500, None, 1000, &[]));
    let rst = h.recv().await.remove(0);
    assert_eq!(rst.control, TcpControl::Rst);
    assert_eq!(rst.ack, Some(501));
    assert_eq!(h.minestrone.flow_counts(), (0, 0));
}

#[async_test]
async fn unknown_flow_segment_is_reset(driver: DefaultDriver) {
    let mut h = Harness::new(driver);
    let remote = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80);
    h.send(&guest_frame(
        remote,
        TcpControl::None,
        10,
        Some(77),
        1000,
        b"x",
    ));
    let rst = parse(&h.client.frames.remove(0));
    assert_eq!(rst.control, TcpControl::Rst);
    assert_eq!(rst.seq, 77);
    assert_eq!(rst.ack, None);
}
