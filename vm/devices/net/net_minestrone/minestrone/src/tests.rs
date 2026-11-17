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
    fn recv(&mut self, data: &[u8], checksum: &ChecksumState) {
        // Without client checksum support, every frame must be complete.
        assert!(!checksum.partial && checksum.tso.is_none());
        self.frames.push(data.to_vec());
    }

    fn rx_mtu(&mut self) -> usize {
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
    mss: Option<u16>,
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
        mss: repr.max_seg_size,
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

fn remote_of(listener: &TcpListener) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port())
}

impl Harness {
    fn new(driver: DefaultDriver) -> Self {
        let mut params = MinestroneParams::local();
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

    fn send_batch(&mut self, frames: &[Vec<u8>]) {
        self.minestrone.access(&mut self.client).send_batch(
            frames.iter().map(|f| (f.as_slice(), ChecksumState::NONE)),
            |err| panic!("frame dropped: {err}"),
        );
    }

    /// Opens a flow to `listener`. Returns the host side of the connection
    /// and the guest's next sequence and acknowledgment numbers.
    async fn connect(
        &mut self,
        listener: &TcpListener,
        window: u16,
    ) -> (std::net::TcpStream, u32, u32) {
        let remote = remote_of(listener);
        self.send(&guest_frame(remote, TcpControl::Syn, 0, None, window, &[]));
        let syn_ack = self.recv().await.remove(0);
        assert_eq!(syn_ack.control, TcpControl::Syn);
        let (server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (server, 1, syn_ack.seq.wrapping_add(1))
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
    h.minestrone.set_mtu(9000);
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
    assert_eq!(syn_ack.mss, Some(8960));
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

/// Data from a batch of guest frames reaches the host in order, a segment
/// retransmitted within the batch is not duplicated, and a FIN in the batch
/// follows the data.
#[async_test]
async fn tcp_batch_writes_data_before_fin(driver: DefaultDriver) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = remote_of(&listener);
    let mut h = Harness::new(driver);
    const WINDOW: u16 = 4096;
    let (mut server, seq, ack) = h.connect(&listener, WINDOW).await;

    let frame = |control: TcpControl, offset: u32, payload: &[u8]| {
        guest_frame(remote, control, seq + offset, Some(ack), WINDOW, payload)
    };
    h.send_batch(&[
        frame(TcpControl::None, 0, b"abc"),
        frame(TcpControl::None, 3, b"def"),
        frame(TcpControl::None, 3, b"def"),
        frame(TcpControl::Fin, 6, b"ghi"),
    ]);
    let mut received = Vec::new();
    server.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"abcdefghi");
    assert_eq!(h.recv().await.pop().unwrap().ack, Some(seq + 10));
}

/// When the host socket accepts only part of a batch, the window closes.
/// Once it reopens, the window update is followed by duplicate ACKs so the
/// guest retransmits the dropped data without waiting for a timeout.
#[async_test]
async fn tcp_partial_write_requests_fast_retransmit(driver: DefaultDriver) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // A fixed receive buffer keeps the host from accepting the whole batch.
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(64 * 1024)
        .unwrap();
    let remote = remote_of(&listener);
    let mut h = Harness::new(driver);
    const WINDOW: u16 = 4096;
    let (mut server, seq, ack) = h.connect(&listener, WINDOW).await;

    // Ignore the advertised window and send more than the socket can hold.
    const FRAME: usize = 60_000;
    const FRAMES: usize = 150;
    let payload = vec![0x5a; FRAME];
    let frames: Vec<_> = (0..FRAMES)
        .map(|i| {
            let seq = seq.wrapping_add((i * FRAME) as u32);
            guest_frame(remote, TcpControl::None, seq, Some(ack), WINDOW, &payload)
        })
        .collect();
    h.send_batch(&frames);
    let blocked = h.recv().await.pop().unwrap();
    let accepted = blocked.ack.unwrap().wrapping_sub(seq) as usize;
    assert!(
        accepted > 0 && accepted < FRAME * FRAMES,
        "accepted {accepted}"
    );
    assert_eq!(blocked.window, 0);

    let reader = std::thread::spawn(move || {
        let mut buf = vec![0; 1 << 20];
        let mut total = 0;
        while total < accepted {
            total += server.read(&mut buf).unwrap();
        }
        // Return the socket so that the host side stays open.
        (server, total)
    });
    let acks = h.recv().await;
    let (_server, total) = reader.join().unwrap();
    assert_eq!(total, accepted);
    assert_eq!(acks.len(), 4, "window update and three duplicates");
    assert!(acks[0].window > 0);
    for a in &acks {
        assert_eq!(a.ack, blocked.ack);
        assert_eq!(a.window, acks[0].window);
        assert!(a.payload.is_empty());
    }
}

#[async_test]
async fn gateway_dns_and_guest_address_aliases(driver: DefaultDriver) {
    let mut params = MinestroneParams::local();
    params.gateway.gateway_ip = Ipv4Addr::new(192, 0, 2, 1);
    params.gateway.client_ip = Ipv4Addr::new(192, 0, 2, 2);
    params.gateway.assigned_ipv6 = Some("2001:db8::2".parse().unwrap());
    let v4_gateway: std::net::IpAddr = params.gateway.gateway_ip.into();
    let stub: std::net::IpAddr = Ipv4Addr::new(127, 0, 0, 53).into();
    let v6_gateway: std::net::IpAddr = params.host_ipv6_gateway.unwrap().into();
    params.configure_dns(vec![stub.into(), v6_gateway.into()]);
    assert_eq!(
        params.gateway.nameservers,
        vec![v4_gateway.into(), v6_gateway.into()]
    );
    assert!(params.map_guest_addr4.is_none() && params.map_guest_addr6.is_none());
    let link_local_dns: std::net::IpAddr = "fe80::53".parse().unwrap();
    params.gateway.nameservers.push(link_local_dns.into());
    params.host_ipv6_interface_index = 7;
    let alias4: Ipv4Addr = "192.0.2.254".parse().unwrap();
    let alias6: std::net::Ipv6Addr = "2001:db8::ff".parse().unwrap();
    params.map_guest_addr4 = Some(alias4);
    params.map_guest_addr6 = Some(alias6);
    let mut m = Minestrone::new(params.clone());
    let mut client = TestClient {
        driver,
        frames: Vec::new(),
    };
    let access = m.access(&mut client);
    assert_eq!(
        access.host_socket_address(link_local_dns, 53).unwrap(),
        std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::53".parse().unwrap(),
            53,
            0,
            7
        ))
    );
    assert!(access.host_socket_address(link_local_dns, 80).is_err());
    assert_eq!(
        access.host_destination(v4_gateway).unwrap(),
        Ipv4Addr::LOCALHOST
    );
    assert_eq!(access.host_destination_port(v4_gateway, 53).unwrap(), stub);
    assert_eq!(
        access.host_destination(v6_gateway).unwrap(),
        std::net::IpAddr::V6("::1".parse().unwrap())
    );
    assert_eq!(
        access.host_destination_port(v6_gateway, 53).unwrap(),
        v6_gateway
    );
    assert_eq!(
        access.host_destination(alias4.into()).unwrap(),
        params.gateway.client_ip
    );
    assert_eq!(
        access.host_destination(alias6.into()).unwrap(),
        params.gateway.assigned_ipv6.unwrap()
    );
    assert_eq!(
        crate::guest_visible(&params, std::net::SocketAddr::new(stub, 53)),
        std::net::SocketAddr::new(v4_gateway, 53)
    );
    assert_eq!(
        crate::guest_visible(&params, (params.gateway.client_ip, 8080).into()),
        std::net::SocketAddr::new(alias4.into(), 8080)
    );
}

/// A virtual gateway address is not a real destination, but a gateway
/// mirrored from the host is reached like any other address.
#[async_test]
async fn mirrored_gateway_is_an_ordinary_destination(driver: DefaultDriver) {
    let gateway = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut params = MinestroneParams::local();
    params.allow_host_local_access = false;
    params.gateway.gateway_ip = Ipv4Addr::new(192, 0, 2, 1);
    params.host_ipv4_gateway = true;
    let mut client = TestClient {
        driver,
        frames: Vec::new(),
    };
    let destination = |params: &MinestroneParams, client: &mut TestClient| {
        Minestrone::new(params.clone())
            .access(client)
            .host_destination(gateway)
            .ok()
    };
    assert_eq!(destination(&params, &mut client), Some(gateway));

    params.allow_host_local_access = true;
    assert_eq!(
        destination(&params, &mut client),
        Some(Ipv4Addr::LOCALHOST.into())
    );

    params.allow_host_local_access = false;
    params.set_cidr("192.0.2.0/24").unwrap();
    assert!(!params.host_ipv4_gateway);
    assert_eq!(destination(&params, &mut client), None);
}
