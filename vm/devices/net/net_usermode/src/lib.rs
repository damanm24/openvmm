// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Definitions shared by the user-mode network stacks, Consomme and
//! Minestrone.
//!
//! Both stacks give a guest network access by translating its Ethernet frames
//! to host sockets. This crate holds what they have in common: the interface
//! to the guest NIC ([`FrameSink`], [`Client`], [`ChecksumState`]), address
//! helpers, and host nameserver discovery. With the `endpoint` feature, the
//! [`endpoint`] module also provides the guest queue plumbing shared by their
//! `net_backend` endpoints.

pub mod addr;
pub mod dns;
#[cfg(feature = "endpoint")]
pub mod endpoint;

use pal_async::driver::Driver;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities;

/// Standard DNS port.
pub const DNS_PORT: u16 = 53;

/// The largest standard Ethernet frame, without FCS. Frames that a stack
/// generates outside of segmentation offload always fit, so every guest
/// receive buffer can hold them.
pub const MIN_MTU: usize = 1514;

/// Checksum and segmentation state for a frame passed between a stack and the
/// guest NIC.
#[derive(Debug, Copy, Clone)]
pub struct ChecksumState {
    /// On receive, the data has a valid IPv4 header checksum. On send, the
    /// checksum should be ignored.
    pub ipv4: bool,
    /// On receive, the data has a valid TCP checksum, or a pseudo-header
    /// partial checksum when `partial` is set. On send, the checksum should be
    /// ignored.
    pub tcp: bool,
    /// On receive, the data has a valid UDP checksum, or a pseudo-header
    /// partial checksum when `partial` is set. On send, the checksum should be
    /// ignored.
    pub udp: bool,
    /// On receive, the TCP or UDP checksum contains only the uncomplemented
    /// pseudo-header sum, including the transport length. The client must
    /// complete the checksum. Not used on send.
    pub partial: bool,
    /// The data consists of multiple TCP segments, each with the provided
    /// segment size.
    ///
    /// The IP header's length field may be invalid and should be ignored.
    pub tso: Option<u16>,
    /// The data is a large UDP payload to be split into UDP datagrams of this
    /// segment size.
    pub gso: Option<u16>,
}

impl ChecksumState {
    /// No checksums are valid and no segmentation is requested.
    pub const NONE: Self = Self {
        ipv4: false,
        tcp: false,
        udp: false,
        partial: false,
        tso: None,
        gso: None,
    };
    /// A valid IPv4 header checksum only.
    pub const IPV4_ONLY: Self = Self {
        ipv4: true,
        ..Self::NONE
    };
    /// Valid IPv4 header and TCP checksums.
    pub const TCP4: Self = Self {
        ipv4: true,
        tcp: true,
        ..Self::NONE
    };
    /// Valid TCP checksum over IPv6.
    pub const TCP6: Self = Self {
        tcp: true,
        ..Self::NONE
    };
    /// Valid IPv4 header and UDP checksums.
    pub const UDP4: Self = Self {
        ipv4: true,
        udp: true,
        ..Self::NONE
    };
    /// Valid UDP checksum over IPv6.
    pub const UDP6: Self = Self {
        udp: true,
        ..Self::NONE
    };

    /// Returns smoltcp checksum capabilities that skip verifying the
    /// checksums this state marks as valid.
    pub fn caps(&self) -> ChecksumCapabilities {
        let mut caps = ChecksumCapabilities::default();
        if self.ipv4 {
            caps.ipv4 = Checksum::None;
        }
        if self.tcp {
            caps.tcp = Checksum::None;
        }
        if self.udp {
            caps.udp = Checksum::None;
        }
        caps
    }
}

/// The destination for frames sent to the guest.
pub trait FrameSink {
    /// Delivers a complete Ethernet frame to the guest.
    ///
    /// If `checksum.ipv4`, `checksum.tcp`, or `checksum.udp` are set, then the
    /// frame contains an IPv4 header, TCP header, and/or UDP header with a
    /// valid checksum, except that `checksum.partial` indicates an
    /// uncomplemented pseudo-header TCP or UDP checksum for the guest to
    /// complete.
    fn recv(&mut self, data: &[u8], checksum: &ChecksumState);

    /// Delivers one Ethernet frame whose bytes are split across `segments`,
    /// in order. This lets callers avoid linearizing headers and payload.
    ///
    /// The default implementation copies the segments into a contiguous
    /// buffer and forwards to [`FrameSink::recv`]. Sinks that can write
    /// discontiguous data directly to the guest should override this.
    fn recv_segments(&mut self, segments: &[&[u8]], checksum: &ChecksumState) {
        if let [segment] = segments {
            self.recv(segment, checksum);
            return;
        }
        self.recv(&segments.concat(), checksum);
    }

    /// Returns the largest frame, including the Ethernet header, that the
    /// next call to `recv` may deliver. This is at least [`MIN_MTU`], or 0 if
    /// the guest has no receive buffers available.
    fn rx_mtu(&mut self) -> usize;
}

/// The guest-facing side of a user-mode network stack.
pub trait Client: FrameSink {
    /// Gets the driver used to poll host sockets and timers.
    fn driver(&self) -> &dyn Driver;

    /// Whether the client can complete partial TCP and UDP receive checksums
    /// independently of GSO.
    fn rx_checksum_supported(&self) -> bool {
        false
    }

    /// Whether the client can receive TCP GSO frames with partial checksums
    /// for the given IP version.
    fn rx_gso_supported(&self, _ipv6: bool) -> bool {
        false
    }
}
