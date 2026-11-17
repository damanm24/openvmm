// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Egress processing of the Consomme queue.
//!
//! The queue's transmit path assembles each guest frame from guest memory and
//! sends it to the Consomme stack.

use crate::ConsommeQueue;
use net_backend::BufferAccess;

impl ConsommeQueue {
    /// Sends the queued guest frames to the Consomme stack and completes all of
    /// them.
    pub(crate) fn process_tx(&mut self, pool: &mut dyn BufferAccess) {
        while let Some(packet) = self.state.next_tx() {
            // Reuse the scratch buffer to avoid per-packet heap allocation.
            // TSO caps the assembled packet at 64 KiB; assert so a buggy
            // upstream caller can't permanently inflate the scratch buffer
            // (and thus the queue's steady-state memory) by feeding an
            // oversized `meta.len`.
            debug_assert!(
                packet.len <= 64 * 1024,
                "tx packet len {} exceeds 64 KiB TSO bound",
                packet.len
            );
            let mut buf = std::mem::take(&mut self.tx_scratch);
            buf.clear();
            buf.resize(packet.len, 0);
            if let Err(err) = self.state.take_tx(&packet, pool.guest_memory(), &mut buf) {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "memory write failure"
                );
            }

            if let Err(err) = self.with_consomme(pool, |c| c.send(&buf, &packet.checksum)) {
                tracing::debug!(error = &err as &dyn std::error::Error, "tx packet ignored");
                match err {
                    consomme::DropReason::SendBufferFull
                    | consomme::DropReason::DestinationNotAllowed
                    | consomme::DropReason::TcpConnectionLimit
                    | consomme::DropReason::UdpConnectionLimit
                    | consomme::DropReason::IcmpConnectionLimit => {
                        self.stats.tx_dropped.increment()
                    }
                    consomme::DropReason::UnsupportedEthertype(_)
                    | consomme::DropReason::UnsupportedIpProtocol(_)
                    | consomme::DropReason::UnsupportedIcmpv6(_)
                    | consomme::DropReason::UnsupportedDhcp(_)
                    | consomme::DropReason::UnsupportedArp
                    | consomme::DropReason::UnsupportedDhcpv6(_)
                    | consomme::DropReason::UnsupportedNdp(_) => self.stats.tx_unknown.increment(),
                    consomme::DropReason::Packet(_)
                    | consomme::DropReason::Ipv4Checksum
                    | consomme::DropReason::Io(_)
                    | consomme::DropReason::BadTcpState(_)
                    | consomme::DropReason::FragmentedPacket
                    | consomme::DropReason::IpLengthMismatch
                    | consomme::DropReason::MalformedPacket => self.stats.tx_errors.increment(),
                }
            }
            self.tx_scratch = buf;
        }
    }
}
