// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARP responder: as in passt, answers requests for any address other than
//! the guest's own with the gateway's MAC address, so that all traffic,
//! including traffic to other addresses on the guest's subnet, is sent to the
//! gateway.

use super::ChecksumState;
use super::FrameSink;
use super::GatewayConfig;
use super::MIN_MTU;
use super::ServiceError;
use smoltcp::wire::ArpOperation;
use smoltcp::wire::ArpPacket;
use smoltcp::wire::ArpRepr;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;

pub(crate) fn handle_arp(
    cfg: &GatewayConfig,
    frame: &EthernetRepr,
    payload: &[u8],
    sink: &mut dyn FrameSink,
) -> Result<(), ServiceError> {
    let arp = ArpRepr::parse(&ArpPacket::new_checked(payload)?)?;
    let ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr,
        source_protocol_addr,
        target_protocol_addr,
        ..
    } = arp
    else {
        return Err(ServiceError::UnsupportedArp);
    };

    if cfg.client_ip == target_protocol_addr
        // Ignore announcements, but not probes from 0.0.0.0.
        || (source_protocol_addr == target_protocol_addr && !source_protocol_addr.is_unspecified())
    {
        return Ok(());
    }

    let e_repr = EthernetRepr {
        src_addr: cfg.gateway_mac,
        dst_addr: frame.src_addr,
        ethertype: EthernetProtocol::Arp,
    };
    let arp_repr = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: cfg.gateway_mac,
        source_protocol_addr: target_protocol_addr,
        target_hardware_addr: source_hardware_addr,
        target_protocol_addr: source_protocol_addr,
    };
    let mut buffer = [0; MIN_MTU];
    let mut response = EthernetFrame::new_unchecked(&mut buffer[..]);
    e_repr.emit(&mut response);
    arp_repr.emit(&mut ArpPacket::new_unchecked(response.payload_mut()));
    let len = e_repr.buffer_len() + arp_repr.buffer_len();
    sink.recv(&buffer[..len], &ChecksumState::NONE);
    Ok(())
}
