//! Pure packet-parsing logic. No I/O, no global state: fully unit testable.

use std::net::Ipv4Addr;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

/// A UDP datagram extracted from a captured Ethernet frame.
pub struct UdpDatagram {
    /// The IPv4 address the datagram was sent from.
    pub source: Ipv4Addr,
    /// The raw UDP payload bytes.
    pub payload: Vec<u8>,
}

/// Parses a raw Ethernet frame and returns the UDP datagram only when it is an
/// IPv4/UDP packet addressed to `port`.
///
/// Any frame that is truncated, is not IPv4, does not carry UDP, or targets a
/// different port yields `None` instead of panicking.
pub fn extract_udp_datagram(frame: &[u8], port: u16) -> Option<UdpDatagram> {
    let eth = EthernetPacket::new(frame)?;
    let ipv4 = Ipv4Packet::new(eth.payload())?;

    // Only IPv4 packets whose upper-layer protocol is UDP are relevant.
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp = UdpPacket::new(ipv4.payload())?;
    if udp.get_destination() != port {
        return None;
    }

    Some(UdpDatagram {
        source: ipv4.get_source(),
        payload: udp.payload().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::util::MacAddr;

    /// Builds a minimal Ethernet + IPv4 + UDP frame carrying `payload`.
    fn build_udp_frame(src: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ipv4_len = 20 + udp_len;
        let eth_len = 14 + ipv4_len;
        let mut buf = vec![0u8; eth_len];

        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_source(MacAddr::zero());
            eth.set_destination(MacAddr::zero());
            eth.set_ethertype(EtherTypes::Ipv4);
        }
        {
            let mut ip = MutableIpv4Packet::new(&mut buf[14..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(ipv4_len as u16);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(src);
            ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
        }
        {
            let mut udp = MutableUdpPacket::new(&mut buf[14 + 20..]).unwrap();
            udp.set_source(40000);
            udp.set_destination(dst_port);
            udp.set_length(udp_len as u16);
            udp.set_payload(payload);
        }
        buf
    }

    #[test]
    fn extracts_matching_udp_datagram() {
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let frame = build_udp_frame(src, 12345, b"hello");
        let datagram = extract_udp_datagram(&frame, 12345).expect("should extract");
        assert_eq!(datagram.source, src);
        assert_eq!(datagram.payload, b"hello");
    }

    #[test]
    fn ignores_wrong_port() {
        let frame = build_udp_frame(Ipv4Addr::new(1, 2, 3, 4), 9999, b"x");
        assert!(extract_udp_datagram(&frame, 12345).is_none());
    }

    #[test]
    fn ignores_non_udp_protocol() {
        let mut frame = build_udp_frame(Ipv4Addr::new(1, 2, 3, 4), 12345, b"x");
        let mut ip = MutableIpv4Packet::new(&mut frame[14..]).unwrap();
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        assert!(extract_udp_datagram(&frame, 12345).is_none());
    }

    #[test]
    fn ignores_truncated_frame() {
        assert!(extract_udp_datagram(&[0u8; 4], 12345).is_none());
        assert!(extract_udp_datagram(&[], 12345).is_none());
    }
}
