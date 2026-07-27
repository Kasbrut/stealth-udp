//! Pure packet-parsing logic. No I/O, no global state: fully unit testable.

use std::net::IpAddr;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

/// A UDP datagram extracted from a captured Ethernet frame.
pub struct UdpDatagram {
    /// The IP address (v4 or v6) the datagram was sent from.
    pub source: IpAddr,
    /// The raw UDP payload bytes.
    pub payload: Vec<u8>,
}

/// Parses a raw Ethernet frame and returns the UDP datagram only when it is an
/// IPv4/UDP or IPv6/UDP packet addressed to `port`.
///
/// Any frame that is truncated, is not IP, does not carry UDP, or targets a
/// different port yields `None` instead of panicking. IPv6 packets that place
/// extension headers before the UDP header are treated as non-UDP (the common
/// no-extension-header case is handled).
pub fn extract_udp_datagram(frame: &[u8], port: u16) -> Option<UdpDatagram> {
    let eth = EthernetPacket::new(frame)?;
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(eth.payload())?;
            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let source = IpAddr::V4(ipv4.get_source());
            udp_for_port(ipv4.payload(), port, source)
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(eth.payload())?;
            if ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let source = IpAddr::V6(ipv6.get_source());
            udp_for_port(ipv6.payload(), port, source)
        }
        _ => None,
    }
}

/// Parses `bytes` as a UDP packet and returns the datagram only if its
/// destination port matches `port`.
fn udp_for_port(bytes: &[u8], port: u16, source: IpAddr) -> Option<UdpDatagram> {
    let udp = UdpPacket::new(bytes)?;
    if udp.get_destination() != port {
        return None;
    }
    Some(UdpDatagram {
        source,
        payload: udp.payload().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::util::MacAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Builds a minimal Ethernet + IPv4 + UDP frame carrying `payload`.
    fn build_udp4_frame(src: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ipv4_len = 20 + udp_len;
        let mut buf = vec![0u8; 14 + ipv4_len];

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

    /// Builds a minimal Ethernet + IPv6 + UDP frame carrying `payload`.
    fn build_udp6_frame(src: Ipv6Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut buf = vec![0u8; 14 + 40 + udp_len];

        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_source(MacAddr::zero());
            eth.set_destination(MacAddr::zero());
            eth.set_ethertype(EtherTypes::Ipv6);
        }
        {
            let mut ip = MutableIpv6Packet::new(&mut buf[14..]).unwrap();
            ip.set_version(6);
            ip.set_next_header(IpNextHeaderProtocols::Udp);
            ip.set_payload_length(udp_len as u16);
            ip.set_hop_limit(64);
            ip.set_source(src);
            ip.set_destination(Ipv6Addr::LOCALHOST);
        }
        {
            let mut udp = MutableUdpPacket::new(&mut buf[14 + 40..]).unwrap();
            udp.set_source(40000);
            udp.set_destination(dst_port);
            udp.set_length(udp_len as u16);
            udp.set_payload(payload);
        }
        buf
    }

    #[test]
    fn extracts_matching_ipv4_datagram() {
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let frame = build_udp4_frame(src, 12345, b"hello");
        let datagram = extract_udp_datagram(&frame, 12345).expect("should extract");
        assert_eq!(datagram.source, IpAddr::V4(src));
        assert_eq!(datagram.payload, b"hello");
    }

    #[test]
    fn extracts_matching_ipv6_datagram() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let frame = build_udp6_frame(src, 12345, b"hello6");
        let datagram = extract_udp_datagram(&frame, 12345).expect("should extract");
        assert_eq!(datagram.source, IpAddr::V6(src));
        assert_eq!(datagram.payload, b"hello6");
    }

    #[test]
    fn ignores_wrong_port() {
        let frame = build_udp4_frame(Ipv4Addr::new(1, 2, 3, 4), 9999, b"x");
        assert!(extract_udp_datagram(&frame, 12345).is_none());
    }

    #[test]
    fn ignores_non_udp_protocol() {
        let mut frame = build_udp4_frame(Ipv4Addr::new(1, 2, 3, 4), 12345, b"x");
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
