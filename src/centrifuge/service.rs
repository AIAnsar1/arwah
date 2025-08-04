use pktparse::ethernet::EtherType;
use pktparse::ip::IPProtocol;
use pktparse::{ethernet, ipv4, ipv6};

use crate::centrifuge::{arp, cjdns, icmp, sll, tcp, udp};
use crate::link::ArwahDataLink;
use crate::network::ether::ArwahEther;
use crate::network::ipv4::ArwahIPv4;
use crate::network::ipv6::ArwahIPv6;
use crate::network::raw::ArwahRaw;
use crate::network::service::ArwahCentrifugeError;

#[inline]
pub fn arwah_parse(link: &ArwahDataLink, data: &[u8]) -> ArwahRaw {
    match *link {
        ArwahDataLink::Ethernet => match arwah_parse_eth(data) {
            Ok(eth) => eth,
            Err(_) => ArwahRaw::Unknown(data.to_vec()),
        },
        ArwahDataLink::Tun => arwah_parse_tun(data),
        ArwahDataLink::Sll => arwah_parse_sll(data),
        ArwahDataLink::RadioTap => ArwahRaw::Unknown(data.to_vec()),
    }
}

#[inline]
pub fn arwah_parse_eth(data: &[u8]) -> Result<ArwahRaw, ArwahCentrifugeError> {
    if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(data) {
        let inner = match eth_frame.ethertype {
            EtherType::IPv4 => match arwah_parse_ipv4(remaining) {
                Ok(ipv4) => ipv4,
                Err(_) => ArwahEther::Unknown(remaining.to_vec()),
            },
            EtherType::IPv6 => match arwah_parse_ipv6(remaining) {
                Ok(ipv6) => ipv6,
                Err(_) => ArwahEther::Unknown(remaining.to_vec()),
            },
            EtherType::ARP => match arp::arwah_extract(remaining) {
                Ok(arp_pkt) => ArwahEther::Arp(arp_pkt),
                Err(_) => ArwahEther::Unknown(remaining.to_vec()),
            },
            EtherType::Other(0xfc00) => match cjdns::arwah_parse(remaining) {
                Ok(cjdns_pkt) => ArwahEther::Cjdns(cjdns_pkt),
                Err(_) => ArwahEther::Unknown(remaining.to_vec()),
            },
            _ => ArwahEther::Unknown(remaining.to_vec()),
        };
        Ok(ArwahRaw::Ether(eth_frame, inner))
    } else {
        Err(ArwahCentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn arwah_parse_tun(data: &[u8]) -> ArwahRaw {
    ArwahRaw::Tun(if let Ok(ipv4) = arwah_parse_ipv4(data) { ipv4 } else { ArwahEther::Unknown(data.to_vec()) })
}

pub fn arwah_parse_sll(data: &[u8]) -> ArwahRaw {
    ArwahRaw::Sll(if let Ok(frame) = sll::arwah_parse(data) { frame } else { ArwahEther::Unknown(data.to_vec()) })
}

#[inline]
pub fn arwah_parse_ipv4(data: &[u8]) -> Result<ArwahEther, ArwahCentrifugeError> {
    if let Ok((remaining, ip_hdr)) = ipv4::parse_ipv4_header(data) {
        let inner = match ip_hdr.protocol {
            IPProtocol::TCP => match tcp::arwah_parse(remaining) {
                Ok((tcp_hdr, tcp)) => ArwahIPv4::TCP(tcp_hdr, tcp),
                Err(_) => ArwahIPv4::Unknown(remaining.to_vec()),
            },
            IPProtocol::UDP => match udp::arwah_parse(remaining) {
                Ok((udp_hdr, udp)) => ArwahIPv4::UDP(udp_hdr, udp),
                Err(_) => ArwahIPv4::Unknown(remaining.to_vec()),
            },
            IPProtocol::ICMP => match icmp::arwah_parse(remaining) {
                Ok((icmp_hdr, icmp)) => ArwahIPv4::ICMP(icmp_hdr, icmp),
                Err(_) => ArwahIPv4::Unknown(remaining.to_vec()),
            },
            _ => ArwahIPv4::Unknown(remaining.to_vec()),
        };
        Ok(ArwahEther::IPv4(ip_hdr, inner))
    } else {
        Ok(ArwahEther::Unknown(data.to_vec()))
    }
}

#[inline]
pub fn arwah_parse_ipv6(data: &[u8]) -> Result<ArwahEther, ArwahCentrifugeError> {
    if let Ok((remaining, ip_hdr)) = ipv6::parse_ipv6_header(data) {
        let inner = match ip_hdr.next_header {
            IPProtocol::TCP => match tcp::arwah_parse(remaining) {
                Ok((tcp_hdr, tcp)) => ArwahIPv6::TCP(tcp_hdr, tcp),
                Err(_) => ArwahIPv6::Unknown(remaining.to_vec()),
            },
            IPProtocol::UDP => match udp::arwah_parse(remaining) {
                Ok((udp_hdr, udp)) => ArwahIPv6::UDP(udp_hdr, udp),
                Err(_) => ArwahIPv6::Unknown(remaining.to_vec()),
            },
            _ => ArwahIPv6::Unknown(remaining.to_vec()),
        };
        Ok(ArwahEther::IPv6(ip_hdr, inner))
    } else {
        Ok(ArwahEther::Unknown(data.to_vec()))
    }
}
