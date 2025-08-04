use crate::network::service::ArwahNoiseLevel;
use crate::network::{icmp, tcp, udp};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahIPv4 {
    TCP(pktparse::tcp::TcpHeader, tcp::ArwahTcp),
    UDP(pktparse::udp::UdpHeader, udp::ArwahUdp),
    ICMP(pktparse::icmp::IcmpHeader, icmp::ArwahICMP),
    Unknown(Vec<u8>),
}

impl ArwahIPv4 {
    pub fn arwah_noise_level(&self) -> ArwahNoiseLevel {
        use self::ArwahIPv4::*;
        match *self {
            TCP(ref header, ref tcp) => tcp.arwah_noise_level(header),
            UDP(_, ref udp) => udp.arwah_noise_level(),
            ICMP(ref header, ref icmp) => icmp.arwah_noise_level(header),
            Unknown(_) => ArwahNoiseLevel::Maximum,
        }
    }
}
