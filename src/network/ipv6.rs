use crate::network::service::ArwahNoiseLevel;
use crate::network::tcp;
use crate::network::udp;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahIPv6 {
    TCP(pktparse::tcp::TcpHeader, tcp::ArwahTcp),
    UDP(pktparse::udp::UdpHeader, udp::ArwahUdp),
    Unknown(Vec<u8>),
}

impl ArwahIPv6 {
    pub fn arwah_noise_level(&self) -> ArwahNoiseLevel {
        use self::ArwahIPv6::*;
        match *self {
            TCP(ref header, ref tcp) => tcp.arwah_noise_level(header),
            UDP(_, ref udp) => udp.arwah_noise_level(),
            Unknown(_) => ArwahNoiseLevel::Maximum,
        }
    }
}
