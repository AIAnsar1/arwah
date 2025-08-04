use crate::network::ether;
use crate::network::service::ArwahNoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahRaw {
    Ether(pktparse::ethernet::EthernetFrame, ether::ArwahEther),
    Tun(ether::ArwahEther),
    Sll(ether::ArwahEther),
    Unknown(Vec<u8>),
}

impl ArwahRaw {
    pub fn arwah_noise_level(&self) -> ArwahNoiseLevel {
        use self::ArwahRaw::*;
        match *self {
            Ether(_, ref ether) => ether.arwah_noise_level(),
            Tun(ref ether) => ether.arwah_noise_level(),
            Sll(ref ether) => ether.arwah_noise_level(),
            Unknown(_) => ArwahNoiseLevel::Maximum,
        }
    }
}
