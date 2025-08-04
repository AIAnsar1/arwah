use self::ArwahEther::*;
use crate::network::service::ArwahNoiseLevel;
use crate::network::{arp, cjdns, ipv4, ipv6};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahEther {
    Arp(arp::ArwahARP),
    IPv4(pktparse::ipv4::IPv4Header, ipv4::ArwahIPv4),
    IPv6(pktparse::ipv6::IPv6Header, ipv6::ArwahIPv6),
    Cjdns(cjdns::ArwahCjdnsEthPkt),
    Unknown(Vec<u8>),
}

impl ArwahEther {
    pub fn arwah_noise_level(&self) -> ArwahNoiseLevel {
        match *self {
            Arp(_) => ArwahNoiseLevel::One,
            IPv4(_, ref ipv4) => ipv4.arwah_noise_level(),
            IPv6(_, ref ipv6) => ipv6.arwah_noise_level(),
            Cjdns(_) => ArwahNoiseLevel::Two,
            Unknown(_) => ArwahNoiseLevel::Maximum,
        }
    }
}
