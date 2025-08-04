use crate::network::{dhcp, dns, dropbox, service::ArwahNoiseLevel, ssdp};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahUdp {
    DHCP(dhcp::ArwahDhcp),
    DNS(dns::ArwahDns),
    SSDP(ssdp::ArwahSsdp),
    Dropbox(dropbox::ArwahDropboxBeacon),
    Text(String),
    Binary(Vec<u8>),
}

impl ArwahUdp {
    pub fn arwah_noise_level(&self) -> ArwahNoiseLevel {
        use self::ArwahUdp::*;
        match *self {
            DHCP(_) => ArwahNoiseLevel::Zero,
            DNS(_) => ArwahNoiseLevel::Zero,
            SSDP(_) => ArwahNoiseLevel::Two,
            Dropbox(_) => ArwahNoiseLevel::Two,
            Text(_) => ArwahNoiseLevel::Two,
            Binary(_) => ArwahNoiseLevel::AlmostMaximum,
        }
    }
}
