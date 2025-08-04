use crate::network::{dhcp, dns, dropbox, service::ArwahNoiseLevel, ssdp};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ARWAH_UDP {
    DHCP(dhcp::ARWAH_DHCP),
    DNS(dns::ARWAH_DNS),
    SSDP(ssdp::ARWAH_SSDP),
    Dropbox(dropbox::ArwahDropboxBeacon),
    Text(String),
    Binary(Vec<u8>),
}

impl ARWAH_UDP {
    pub fn arwah_noise_level(&self) -> ArwahNoiseLevel {
        use self::ARWAH_UDP::*;
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
