use crate::network::service::ArwahNoiseLevel;
use crate::network::{http, tls};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahTcp {
    TLS(tls::ArwahTls),
    HTTP(http::ArwahHttp),
    Text(String),
    Binary(Vec<u8>),
    Empty,
}

impl ArwahTcp {
    pub fn arwah_noise_level(&self, header: &pktparse::tcp::TcpHeader) -> ArwahNoiseLevel {
        use self::ArwahTcp::*;

        if header.flag_rst || header.flag_syn || header.flag_fin {
            match *self {
                Text(_) => ArwahNoiseLevel::Two,
                Binary(_) => ArwahNoiseLevel::Two,
                Empty => ArwahNoiseLevel::Two,
                _ => ArwahNoiseLevel::Zero,
            }
        } else {
            match *self {
                Text(ref text) if text.len() <= 8 => ArwahNoiseLevel::AlmostMaximum,
                Binary(_) => ArwahNoiseLevel::AlmostMaximum,
                Empty => ArwahNoiseLevel::AlmostMaximum,
                _ => ArwahNoiseLevel::Zero,
            }
        }
    }
}
