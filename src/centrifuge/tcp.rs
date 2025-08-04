use crate::centrifuge::http;
use crate::centrifuge::tls;
use crate::network::service::ArwahCentrifugeError;
use crate::network::tcp::ARWAH_TCP;
use pktparse::tcp::{self, TcpHeader};
use std::str::from_utf8;

pub fn arwah_parse(remaining: &[u8]) -> Result<(TcpHeader, ARWAH_TCP), ArwahCentrifugeError> {
    if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
        let inner = match arwah_extract(&tcp_hdr, remaining) {
            Ok(x) => x,
            Err(_) => arwah_unknown(remaining),
        };
        Ok((tcp_hdr, inner))
    } else {
        Err(ArwahCentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn arwah_extract(_tcp_hdr: &TcpHeader, remaining: &[u8]) -> Result<ARWAH_TCP, ArwahCentrifugeError> {
    if remaining.is_empty() {
        Ok(ARWAH_TCP::Empty)
    } else if let Ok(client_hello) = tls::arwah_extract(remaining) {
        Ok(ARWAH_TCP::TLS(client_hello))
    } else if let Ok(server_hello) = tls::arwah_extract(remaining) {
        Ok(ARWAH_TCP::TLS(server_hello))
    } else if let Ok(http) = http::arwah_extract(remaining) {
        Ok(ARWAH_TCP::HTTP(http))
    } else {
        Err(ArwahCentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn arwah_unknown(remaining: &[u8]) -> ARWAH_TCP {
    if remaining.contains(&0) {
        ARWAH_TCP::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => ARWAH_TCP::Text(remaining.to_owned()),
            Err(_) => ARWAH_TCP::Binary(remaining.to_vec()),
        }
    }
}
