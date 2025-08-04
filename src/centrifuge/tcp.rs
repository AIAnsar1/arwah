use crate::centrifuge::http;
use crate::centrifuge::tls;
use crate::network::service::ArwahCentrifugeError;
use crate::network::tcp::ArwahTcp;
use pktparse::tcp::{self, TcpHeader};
use std::str::from_utf8;

pub fn arwah_parse(remaining: &[u8]) -> Result<(TcpHeader, ArwahTcp), ArwahCentrifugeError> {
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
pub fn arwah_extract(_tcp_hdr: &TcpHeader, remaining: &[u8]) -> Result<ArwahTcp, ArwahCentrifugeError> {
    if remaining.is_empty() {
        Ok(ArwahTcp::Empty)
    } else if let Ok(client_hello) = tls::arwah_extract(remaining) {
        Ok(ArwahTcp::TLS(client_hello))
    } else if let Ok(server_hello) = tls::arwah_extract(remaining) {
        Ok(ArwahTcp::TLS(server_hello))
    } else if let Ok(http) = http::arwah_extract(remaining) {
        Ok(ArwahTcp::HTTP(http))
    } else {
        Err(ArwahCentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn arwah_unknown(remaining: &[u8]) -> ArwahTcp {
    if remaining.contains(&0) {
        ArwahTcp::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => ArwahTcp::Text(remaining.to_owned()),
            Err(_) => ArwahTcp::Binary(remaining.to_vec()),
        }
    }
}
