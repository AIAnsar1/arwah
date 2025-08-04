use crate::centrifuge::{dhcp, dns, dropbox, ssdp};
use crate::network::service::ArwahCentrifugeError;
use crate::network::udp::ArwahUdp;
use pktparse::udp::{self, UdpHeader};
use std::str::from_utf8;

pub fn arwah_parse(remaining: &[u8]) -> Result<(udp::UdpHeader, ArwahUdp), ArwahCentrifugeError> {
    if let Ok((remaining, udp_hdr)) = udp::parse_udp_header(remaining) {
        let inner = match arwah_extract(udp_hdr, remaining) {
            Ok(x) => x,
            Err(_) => arwah_unknown(remaining),
        };
        Ok((udp_hdr, inner))
    } else {
        Err(ArwahCentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn arwah_extract(udp_hdr: UdpHeader, remaining: &[u8]) -> Result<ArwahUdp, ArwahCentrifugeError> {
    if remaining.is_empty() {
        Ok(ArwahUdp::Binary(Vec::new()))
    } else if udp_hdr.dest_port == 53 || udp_hdr.source_port == 53 {
        let dns = dns::arwah_extract(remaining)?;
        Ok(ArwahUdp::DNS(dns))
    } else if (udp_hdr.dest_port == 67 && udp_hdr.source_port == 68) || (udp_hdr.dest_port == 68 && udp_hdr.source_port == 67) {
        let dhcp = dhcp::arwah_extract(remaining)?;
        Ok(ArwahUdp::DHCP(dhcp))
    } else if udp_hdr.source_port == 17500 && udp_hdr.dest_port == 17500 {
        let dropbox = dropbox::arwah_extract(remaining)?;
        Ok(ArwahUdp::Dropbox(dropbox))
    } else {
        Err(ArwahCentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn arwah_unknown(remaining: &[u8]) -> ArwahUdp {
    if remaining.contains(&0) {
        ArwahUdp::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => {
                if let Ok(ssdp) = ssdp::arwah_parse_ssdp(remaining) {
                    ArwahUdp::SSDP(ssdp)
                } else {
                    ArwahUdp::Text(remaining.to_owned())
                }
            }
            Err(_) => ArwahUdp::Binary(remaining.to_vec()),
        }
    }
}
