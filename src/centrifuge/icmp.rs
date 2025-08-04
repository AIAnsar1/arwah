use crate::network::icmp::ArwahICMP;
use crate::network::service::ArwahCentrifugeError;
use pktparse::icmp::*;

pub fn arwah_parse(remaining: &[u8]) -> Result<(IcmpHeader, ArwahICMP), ArwahCentrifugeError> {
    if let Ok((remaining, icmp_hdr)) = parse_icmp_header(remaining) { Ok((icmp_hdr, ArwahICMP { data: remaining.to_vec() })) } else { Err(ArwahCentrifugeError::InvalidPacket) }
}
