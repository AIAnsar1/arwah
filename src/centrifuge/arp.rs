use crate::network::arp::ArwahARP;
use crate::network::service::ArwahCentrifugeError;
use pktparse::arp::Operation;

pub fn arwah_extract(remaining: &[u8]) -> Result<ArwahARP, ArwahCentrifugeError> {
    if let Ok((_remaining, arp_pkt)) = pktparse::arp::parse_arp_pkt(remaining) {
        match arp_pkt.operation {
            Operation::Request => Ok(ArwahARP::Request(arp_pkt)),
            Operation::Reply => Ok(ArwahARP::Reply(arp_pkt)),
            Operation::Other(_) => Err(ArwahCentrifugeError::UnknownProtocol),
        }
    } else {
        Err(ArwahCentrifugeError::InvalidPacket)
    }
}
