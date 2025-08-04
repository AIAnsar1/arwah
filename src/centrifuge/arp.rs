use crate::network::arp::ARWAH_ARP;
use crate::network::service::ArwahCentrifugeError;
use pktparse::arp::Operation;

pub fn arwah_extract(remaining: &[u8]) -> Result<ARWAH_ARP, ArwahCentrifugeError> {
    if let Ok((_remaining, arp_pkt)) = pktparse::arp::parse_arp_pkt(remaining) {
        match arp_pkt.operation {
            Operation::Request => Ok(ARWAH_ARP::Request(arp_pkt)),
            Operation::Reply => Ok(ARWAH_ARP::Reply(arp_pkt)),
            Operation::Other(_) => Err(ArwahCentrifugeError::UnknownProtocol),
        }
    } else {
        Err(ArwahCentrifugeError::InvalidPacket)
    }
}
