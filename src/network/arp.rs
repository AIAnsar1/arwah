use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ARWAH_ARP {
    Request(pktparse::arp::ArpPacket),
    Reply(pktparse::arp::ArpPacket),
}
