use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahARP {
    Request(pktparse::arp::ArpPacket),
    Reply(pktparse::arp::ArpPacket),
}
