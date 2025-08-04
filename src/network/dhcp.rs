use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahPacket {
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub hostname: Option<String>,
    pub requested_ip_address: Option<Ipv4Addr>,
    pub router: Option<Vec<Ipv4Addr>>,
    pub domain_name_server: Option<Vec<Ipv4Addr>>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ARWAH_DHCP {
    ACK(ArwahPacket),
    DECLINE(ArwahPacket),
    DISCOVER(ArwahPacket),
    INFORM(ArwahPacket),
    NAK(ArwahPacket),
    OFFER(ArwahPacket),
    RELEASE(ArwahPacket),
    REQUEST(ArwahPacket),
    UNKNOWN(ArwahPacket),
}

impl ArwahPacket {
    pub fn arwah_new(ciaddr: Ipv4Addr, yiaddr: Ipv4Addr, siaddr: Ipv4Addr, chaddr: [u8; 6]) -> ArwahPacket {
        ArwahPacket { ciaddr, yiaddr, siaddr, chaddr, hostname: None, requested_ip_address: None, router: None, domain_name_server: None }
    }
}
