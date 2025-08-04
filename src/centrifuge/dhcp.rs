use crate::network::dhcp::ARWAH_DHCP::*;
use crate::network::dhcp::*;
use crate::network::service::ArwahCentrifugeError;
use dhcp4r::options::DhcpOption::DhcpMessageType;
use dhcp4r::options::*;
use dhcp4r::packet::Packet;

fn arwah_wrap_packet(dhcp: &Packet, packet: ArwahPacket) -> ARWAH_DHCP {
    match dhcp.option(dhcp4r::options::DHCP_MESSAGE_TYPE) {
        Some(DhcpMessageType(msg_type)) => match msg_type {
            dhcp4r::options::MessageType::Ack => ACK(packet),
            dhcp4r::options::MessageType::Decline => DECLINE(packet),
            dhcp4r::options::MessageType::Discover => DISCOVER(packet),
            dhcp4r::options::MessageType::Inform => INFORM(packet),
            dhcp4r::options::MessageType::Nak => NAK(packet),
            dhcp4r::options::MessageType::Offer => OFFER(packet),
            dhcp4r::options::MessageType::Release => RELEASE(packet),
            dhcp4r::options::MessageType::Request => REQUEST(packet),
        },
        _ => UNKNOWN(packet),
    }
}

pub fn arwah_extract(remaining: &[u8]) -> Result<ARWAH_DHCP, ArwahCentrifugeError> {
    let dhcp = match dhcp4r::packet::Packet::from(remaining) {
        Ok(dhcp) => dhcp,
        Err(_err) => return Err(ArwahCentrifugeError::InvalidPacket),
    };
    let mut packet = ArwahPacket::arwah_new(dhcp.ciaddr, dhcp.yiaddr, dhcp.siaddr, dhcp.chaddr);

    for option in &dhcp.options {
        match option {
            DhcpOption::RequestedIpAddress(addr) => packet.requested_ip_address = Some(*addr),
            DhcpOption::HostName(hostname) => packet.hostname = Some(hostname.to_string()),
            DhcpOption::Router(router) => packet.router = Some(router.clone()),
            DhcpOption::DomainNameServer(server) => packet.domain_name_server = Some(server.clone()),
            _ => (),
        }
    }
    Ok(arwah_wrap_packet(&dhcp, packet))
}
