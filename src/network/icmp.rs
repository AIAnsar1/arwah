use crate::network::service::ArwahNoiseLevel;
use pktparse::icmp::{IcmpCode, IcmpHeader};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahICMP {
    pub data: Vec<u8>,
}

impl ArwahICMP {
    pub fn arwah_noise_level(&self, header: &IcmpHeader) -> ArwahNoiseLevel {
        match header.code {
            IcmpCode::EchoReply => ArwahNoiseLevel::One,
            /*
            IcmpCode::Reserved,
            IcmpCode::DestinationUnreachable(_) =>
            IcmpCode::DestinationUnreachable(Unreachable),
            IcmpCode::SourceQuench,
            IcmpCode::Redirect(Redirect),
            */
            IcmpCode::EchoRequest => ArwahNoiseLevel::One,
            /*
            IcmpCode::RouterAdvertisment,
            IcmpCode::RouterSolicication,
            IcmpCode::TimeExceeded(_) => ArwahNoiseLevel::One,
            IcmpCode::ParameterProblem(ParameterProblem),
            IcmpCode::Timestamp,
            IcmpCode::TimestampReply,
            IcmpCode::ExtendedEchoRequest,
            IcmpCode::ExtendedEchoReply(ExtendedEchoReply),
            IcmpCode::Other(u16)
            */
            _ => ArwahNoiseLevel::Two,
        }
    }
}
