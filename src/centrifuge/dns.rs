use crate::network::dns::ArwahRecord;
use crate::network::dns::*;
use crate::network::service::ArwahCentrifugeError;
pub fn arwah_extract(remaining: &[u8]) -> Result<ARWAH_DNS, ArwahCentrifugeError> {
    if let Ok(dns) = dns_parser::Packet::parse(remaining) {
        if dns.header.query {
            let questions = dns.questions.into_iter().map(|q| (q.qtype.into(), q.qname.to_string())).collect();
            Ok(ArwahRequest::arwah_new(questions).arwah_wrap())
        } else {
            let answers = dns.answers.into_iter().map(|a| (a.name.to_string(), ArwahRecord::from(a.data))).collect();
            Ok(ArwahResponse::arwah_new(answers).arwah_wrap())
        }
    } else {
        Err(ArwahCentrifugeError::WrongProtocol)
    }
}
