use crate::network::service::ArwahCentrifugeError;
use crate::network::ssdp::ArwahSsdp;

pub fn arwah_parse_ssdp(data: &str) -> Result<ArwahSsdp, ArwahCentrifugeError> {
    if let Some(extra) = data.strip_prefix("M-SEARCH * HTTP/1.1\r\n") {
        let extra = if extra.is_empty() { None } else { Some(extra.to_string()) };
        Ok(ArwahSsdp::Discover(extra))
    } else if data == "M-SEARCH * HTTP/1.0" {
        Ok(ArwahSsdp::Discover(None))
    } else if let Some(data) = data.strip_prefix("NOTIFY * HTTP/1.1\r\n") {
        Ok(ArwahSsdp::Notify(data.to_string()))
    } else if let Some(data) = data.strip_prefix("BT-SEARCH * HTTP/1.1\r\n") {
        Ok(ArwahSsdp::BTSearch(data.to_string()))
    } else {
        Err(ArwahCentrifugeError::UnknownProtocol)
    }
}
