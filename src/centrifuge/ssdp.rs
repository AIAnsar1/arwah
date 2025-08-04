use crate::network::service::ArwahCentrifugeError;
use crate::network::ssdp::ARWAH_SSDP;

pub fn arwah_parse_ssdp(data: &str) -> Result<ARWAH_SSDP, ArwahCentrifugeError> {
    if let Some(extra) = data.strip_prefix("M-SEARCH * HTTP/1.1\r\n") {
        let extra = if extra.is_empty() { None } else { Some(extra.to_string()) };
        Ok(ARWAH_SSDP::Discover(extra))
    } else if data == "M-SEARCH * HTTP/1.0" {
        Ok(ARWAH_SSDP::Discover(None))
    } else if let Some(data) = data.strip_prefix("NOTIFY * HTTP/1.1\r\n") {
        Ok(ARWAH_SSDP::Notify(data.to_string()))
    } else if let Some(data) = data.strip_prefix("BT-SEARCH * HTTP/1.1\r\n") {
        Ok(ARWAH_SSDP::BTSearch(data.to_string()))
    } else {
        Err(ArwahCentrifugeError::UnknownProtocol)
    }
}
