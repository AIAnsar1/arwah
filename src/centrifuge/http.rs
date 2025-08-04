use crate::network::http::{ArwahHttp, ArwahRequest, ArwahResponse};
use crate::network::service::ArwahCentrifugeError;
use bstr::BString;
use httparse::Status;
use std::convert::TryFrom;

pub fn arwah_extract(remaining: &[u8]) -> Result<ArwahHttp, ArwahCentrifugeError> {
    let mut req_headers = [httparse::EMPTY_HEADER; 256];
    let mut resp_headers = [httparse::EMPTY_HEADER; 256];
    let mut req = httparse::Request::new(&mut req_headers);
    let mut resp = httparse::Response::new(&mut resp_headers);

    if let Ok(status) = req.parse(remaining) {
        let remaining = match status {
            Status::Complete(n) => &remaining[n..],
            Status::Partial => &[],
        };
        let mut req = ArwahRequest::try_from(req)?;

        if !remaining.is_empty() {
            req.body = Some(BString::from(remaining))
        }
        Ok(ArwahHttp::Request(req))
    } else if let Ok(status) = resp.parse(remaining) {
        let remaining = match status {
            Status::Complete(n) => &remaining[n..],
            Status::Partial => &[],
        };
        let mut resp = ArwahResponse::try_from(resp)?;

        if !remaining.is_empty() {
            resp.body = Some(BString::from(remaining))
        }
        Ok(ArwahHttp::Response(resp))
    } else {
        Err(ArwahCentrifugeError::WrongProtocol)
    }
}
