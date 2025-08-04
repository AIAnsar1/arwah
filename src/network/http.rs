use crate::network::service::ArwahCentrifugeError;
use bstr::BString;
use httparse::Header;
use serde::Serialize;
use std::convert::TryFrom;
use std::str;

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahRequest {
    pub method: String,
    pub path: String,
    pub version: u8,
    pub headers: Vec<(String, BString)>,
    pub host: Option<String>,
    pub agent: Option<String>,
    pub referer: Option<String>,
    pub auth: Option<String>,
    pub cookies: Option<String>,
    pub body: Option<BString>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahResponse {
    pub code: u16,
    pub reason: String,
    pub version: u8,
    pub headers: Vec<(String, BString)>,
    pub body: Option<BString>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahHttp {
    Request(ArwahRequest),
    Response(ArwahResponse),
}

fn arwah_append_if_header(mem: &mut Option<String>, expected: &str, header: &Header) {
    if header.name.eq_ignore_ascii_case(expected) {
        if let Ok(value) = str::from_utf8(header.value) {
            let mem = mem.get_or_insert_with(String::new);

            if !mem.is_empty() {
                mem.push_str("; ");
            }
            mem.push_str(value);
        }
    }
}

impl TryFrom<httparse::Request<'_, '_>> for ArwahRequest {
    type Error = ArwahCentrifugeError;

    fn try_from(req: httparse::Request) -> Result<ArwahRequest, ArwahCentrifugeError> {
        let Some(method) = req.method else { return Err(ArwahCentrifugeError::InvalidPacket) };
        let Some(path) = req.path else { return Err(ArwahCentrifugeError::InvalidPacket) };
        let Some(version) = req.version else { return Err(ArwahCentrifugeError::InvalidPacket) };

        let mut out = ArwahRequest { method: method.to_string(), path: path.to_string(), version, headers: Vec::new(), host: None, agent: None, referer: None, auth: None, cookies: None, body: None };

        for header in req.headers {
            out.headers.push((header.name.into(), header.value.into()));
            arwah_append_if_header(&mut out.host, "host", header);
            arwah_append_if_header(&mut out.agent, "user-agent", header);
            arwah_append_if_header(&mut out.referer, "referer", header);
            arwah_append_if_header(&mut out.auth, "authorization", header);
            arwah_append_if_header(&mut out.cookies, "cookie", header);
        }
        Ok(out)
    }
}

impl TryFrom<httparse::Response<'_, '_>> for ArwahResponse {
    type Error = ArwahCentrifugeError;

    fn try_from(res: httparse::Response) -> Result<ArwahResponse, ArwahCentrifugeError> {
        let Some(version) = res.version else { return Err(ArwahCentrifugeError::InvalidPacket) };
        let Some(code) = res.code else { return Err(ArwahCentrifugeError::InvalidPacket) };
        let Some(reason) = res.reason else { return Err(ArwahCentrifugeError::InvalidPacket) };
        let mut out = ArwahResponse { version, code, reason: reason.to_string(), headers: Vec::new(), body: None };

        for header in res.headers {
            out.headers.push((header.name.into(), header.value.into()));
        }
        Ok(out)
    }
}
