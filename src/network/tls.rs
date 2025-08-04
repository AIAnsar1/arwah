use data_encoding::BASE64;
use serde::Serialize;
use tls_parser::{TlsClientHelloContents, TlsServerHelloContents, TlsVersion};

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahClientHello {
    pub version: Option<&'static str>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahServerHello {
    pub version: Option<&'static str>,
    pub session_id: Option<String>,
    pub cipher: Option<&'static str>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahTls {
    ClientHello(ArwahClientHello),
    ServerHello(ArwahServerHello),
}

fn arwah_tls_version(ver: TlsVersion) -> Option<&'static str> {
    match ver {
        TlsVersion::Ssl30 => Some("ssl3.0"),
        TlsVersion::Tls10 => Some("tls1.0"),
        TlsVersion::Tls11 => Some("tls1.1"),
        TlsVersion::Tls12 => Some("tls1.2"),
        TlsVersion::Tls13 => Some("tls1.3"),
        _ => None,
    }
}

impl ArwahClientHello {
    pub fn arwah_new(ch: &TlsClientHelloContents, hostname: Option<String>) -> ArwahClientHello {
        let session_id = ch.session_id.map(|id| BASE64.encode(id));
        ArwahClientHello { version: arwah_tls_version(ch.version), session_id, hostname }
    }
}

impl ArwahServerHello {
    pub fn arwah_new(sh: &TlsServerHelloContents) -> ArwahServerHello {
        let cipher = sh.cipher.get_ciphersuite().map(|cs| cs.name);
        let session_id = sh.session_id.map(|id| BASE64.encode(id));
        ArwahServerHello { version: arwah_tls_version(sh.version), session_id, cipher }
    }
}
