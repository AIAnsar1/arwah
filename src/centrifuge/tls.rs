use crate::network::service::ArwahCentrifugeError;
use crate::network::tls::{ARWAH_TLS, ArwahClientHello, ArwahServerHello};
use std::str;
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extension};

pub fn arwah_extract(remaining: &[u8]) -> Result<ARWAH_TLS, ArwahCentrifugeError> {
    if let Ok((_remaining, tls)) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            match msg {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    let mut hostname = None;

                    if let Some(mut remaining) = ch.ext {
                        while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
                            remaining = remaining2;
                            if let TlsExtension::SNI(sni) = ext {
                                for s in sni {
                                    let name = str::from_utf8(s.1).map_err(|_| ArwahCentrifugeError::ParsingError)?;
                                    hostname = Some(name.to_owned());
                                }
                            }
                        }
                        return Ok(ARWAH_TLS::ClientHello(ArwahClientHello::arwah_new(&ch, hostname)));
                    }
                }
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    return Ok(ARWAH_TLS::ServerHello(ArwahServerHello::arwah_new(&sh)));
                }
                _ => (),
            }
        }

        Err(ArwahCentrifugeError::ParsingError)
    } else {
        Err(ArwahCentrifugeError::WrongProtocol)
    }
}
