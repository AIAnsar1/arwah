use crate::network::cjdns;
use crate::network::service::ArwahCentrifugeError;
use nom::bytes::complete::{tag, take};
use nom::number::complete::be_u16;

const ARWAH_BEACON_PASSWORD_LEN: usize = 20;
const ARWAH_BEACON_PUBKEY_LEN: usize = 32;

fn arwah_cjdns_eth_header(input: &[u8]) -> nom::IResult<&[u8], cjdns::ArwahCjdnsEthPkt> {
    let (input, (_version, _zero, _length, _fc00, _padding, version, password, pubkey)) =
        nom::sequence::tuple((tag(b"\x00"), tag(b"\x00"), be_u16, tag(b"\xfc\x00"), take(2_usize), be_u16, take(ARWAH_BEACON_PASSWORD_LEN), take(ARWAH_BEACON_PUBKEY_LEN)))(input)?;
    Ok((input, cjdns::ArwahCjdnsEthPkt { version, password: password.to_vec(), pubkey: pubkey.to_vec() }))
}

pub fn arwah_parse(remainig: &[u8]) -> Result<cjdns::ArwahCjdnsEthPkt, ArwahCentrifugeError> {
    if let Ok((remaining, cjdns_eth_hdr)) = arwah_cjdns_eth_header(remainig) {
        if remaining.is_empty() { Ok(cjdns_eth_hdr) } else { Err(ArwahCentrifugeError::InvalidPacket) }
    } else {
        Err(ArwahCentrifugeError::InvalidPacket)
    }
}
