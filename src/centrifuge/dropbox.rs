use crate::network::dropbox::ArwahDropboxBeacon;
use crate::network::service::ArwahCentrifugeError;
use std::str;

pub fn arwah_extract(data: &[u8]) -> Result<ArwahDropboxBeacon, ArwahCentrifugeError> {
    let data = str::from_utf8(data).map_err(|_| ArwahCentrifugeError::InvalidPacket)?;
    let beacon = serde_json::from_str(data).map_err(|_| ArwahCentrifugeError::InvalidPacket)?;
    Ok(beacon)
}
