use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ArwahDropboxBeacon {
    pub version: Vec<u8>,
    pub host_int: u128,
    pub namespaces: Vec<u64>,
    pub displayname: String,
    pub port: u16,
}
