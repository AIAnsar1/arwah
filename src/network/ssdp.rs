use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ARWAH_SSDP {
    Discover(Option<String>),
    Notify(String),
    BTSearch(String),
}
