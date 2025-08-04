use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahSsdp {
    Discover(Option<String>),
    Notify(String),
    BTSearch(String),
}
