use dns_parser::QueryType;
use dns_parser::RData;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahRequest {
    pub questions: Vec<(ArwahQueryType, String)>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ArwahResponse {
    pub answers: Vec<(String, ArwahRecord)>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ARWAH_DNS {
    Request(ArwahRequest),
    Response(ArwahResponse),
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahQueryType {
    A,
    NS,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AAAA,
    SRV,
    AXFR,
    MAILB,
    MAILA,
    All,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ArwahRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    TXT(String),
    Unknown,
}

impl From<QueryType> for ArwahQueryType {
    #[inline]
    fn from(qt: QueryType) -> ArwahQueryType {
        match qt {
            QueryType::A => ArwahQueryType::A,
            QueryType::NS => ArwahQueryType::NS,
            QueryType::MF => ArwahQueryType::MF,
            QueryType::CNAME => ArwahQueryType::CNAME,
            QueryType::SOA => ArwahQueryType::SOA,
            QueryType::MB => ArwahQueryType::MB,
            QueryType::MG => ArwahQueryType::MG,
            QueryType::MR => ArwahQueryType::MR,
            QueryType::NULL => ArwahQueryType::NULL,
            QueryType::WKS => ArwahQueryType::WKS,
            QueryType::PTR => ArwahQueryType::PTR,
            QueryType::HINFO => ArwahQueryType::HINFO,
            QueryType::MINFO => ArwahQueryType::MINFO,
            QueryType::MX => ArwahQueryType::MX,
            QueryType::TXT => ArwahQueryType::TXT,
            QueryType::AAAA => ArwahQueryType::AAAA,
            QueryType::SRV => ArwahQueryType::SRV,
            QueryType::AXFR => ArwahQueryType::AXFR,
            QueryType::MAILB => ArwahQueryType::MAILB,
            QueryType::MAILA => ArwahQueryType::MAILA,
            QueryType::All => ArwahQueryType::All,
        }
    }
}

impl ArwahRequest {
    pub fn arwah_new(questions: Vec<(ArwahQueryType, String)>) -> ArwahRequest {
        ArwahRequest { questions }
    }

    pub fn arwah_wrap(self) -> ARWAH_DNS {
        ARWAH_DNS::Request(self)
    }
}

impl ArwahResponse {
    pub fn arwah_new(answers: Vec<(String, ArwahRecord)>) -> ArwahResponse {
        ArwahResponse { answers }
    }

    pub fn arwah_wrap(self) -> ARWAH_DNS {
        ARWAH_DNS::Response(self)
    }
}

impl From<RData<'_>> for ArwahRecord {
    fn from(rdata: dns_parser::RData) -> ArwahRecord {
        match rdata {
            RData::A(addr) => ArwahRecord::A(addr.0),
            RData::AAAA(addr) => ArwahRecord::AAAA(addr.0),
            RData::CNAME(name) => ArwahRecord::CNAME(name.to_string()),
            RData::NS(name) => ArwahRecord::NS(name.to_string()),
            RData::PTR(name) => ArwahRecord::PTR(name.to_string()),
            RData::TXT(data) => {
                let mut x = Vec::new();

                for r in data.iter() {
                    x.extend(r);
                }
                ArwahRecord::TXT(String::from_utf8_lossy(&x).to_string())
            }
            _ => ArwahRecord::Unknown,
        }
    }
}
