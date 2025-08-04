use pktparse::{ipv4, ipv6};
use std::fmt::Display;
use std::net::Ipv4Addr;

pub trait ArwahIPHeader {
    type Addr: Display;

    fn arwah_source_addr(&self) -> Self::Addr;
    fn arwah_dest_addr(&self) -> Self::Addr;
}

impl ArwahIPHeader for ipv4::IPv4Header {
    type Addr = Ipv4Addr;

    #[inline]
    fn arwah_source_addr(&self) -> Self::Addr {
        self.source_addr
    }

    #[inline]
    fn arwah_dest_addr(&self) -> Self::Addr {
        self.dest_addr
    }
}

impl ArwahIPHeader for ipv6::IPv6Header {
    type Addr = String;

    #[inline]
    fn arwah_source_addr(&self) -> Self::Addr {
        format!("[{}]", self.source_addr)
    }

    #[inline]
    fn arwah_dest_addr(&self) -> Self::Addr {
        format!("[{}]", self.dest_addr)
    }
}
