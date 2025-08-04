use ansi_term::Color;
use bstr::ByteSlice;
use pktparse::icmp::{IcmpCode, IcmpData, IcmpHeader};
use sha2::{Digest, Sha512};
use std::cmp;
use std::fmt::Debug;
use std::sync::Arc;

use crate::network::arp::ARWAH_ARP;
use crate::network::dhcp::ARWAH_DHCP;
use crate::network::{arp, cjdns, http, icmp, ipv4, ipv6, tcp, tls, udp};
use crate::network::{ether::ArwahEther, ip::ArwahIPHeader, raw::ArwahRaw, service::ArwahNoiseLevel};

const GREY: Color = Color::Fixed(245);

#[derive(Debug, Clone)]
pub enum ArwahLayout {
    Compact,
    Debugging,
    Json,
}

pub struct ArwahConfig {
    fmt: ArwahFormat,
    filter: Arc<ArwahFilter>,
}

pub struct ArwahFormat {
    layout: ArwahLayout,
    colors: bool,
}

pub struct ArwahFilter {
    pub verbosity: u8,
}

struct ArwahDhcpKvListWriter<'a> {
    elements: Vec<(&'a str, String)>,
}

impl ArwahConfig {
    pub fn arwah_new(layout: ArwahLayout, verbosity: u8, colors: bool) -> ArwahConfig {
        ArwahConfig { fmt: ArwahFormat::arwah_new(layout, colors), filter: Arc::new(ArwahFilter::arwah_new(verbosity)) }
    }

    pub fn arwah_filter(&self) -> Arc<ArwahFilter> {
        self.filter.clone()
    }

    pub fn arwah_format(self) -> ArwahFormat {
        self.fmt
    }
}

impl ArwahFormat {
    pub fn arwah_new(layout: ArwahLayout, colors: bool) -> ArwahFormat {
        ArwahFormat { layout, colors }
    }

    #[inline]
    pub fn arwah_print(&self, packet: ArwahRaw) {
        match self.layout {
            ArwahLayout::Compact => self.arwah_print_compact(packet),
            ArwahLayout::Debugging => self.arwah_print_debugging(packet),
            ArwahLayout::Json => self.arwah_print_json(&packet),
        }
    }

    #[inline]
    fn arwah_colorify(&self, color: Color, out: String) -> String {
        if self.colors { color.normal().paint(out).to_string() } else { out }
    }

    #[inline]
    fn arwah_print_compact(&self, packet: ArwahRaw) {
        let mut out = String::new();

        let color = match packet {
            ArwahRaw::Ether(eth_frame, eth) => {
                out += &format!("{} -> {}, ", arwah_display_macaddr(eth_frame.source_mac), arwah_display_macaddr(eth_frame.dest_mac));
                self.arwah_format_compact_eth(&mut out, eth)
            }
            ArwahRaw::Tun(eth) => self.arwah_format_compact_eth(&mut out, eth),
            ArwahRaw::Sll(eth) => self.arwah_format_compact_eth(&mut out, eth),
            ArwahRaw::Unknown(data) => self.arwah_format_compact_unknown_data(&mut out, &data),
        };

        println!(
            "[ ETA ]: -> {}",
            match color {
                Some(color) => self.arwah_colorify(color, out),
                None => out,
            }
        );
    }

    #[inline]
    fn arwah_format_compact_unknown_data(&self, out: &mut String, data: &[u8]) -> Option<Color> {
        out.push_str(&format!("UNKNOWN {:?}", data));
        None
    }

    #[inline]
    fn arwah_format_compact_eth(&self, out: &mut String, eth: ArwahEther) -> Option<Color> {
        match eth {
            ArwahEther::Arp(arp_pkt) => Some(self.arwah_format_compact_arp(out, &arp_pkt)),
            ArwahEther::IPv4(ip_hdr, ipv4) => self.arwah_format_compact_ipv4(out, &ip_hdr, ipv4),
            ArwahEther::IPv6(ip_hdr, ipv6) => self.arwah_format_compact_ipv6(out, &ip_hdr, ipv6),
            ArwahEther::Cjdns(cjdns_pkt) => Some(self.arwah_format_compact_cjdns(out, &cjdns_pkt)),
            ArwahEther::Unknown(data) => self.arwah_format_compact_unknown_data(out, &data),
        }
    }

    #[inline]
    fn arwah_format_compact_arp(&self, out: &mut String, arp_pkt: &arp::ARWAH_ARP) -> Color {
        out.push_str(&match arp_pkt {
            ARWAH_ARP::Request(arp_pkt) => {
                format!("[ ETA ]: -> ARP/REQUEST {:15} ? (tell {}, {})", arp_pkt.dest_addr.to_string(), arp_pkt.src_addr, arwah_display_macaddr(arp_pkt.src_mac))
            }
            ARWAH_ARP::Reply(arp_pkt) => {
                format!(
                    "[ ETA ]: -> ARP/REPLY {:15} ! => {} (fyi  {}, {})",
                    arp_pkt.src_addr.to_string(),
                    arwah_display_macaddr(arp_pkt.src_mac),
                    arp_pkt.dest_addr,
                    arwah_display_macaddr(arp_pkt.dest_mac)
                )
            }
        });
        Color::Blue
    }

    #[inline]
    fn arwah_format_compact_cjdns(&self, out: &mut String, cjdns: &cjdns::ArwahCjdnsEthPkt) -> Color {
        let password = cjdns.password.iter().map(|b| format!("[ ETA ]: -> \\x{:02x}", b)).fold(String::new(), |a, b| a + &b);

        let ipv6 = {
            let bytes1 = Sha512::digest(&cjdns.pubkey);
            let bytes2 = Sha512::digest(bytes1);
            let mut iter = bytes2.as_slice().iter();
            let mut ipv6 = String::new();

            for x in 0..8 {
                let b1 = iter.next().unwrap();
                let b2 = iter.next().unwrap();
                ipv6.push_str(&format!("[ ETA ]: {:02x}{:02x}", b1, b2));

                if x != 7 {
                    ipv6.push(':')
                }
            }
            ipv6
        };
        out.push_str(&format!("CJDNS BEACON  version={:?}, password=\"{}\", ipv6={:?}, pubkey={:?}", cjdns.version, password, ipv6, cjdns.pubkey));
        Color::Purple
    }

    #[inline]
    fn arwah_format_compact_ipv4<IP: ArwahIPHeader>(&self, out: &mut String, ip_hdr: &IP, next: ipv4::ArwahIPv4) -> Option<Color> {
        match next {
            ipv4::ArwahIPv4::TCP(tcp_hdr, tcp) => Some(self.arwah_format_compact_ip_tcp(out, ip_hdr, &tcp_hdr, tcp)),
            ipv4::ArwahIPv4::UDP(udp_hdr, udp) => Some(self.arwah_format_compact_ip_udp(out, ip_hdr, udp_hdr, udp)),
            ipv4::ArwahIPv4::ICMP(icmp_hdr, icmp) => Some(self.arwah_format_compact_ip_icmp(out, ip_hdr, icmp_hdr, icmp)),
            ipv4::ArwahIPv4::Unknown(data) => self.arwah_format_compact_ip_unknown(out, ip_hdr, &data),
        }
    }

    #[inline]
    fn arwah_format_compact_ipv6<IP: ArwahIPHeader>(&self, out: &mut String, ip_hdr: &IP, next: ipv6::ArwahIPv6) -> Option<Color> {
        match next {
            ipv6::ArwahIPv6::TCP(tcp_hdr, tcp) => Some(self.arwah_format_compact_ip_tcp(out, ip_hdr, &tcp_hdr, tcp)),
            ipv6::ArwahIPv6::UDP(udp_hdr, udp) => Some(self.arwah_format_compact_ip_udp(out, ip_hdr, udp_hdr, udp)),
            ipv6::ArwahIPv6::Unknown(data) => self.arwah_format_compact_ip_unknown(out, ip_hdr, &data),
        }
    }

    #[inline]
    fn arwah_format_compact_ip_unknown<IP: ArwahIPHeader>(&self, out: &mut String, ip_hdr: &IP, data: &[u8]) -> Option<Color> {
        out.push_str(&format!("UNKNOWN {} -> {} {:?}", ip_hdr.arwah_source_addr(), ip_hdr.arwah_dest_addr(), data));
        None
    }

    #[inline]
    fn arwah_format_compact_ip_tcp<IP: ArwahIPHeader>(&self, out: &mut String, ip_hdr: &IP, tcp_hdr: &pktparse::tcp::TcpHeader, tcp: tcp::ARWAH_TCP) -> Color {
        let mut flags = String::new();
        if tcp_hdr.flag_syn {
            flags.push('S')
        }
        if tcp_hdr.flag_ack {
            flags.push('A')
        }
        if tcp_hdr.flag_rst {
            flags.push('R')
        }
        if tcp_hdr.flag_fin {
            flags.push('F')
        }
        out.push_str(&format!("[tcp/{:2}] {:22} -> {:22} ", flags, format!("{}:{}", ip_hdr.arwah_source_addr(), tcp_hdr.source_port), format!("{}:{}", ip_hdr.arwah_dest_addr(), tcp_hdr.dest_port)));

        match tcp {
            tcp::ARWAH_TCP::HTTP(http::ArwahHttp::Request(http)) => {
                out.push_str("[http] req, ");

                let offset = out.len();
                out.push_str(&format!("{:?} {:?} HTTP/1.{}", http.method, http.path, http.version));

                if let Some(host) = &http.host {
                    out.push_str(&format!(" http://{host}{}", http.path));
                }

                for (key, value) in &http.headers {
                    out.push_str(&arwah_align(offset, &format!("{key:?}: {value:?}")));
                }

                if let Some(body) = http.body {
                    out.push('\n');
                    out.push_str(&arwah_align(offset, &format!("{body:?}")));
                }

                Color::Red
            }
            tcp::ARWAH_TCP::HTTP(http::ArwahHttp::Response(http)) => {
                out.push_str("[http] resp, ");
                let offset = out.len();
                out.push_str(&format!("HTTP/1.{} {} {:?} ", http.version, http.code, http.reason));

                for (key, value) in &http.headers {
                    out.push_str(&arwah_align(offset, &format!("{key:?}: {value:?}")));
                }

                if let Some(body) = http.body {
                    out.push('\n');
                    out.push_str(&arwah_align(offset, &format!("{body:?}")));
                }

                Color::Red
            }
            tcp::ARWAH_TCP::TLS(tls::ARWAH_TLS::ClientHello(client_hello)) => {
                let extra = arwah_display_kv_list(&[("version", client_hello.version), ("session", client_hello.session_id.as_deref()), ("hostname", client_hello.hostname.as_deref())]);
                out.push_str("TLS ClientHello");
                out.push_str(&extra);
                Color::Green
            }
            tcp::ARWAH_TCP::TLS(tls::ARWAH_TLS::ServerHello(server_hello)) => {
                let extra = arwah_display_kv_list(&[("version", server_hello.version), ("session", server_hello.session_id.as_deref()), ("cipher", server_hello.cipher)]);
                out.push_str("TLS ServerHello");
                out.push_str(&extra);
                Color::Green
            }
            tcp::ARWAH_TCP::Text(text) => {
                out.push_str(&format!("TEXT {:?}", text));
                Color::Red
            }
            tcp::ARWAH_TCP::Binary(x) => {
                out.push_str(&format!("BINARY {:?}", x.as_bstr()));
                if tcp_hdr.flag_rst { GREY } else { Color::Red }
            }
            tcp::ARWAH_TCP::Empty => GREY,
        }
    }

    #[inline]
    fn arwah_format_compact_ip_udp<IP: ArwahIPHeader>(&self, out: &mut String, ip_hdr: &IP, udp_hdr: pktparse::udp::UdpHeader, udp: udp::ARWAH_UDP) -> Color {
        out.push_str(&format!("UDP {:22} -> {:22} ", format!("{}:{}", ip_hdr.arwah_source_addr(), udp_hdr.source_port), format!("{}:{}", ip_hdr.arwah_dest_addr(), udp_hdr.dest_port)));
        match udp {
            udp::ARWAH_UDP::DHCP(dhcp) => {
                match dhcp {
                    ARWAH_DHCP::DISCOVER(disc) => {
                        out.push_str(&format!("DHCP DISCOVER: {}", arwah_display_macadr_buf(disc.chaddr)));
                        out.push_str(&ArwahDhcpKvListWriter::arwah_new().arwah_append("hostname", &disc.hostname).arwah_append("requested_ip_address", &disc.requested_ip_address).arwah_finalize());
                    }
                    ARWAH_DHCP::REQUEST(req) => {
                        out.push_str(&format!("DHCP REQ: {}", arwah_display_macadr_buf(req.chaddr)));
                        out.push_str(&ArwahDhcpKvListWriter::arwah_new().arwah_append("hostname", &req.hostname).arwah_append("requested_ip_address", &req.requested_ip_address).arwah_finalize());
                    }
                    ARWAH_DHCP::ACK(ack) => {
                        out.push_str(&format!("DHCP ACK: {} => {}", arwah_display_macadr_buf(ack.chaddr), ack.yiaddr));
                        out.push_str(
                            &ArwahDhcpKvListWriter::arwah_new()
                                .arwah_append("hostname", &ack.hostname)
                                .arwah_append("router", &ack.router)
                                .arwah_append("dns", &ack.domain_name_server)
                                .arwah_finalize(),
                        );
                    }
                    ARWAH_DHCP::OFFER(offer) => {
                        out.push_str(&format!("DHCP OFFER: {} => {}", arwah_display_macadr_buf(offer.chaddr), offer.yiaddr));
                        out.push_str(
                            &ArwahDhcpKvListWriter::arwah_new()
                                .arwah_append("hostname", &offer.hostname)
                                .arwah_append("router", &offer.router)
                                .arwah_append("dns", &offer.domain_name_server)
                                .arwah_finalize(),
                        );
                    }
                    _ => {
                        out.push_str(&format!("DHCP {:?}", dhcp));
                    }
                };
                Color::Blue
            }
            udp::ARWAH_UDP::DNS(dns) => {
                match dns {
                    crate::network::dns::ARWAH_DNS::Request(req) => {
                        out.push_str("DNS req, ");

                        match req.questions.iter().map(|x| format!("{:?}", x)).reduce(|a, b| a + &arwah_align(out.len(), &b)) {
                            Some(dns_str) => out.push_str(&dns_str),
                            None => out.push_str("[]"),
                        };
                    }
                    crate::network::dns::ARWAH_DNS::Response(resp) => {
                        out.push_str("DNS resp, ");
                        match resp.answers.iter().map(|x| format!("{:?}", x)).reduce(|a, b| a + &arwah_align(out.len(), &b)) {
                            Some(dns_str) => out.push_str(&dns_str),
                            None => out.push_str("[]"),
                        };
                    }
                };

                Color::Yellow
            }
            udp::ARWAH_UDP::SSDP(ssdp) => {
                out.push_str(&match ssdp {
                    crate::network::ssdp::ARWAH_SSDP::Discover(None) => "[ssdp] searching...".to_string(),
                    crate::network::ssdp::ARWAH_SSDP::Discover(Some(extra)) => format!("[ssdp] searching({:?})...", extra),
                    crate::network::ssdp::ARWAH_SSDP::Notify(extra) => format!("[ssdp] notify: {:?}", extra),
                    crate::network::ssdp::ARWAH_SSDP::BTSearch(extra) => format!("[ssdp] torrent search: {:?}", extra),
                });
                Color::Purple
            }
            udp::ARWAH_UDP::Dropbox(dropbox) => {
                out.push_str(&format!(
                    "[dropbox] beacon: version={:?}, host_int={:?}, namespaces={:?}, displayname={:?}, port={:?}",
                    dropbox.version, dropbox.host_int, dropbox.namespaces, dropbox.displayname, dropbox.port
                ));
                Color::Purple
            }
            udp::ARWAH_UDP::Text(text) => {
                out.push_str(&format!("TEXT {:?}", text));
                Color::Red
            }
            udp::ARWAH_UDP::Binary(x) => {
                out.push_str(&format!("BINARY {:?}", x.as_bstr()));
                Color::Red
            }
        }
    }

    fn arwah_format_compact_ip_icmp<IP: ArwahIPHeader>(&self, out: &mut String, ip_hdr: &IP, icmp_hdr: IcmpHeader, icmp: icmp::ArwahICMP) -> Color {
        let code = match icmp_hdr.code {
            IcmpCode::EchoReply => Some("icmp/pong"),
            /*
            IcmpCode::Reserved,
            */
            IcmpCode::DestinationUnreachable(_) => Some("icmp/unrch"),
            /*
            IcmpCode::DestinationUnreachable(Unreachable),
            IcmpCode::SourceQuench,
            IcmpCode::Redirect(Redirect),
            */
            IcmpCode::EchoRequest => Some("icmp/ping"),
            /*
            IcmpCode::RouterAdvertisment,
            IcmpCode::RouterSolicication,
            */
            IcmpCode::TimeExceeded(_) => Some("icmp/ttl"),
            /*
            IcmpCode::ParameterProblem(ParameterProblem),
            IcmpCode::Timestamp,
            IcmpCode::TimestampReply,
            IcmpCode::ExtendedEchoRequest,
            IcmpCode::ExtendedEchoReply(ExtendedEchoReply),
            IcmpCode::Other(u16)
            */
            _ => None,
        };
        out.push_str(&format!("[ ETA ]: -> [{:10}] {:18} -> {:22} [code={:?}", code.unwrap_or("icmp"), ip_hdr.arwah_source_addr(), ip_hdr.arwah_dest_addr(), icmp_hdr.code));

        if icmp_hdr.data != IcmpData::None {
            out.push_str(&format!(", data={:?}", icmp_hdr.data));
        }
        out.push_str(&format!("] {:?}", icmp.data.as_bstr()));
        Color::Blue
    }

    #[inline]
    fn arwah_print_debugging(&self, packet: ArwahRaw) {
        match packet {
            ArwahRaw::Ether(eth_frame, eth) => {
                println!("ETH -> {:?}", eth_frame);
                self.arwah_print_debugging_eth(1, eth);
            }
            ArwahRaw::Tun(eth) => self.arwah_print_debugging_eth(0, eth),
            ArwahRaw::Sll(eth) => self.arwah_print_debugging_eth(0, eth),
            ArwahRaw::Unknown(data) => println!("UNKNOWN -> {:?}", data),
        }
    }

    #[inline]
    fn arwah_print_debugging_eth(&self, indent: usize, eth: ArwahEther) {
        match eth {
            ArwahEther::Arp(arp_pkt) => {
                println!("{}{}", "\t".repeat(indent), self.arwah_colorify(Color::Blue, format!("[ ETA ]: -> ARP  {:?}", arp_pkt)));
            }
            ArwahEther::IPv4(ip_hdr, ipv4::ArwahIPv4::TCP(tcp_hdr, tcp)) => {
                println!("{} IPv4 -> {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} TCP -> {:?}", "\t".repeat(indent + 1), tcp_hdr);
                println!("{}{}", "\t".repeat(indent + 2), self.arwah_print_debugging_tcp(tcp));
            }
            ArwahEther::IPv4(ip_hdr, ipv4::ArwahIPv4::UDP(udp_hdr, udp)) => {
                println!("{} IPv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} UDP: {:?}", "\t".repeat(indent + 1), udp_hdr);
                println!("{}{}", "\t".repeat(indent + 2), self.arwah_print_debugging_udp(udp));
            }
            ArwahEther::IPv4(ip_hdr, ipv4::ArwahIPv4::ICMP(icmp_hdr, icmp)) => {
                println!("{} IPv4 -> {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} ICMP -> {:?}", "\t".repeat(indent + 1), icmp_hdr);
                println!("{}{:?}", "\t".repeat(indent + 2), icmp.data);
            }
            ArwahEther::IPv4(ip_hdr, ipv4::ArwahIPv4::Unknown(data)) => {
                println!("{} ipv4 -> {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} UNKNOWN -> {:?}", "\t".repeat(indent + 1), data);
            }
            ArwahEther::IPv6(ip_hdr, ipv6::ArwahIPv6::TCP(tcp_hdr, tcp)) => {
                println!("{} IPv6 -> {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} TCP -> {:?}", "\t".repeat(indent + 1), tcp_hdr);
                println!("{}{}", "\t".repeat(indent + 2), self.arwah_print_debugging_tcp(tcp));
            }
            ArwahEther::IPv6(ip_hdr, ipv6::ArwahIPv6::UDP(udp_hdr, udp)) => {
                println!("{} IPv6 -> {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} UDP -> {:?}", "\t".repeat(indent + 1), udp_hdr);
                println!("{}{}", "\t".repeat(indent + 2), self.arwah_print_debugging_udp(udp));
            }
            ArwahEther::IPv6(ip_hdr, ipv6::ArwahIPv6::Unknown(data)) => {
                println!("{} IPv6 -> {:?}", "\t".repeat(indent), ip_hdr);
                println!("{} UNKNOWN -> {:?}", "\t".repeat(indent + 1), data);
            }
            ArwahEther::Cjdns(cjdns_pkt) => {
                println!("{} CJDNS -> {:?}", "\t".repeat(indent), cjdns_pkt);
            }
            ArwahEther::Unknown(data) => {
                println!("{} UNKNOWN -> {:?}", "\t".repeat(indent), data);
            }
        }
    }

    #[inline]
    fn arwah_print_debugging_tcp(&self, tcp: tcp::ARWAH_TCP) -> String {
        match tcp {
            tcp::ARWAH_TCP::HTTP(http::ArwahHttp::Request(http)) => self.arwah_colorify(Color::Red, format!("HTTP -> {http:?}")),
            tcp::ARWAH_TCP::HTTP(http::ArwahHttp::Response(http)) => self.arwah_colorify(Color::Red, format!("HTTP -> {http:?}")),
            tcp::ARWAH_TCP::TLS(client_hello) => self.arwah_colorify(Color::Green, format!("TLS -> {:?}", client_hello)),
            tcp::ARWAH_TCP::Text(text) => self.arwah_colorify(Color::Blue, format!("TEXT -> {:?}", text)),
            tcp::ARWAH_TCP::Binary(x) => self.arwah_colorify(Color::Yellow, format!("BINARY -> {:?}", x)),
            tcp::ARWAH_TCP::Empty => self.arwah_colorify(GREY, String::new()),
        }
    }

    #[inline]
    fn arwah_print_debugging_udp(&self, udp: udp::ARWAH_UDP) -> String {
        match udp {
            udp::ARWAH_UDP::DHCP(dhcp) => self.arwah_colorify(Color::Green, format!("DHCP -> {:?}", dhcp)),
            udp::ARWAH_UDP::DNS(dns) => self.arwah_colorify(Color::Green, format!("DNS -> {:?}", dns)),
            udp::ARWAH_UDP::SSDP(ssdp) => self.arwah_colorify(Color::Purple, format!("SSDP -> {:?}", ssdp)),
            udp::ARWAH_UDP::Dropbox(dropbox) => self.arwah_colorify(Color::Purple, format!("DROPBOX -> {:?}", dropbox)),
            udp::ARWAH_UDP::Text(text) => self.arwah_colorify(Color::Blue, format!("TEXT -> {:?}", text)),
            udp::ARWAH_UDP::Binary(x) => self.arwah_colorify(Color::Yellow, format!("BINARY -> {:?}", x)),
        }
    }

    #[inline]
    fn arwah_print_json(&self, packet: &ArwahRaw) {
        println!("{}", serde_json::to_string(packet).unwrap())
    }
}

impl ArwahFilter {
    #[inline]
    pub fn arwah_new(verbosity: u8) -> ArwahFilter {
        let verbosity = cmp::min(verbosity, ArwahNoiseLevel::Maximum.arwah_into_u8());

        ArwahFilter { verbosity }
    }

    #[inline]
    pub fn arwah_matches(&self, packet: &ArwahRaw) -> bool {
        packet.arwah_noise_level().arwah_into_u8() <= self.verbosity
    }
}

impl<'a> ArwahDhcpKvListWriter<'a> {
    fn arwah_new() -> ArwahDhcpKvListWriter<'a> {
        ArwahDhcpKvListWriter { elements: vec![] }
    }

    fn arwah_append<T: Debug>(mut self, key: &'a str, value: &Option<T>) -> Self {
        if let Some(value) = value {
            self.elements.push((key, format!("{:?}", value)));
        }
        self
    }

    fn arwah_finalize(self) -> String {
        self.elements.iter().map(|&(key, ref value)| format!("{} {}", key, value)).reduce(|a, b| a + ", " + &b).map_or_else(String::new, |extra| format!(" ({})", extra))
    }
}

#[inline]
fn arwah_align(len: usize, a: &str) -> String {
    format!("\n{} {}", " ".repeat(len), &a)
}

#[inline]
fn arwah_display_macaddr(mac: pktparse::ethernet::MacAddress) -> String {
    arwah_display_macadr_buf(mac.0)
}

#[inline]
fn arwah_display_macadr_buf(mac: [u8; 6]) -> String {
    let mut string = mac.iter().fold(String::new(), |acc, &x| format!("{}{:02x}:", acc, x));
    string.pop();
    string
}

#[inline]
fn arwah_display_kv_list(list: &[(&str, Option<&str>)]) -> String {
    list.iter().filter_map(|&(key, ref value)| value.as_ref().map(|value| format!("{}: {:?}", key, value))).reduce(|a, b| a + ", " + &b).map_or_else(String::new, |extra| format!(" ({})", extra))
}
