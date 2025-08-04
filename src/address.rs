use crate::input::ArwahOpts;
use crate::warning;
use cidr_utils::cidr::{IpCidr, IpInet};
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
};
use log::debug;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, prelude::*};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

pub fn arwah_parse_addresses(input: &ArwahOpts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_addresses: Vec<&str> = Vec::new();
    let backup_resolver = arwah_get_resolver(&input.resolver);

    for address in &input.addresses {
        let parsed_ips = arwah_parse_address(address, &backup_resolver);

        if !parsed_ips.is_empty() {
            ips.extend(parsed_ips);
        } else {
            unresolved_addresses.push(address);
        }
    }

    for file_path in unresolved_addresses {
        let file_path = Path::new(file_path);

        if !file_path.is_file() {
            warning!(format!("[ ETA ]: Host {file_path:?} could not be resolved."), input.greppable, input.accessible);
            continue;
        }

        if let Ok(x) = arwah_read_ips_from_file(file_path, &backup_resolver) {
            ips.extend(x);
        } else {
            warning!(format!("[ ETA ]: Host {file_path:?} could not be resolved."), input.greppable, input.accessible);
        }
    }
    let excluded_cidrs = arwah_parse_excluded_networks(&input.exclude_addresses, &backup_resolver);
    let mut seen = BTreeSet::new();
    ips.retain(|ip| seen.insert(*ip) && !excluded_cidrs.iter().any(|cidr| cidr.contains(ip)));
    ips
}

pub fn arwah_parse_address(address: &str, resolver: &Resolver) -> Vec<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(address) {
        vec![addr]
    } else if let Ok(net_addr) = IpInet::from_str(address) {
        net_addr.network().into_iter().addresses().collect()
    } else {
        match format!("{address}:80").to_socket_addrs() {
            Ok(mut iter) => vec![iter.next().unwrap().ip()],
            Err(_) => arwah_resolve_ips_from_host(address, resolver),
        }
    }
}

fn arwah_resolve_ips_from_host(source: &str, backup_resolver: &Resolver) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = backup_resolver.lookup_ip(source) {
        ips.extend(addrs.iter())
    }
    ips
}

fn arwah_parse_excluded_networks(exclude_addresses: &Option<Vec<String>>, resolver: &Resolver) -> Vec<IpCidr> {
    exclude_addresses.iter().flatten().flat_map(|addr| arwah_parse_single_excluded_address(addr, resolver)).collect()
}

fn arwah_parse_single_excluded_address(addr: &str, resolver: &Resolver) -> Vec<IpCidr> {
    if let Ok(cidr) = IpCidr::from_str(addr) {
        return vec![cidr];
    }

    if let Ok(ip) = IpAddr::from_str(addr) {
        return vec![IpCidr::new_host(ip)];
    }
    arwah_resolve_ips_from_host(addr, resolver).into_iter().map(IpCidr::new_host).collect()
}

fn arwah_get_resolver(resolver: &Option<String>) -> Resolver {
    match resolver {
        Some(r) => {
            let mut config = ResolverConfig::new();
            let resolver_ips = match arwah_read_resolver_from_file(r) {
                Ok(ips) => ips,
                Err(_) => r.split(',').filter_map(|r| IpAddr::from_str(r).ok()).collect::<Vec<_>>(),
            };

            for ip in resolver_ips {
                config.add_name_server(NameServerConfig::new(SocketAddr::new(ip, 53), Protocol::Udp));
            }
            Resolver::new(config, ResolverOpts::default()).unwrap()
        }
        None => match Resolver::from_system_conf() {
            Ok(resolver) => resolver,
            Err(_) => Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap(),
        },
    }
}

fn arwah_read_resolver_from_file(path: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let ips = fs::read_to_string(path)?.lines().filter_map(|line| IpAddr::from_str(line.trim()).ok()).collect();
    Ok(ips)
}

#[cfg(not(tarpaulin_include))]
fn arwah_read_ips_from_file(ips: &std::path::Path, backup_resolver: &Resolver) -> Result<Vec<IpAddr>, std::io::Error> {
    let file = File::open(ips)?;
    let reader = BufReader::new(file);
    let mut ips: Vec<IpAddr> = Vec::new();

    for address_line in reader.lines() {
        if let Ok(address) = address_line {
            ips.extend(arwah_parse_address(&address, backup_resolver));
        } else {
            debug!("[ ETA ]: Line in file is not valid");
        }
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::{ArwahOpts, arwah_get_resolver, arwah_parse_addresses};
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_correct_addresses() {
        let opts = ArwahOpts { addresses: vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(192, 168, 0, 2), Ipv4Addr::new(192, 168, 0, 3)]);
    }

    #[test]
    fn test_parse_addresses_with_address_exclusions() {
        let opts = ArwahOpts { addresses: vec!["192.168.0.0/30".to_owned()], exclude_addresses: Some(vec!["192.168.0.1".to_owned()]), ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips, [Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(192, 168, 0, 2), Ipv4Addr::new(192, 168, 0, 3)]);
    }

    #[test]
    fn test_parse_addresses_with_cidr_exclusions() {
        let opts = ArwahOpts { addresses: vec!["192.168.0.0/29".to_owned()], exclude_addresses: Some(vec!["192.168.0.0/30".to_owned()]), ..Default::default() };
        let ips = arwah_parse_addresses(&opts);

        assert_eq!(ips, [Ipv4Addr::new(192, 168, 0, 4), Ipv4Addr::new(192, 168, 0, 5), Ipv4Addr::new(192, 168, 0, 6), Ipv4Addr::new(192, 168, 0, 7),]);
    }

    #[test]
    fn test_parse_addresses_with_incorrect_address_exclusions() {
        let opts = ArwahOpts { addresses: vec!["192.168.0.0/30".to_owned()], exclude_addresses: Some(vec!["192.168.0.1".to_owned()]), ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips, [Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(192, 168, 0, 2), Ipv4Addr::new(192, 168, 0, 3)]);
    }

    #[test]
    fn test_parse_correct_host_addresses() {
        let opts = ArwahOpts { addresses: vec!["google.com".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_parse_correct_and_incorrect_addresses() {
        let opts = ArwahOpts { addresses: vec!["127.0.0.1".to_owned(), "im_wrong".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1),]);
    }

    #[test]
    fn test_parse_incorrect_addresses() {
        let opts = ArwahOpts { addresses: vec!["im_wrong".to_owned(), "300.10.1.1".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_hosts_file_and_incorrect_hosts() {
        let opts = ArwahOpts { addresses: vec!["examples/hosts.txt".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn test_parse_empty_hosts_file() {
        let opts = ArwahOpts { addresses: vec!["examples/empty.txt".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn test_parse_naughty_host_file() {
        let opts = ArwahOpts { addresses: vec!["examples/naughty.txt".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn test_parse_duplicate_cidrs() {
        let opts = ArwahOpts { addresses: vec!["79.98.104.0/21".to_owned(), "79.98.104.0/24".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips.len(), 2_048);
    }

    #[test]
    fn parse_overspecific_cidr() {
        let opts = ArwahOpts { addresses: vec!["192.128.1.1/24".to_owned()], ..Default::default() };
        let ips = arwah_parse_addresses(&opts);
        assert_eq!(ips.len(), 256);
    }

    #[test]
    fn test_resolver_default_cloudflare() {
        let opts = ArwahOpts::default();
        let resolver = arwah_get_resolver(&opts.resolver);
        let lookup = resolver.lookup_ip("www.example.com.").unwrap();
        assert!(opts.resolver.is_none());
        assert!(lookup.iter().next().is_some());
    }

    #[test]
    fn test_resolver_args_google_dns() {
        let opts = ArwahOpts { resolver: Some("8.8.8.8,8.8.4.4".to_owned()), ..Default::default() };
        let resolver = arwah_get_resolver(&opts.resolver);
        let lookup = resolver.lookup_ip("www.example.com.").unwrap();
        assert!(lookup.iter().next().is_some());
    }
}
