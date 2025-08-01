use crate::generated::get_parsed_data;
use crate::scanner::socket::ArwahSocket;
use crate::strategy::service::ArwahStrategy;
use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::{io, net::UdpSocket};
use colored::Colorize;
use futures::stream::FuturesUnordered;
use log::debug;
use std::collections::BTreeMap;
use std::{
    collections::HashSet,
    net::{IpAddr, Shutdown, SocketAddr},
    num::NonZeroU8,
    time::Duration,
};

#[cfg(not(tarpaulin_include))]
#[derive(Debug)]
pub struct ArwahScanner {
    ips: Vec<IpAddr>,
    batch_size: u16,
    timeout: Duration,
    tries: NonZeroU8,
    greppable: bool,
    strategy: ArwahStrategy,
    accessible: bool,
    exclude_ports: Vec<u16>,
    udp: bool,
}

#[allow(clippy::too_many_arguments)]
impl ArwahScanner {
    pub fn arwah_new(
        ips: &[IpAddr],
        batch_size: u16,
        timeout: Duration,
        tries: u8,
        greppable: bool,
        strategy: ArwahStrategy,
        accessible: bool,
        exclude_ports: Vec<u16>,
        udp: bool,
    ) -> Self {
        Self {
            batch_size,
            timeout,
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
            greppable,
            strategy,
            ips: ips.iter().map(ToOwned::to_owned).collect(),
            accessible,
            exclude_ports,
            udp,
        }
    }

    pub async fn arwah_run(&self) -> Vec<SocketAddr> {
        let ports: Vec<u16> = self
            .strategy
            .arwah_order()
            .iter()
            .filter(|&port| !self.exclude_ports.contains(port))
            .copied()
            .collect();
        let mut socket_iterator: ArwahSocket = ArwahSocket::arwah_new(&self.ips, &ports);
        let mut open_sockets: Vec<SocketAddr> = Vec::new();
        let mut ftrs = FuturesUnordered::new();
        let mut errors: HashSet<String> = HashSet::new();
        let udp_map = get_parsed_data();

        for _ in 0..=self.batch_size {
            if let Some(socket) = socket_iterator.next() {
                ftrs.push(self.arwah_scan_socket(socket, udp_map.clone()));
            } else {
                break;
            }
        }
        debug!(
            "[ ETA ]: Start scanning sockets. \nBatch size {}\nNumber of ip-s {}\nNumber of ports {}\nTargets all together {} ",
            self.batch_size,
            self.ips.len(),
            &ports.len(),
            (self.ips.len() * ports.len())
        );

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = socket_iterator.next() {
                ftrs.push(self.arwah_scan_socket(socket, udp_map.clone()));
            }

            match result {
                Ok(socket) => {
                    open_sockets.push(socket);
                }
                Err(e) => {
                    let error_string = e.to_string();

                    if errors.len() < self.ips.len() * 1000 {
                        errors.insert(error_string);
                    }
                }
            }
        }
        debug!("[ ETA ]: Typical socket connection errors {errors:?}");
        debug!("[ ETA ]: Open Sockets found: {:?}", &open_sockets);
        open_sockets
    }

    async fn arwah_scan_socket(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> io::Result<SocketAddr> {
        if self.udp {
            return self.arwah_scan_udp_scoket(socket, udp_map).await;
        }
        let tries = self.tries.get();

        for nr_try in 1..=tries {
            match self.arwah_connect(socket).await {
                Ok(tcp_stream) => {
                    debug!(
                        "[ ETA ]: Connection was successful, shutting down stream {}",
                        &socket
                    );

                    if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                        debug!("[ ETA ]: Shutdown stream error {}", &e);
                    }
                    self.arwah_fmt_ports(socket);
                    debug!("[ ETA ]: Return Ok after {nr_try} tries");
                    return Ok(socket);
                }
                Err(e) => {
                    let mut error_string = e.to_string();
                    assert!(
                        !error_string
                            .to_lowercase()
                            .contains("[ ETA ]: too many open files"),
                        "Too many open files. Please reduce batch size. The default is 5000. Try -b 2500."
                    );

                    if nr_try == tries {
                        error_string.push(' ');
                        error_string.push_str(&socket.ip().to_string());
                        return Err(io::Error::other(error_string));
                    }
                }
            };
        }
        unreachable!();
    }

    async fn arwah_scan_udp_scoket(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> io::Result<SocketAddr> {
        let mut payload: Vec<u8> = Vec::new();

        for (kv, vk) in udp_map {
            if kv.contains(&socket.port()) {
                payload = vk
            }
        }
        let tries = self.tries.get();

        for _ in 1..=tries {
            match self.arwah_udp_scan(socket, &payload, self.timeout).await {
                Ok(true) => {
                    return Ok(socket);
                }
                Ok(false) => {
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Err(io::Error::other(format!(
            "[ ETA ]: UDP scan timed-out for all tries on socket {socket}"
        )))
    }

    async fn arwah_connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        let stream = io::timeout(
            self.timeout,
            async move { TcpStream::connect(socket).await },
        )
        .await?;
        Ok(stream)
    }

    async fn arwah_udp_bind(&self, socket: SocketAddr) -> io::Result<UdpSocket> {
        let local_addr = match socket {
            SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().unwrap(),
        };
        UdpSocket::bind(local_addr).await
    }

    async fn arwah_udp_scan(
        &self,
        socket: SocketAddr,
        payload: &[u8],
        wait: Duration,
    ) -> io::Result<bool> {
        match self.arwah_udp_bind(socket).await {
            Ok(udp_socket) => {
                let mut buf = [0u8; 1024];
                udp_socket.connect(socket).await?;
                udp_socket.send(payload).await?;

                match io::timeout(wait, udp_socket.recv(&mut buf)).await {
                    Ok(size) => {
                        debug!("[ ETA ]: Received {size} bytes");
                        self.arwah_fmt_ports(socket);
                        Ok(true)
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            Ok(false)
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            Err(e) => {
                println!("[ ETA ]: Err E binding sock {e:?}");
                Err(e)
            }
        }
    }

    fn arwah_fmt_ports(&self, socket: SocketAddr) {
        if !self.greppable {
            if self.accessible {
                println!("[ ETA ]: Open {socket}");
            } else {
                println!("[ ETA ]: Open {}", socket.to_string().purple());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{ArwahPortRange, ArwahScanOrder};
    use async_std::task::block_on;
    use std::{net::IpAddr, time::Duration};

    #[test]
    fn scanner_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 1,
            end: 1000,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn ipv6_scanner_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["::1".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 1,
            end: 1000,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn quad_zero_scanner_runs() {
        let addrs = vec!["0.0.0.0".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 1,
            end: 1000,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn google_dns_runs() {
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 400,
            end: 445,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn infer_ulimit_lowering_no_panic() {
        // Test behaviour on MacOS where ulimit is not automatically lowered
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];

        // mac should have this automatically scaled down
        let range = ArwahPortRange {
            start: 400,
            end: 600,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }

    #[test]
    fn udp_scan_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 1,
            end: 1000,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_ipv6_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["::1".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 1,
            end: 1000,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_quad_zero_scanner_runs() {
        let addrs = vec!["0.0.0.0".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 1,
            end: 1000,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_google_dns_runs() {
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let range = ArwahPortRange {
            start: 100,
            end: 150,
        };
        let strategy = ArwahStrategy::arwah_pick(&Some(range), None, ArwahScanOrder::Random);
        let scanner = ArwahScanner::arwah_new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.arwah_run());
        assert_eq!(1, 1);
    }
}
