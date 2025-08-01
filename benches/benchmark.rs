use arwah::input::{ArwahOpts, ArwahPortRange, ArwahScanOrder};
use arwah::scanner::service::ArwahScanner;
use arwah::strategy::service::ArwahStrategy;
use async_std::task::block_on;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Duration;

fn arwah_portscan_tcp(scanner: &ArwahScanner) {
    let _scan_result = block_on(scanner.arwah_run());
}

fn arwah_portscan_udp(scanner: &ArwahScanner) {
    let _scan_result = block_on(scanner.arwah_run());
}

fn arwah_bench_address() {
    let _addrs = ["127.0.0.1".parse::<IpAddr>().unwrap()];
}

fn arwah_bench_port_strategy() {
    let range = ArwahPortRange {
        start: 1,
        end: 1_000,
    };
    let _strategy = ArwahStrategy::arwah_pick(&Some(range.clone()), None, ArwahScanOrder::Serial);
}

fn arwah_bench_address_parsing() {
    let opts = ArwahOpts {
        addresses: vec![
            "127.0.0.1".to_owned(),
            "10.2.0.1".to_owned(),
            "192.168.0.0/24".to_owned(),
        ],
        exclude_addresses: Some(vec![
            "10.0.0.0/8".to_owned(),
            "172.16.0.0/12".to_owned(),
            "192.168.0.0/16".to_owned(),
            "172.16.0.1".to_owned(),
        ]),
        ..Default::default()
    };
    let _ips = arwah::address::arwah_parse_addresses(&opts);
}

fn arwah_criterion_benchmark(c: &mut Criterion) {
    let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
    let range = ArwahPortRange {
        start: 1,
        end: 1_000,
    };
    let strategy_tcp =
        ArwahStrategy::arwah_pick(&Some(range.clone()), None, ArwahScanOrder::Serial);
    let strategy_udp =
        ArwahStrategy::arwah_pick(&Some(range.clone()), None, ArwahScanOrder::Serial);
    let scanner_tcp = ArwahScanner::arwah_new(
        &addrs,
        10,
        Duration::from_millis(10),
        1,
        false,
        strategy_tcp,
        true,
        vec![],
        false,
    );

    c.bench_function("portscan tcp", |b| {
        b.iter(|| arwah_portscan_tcp(black_box(&scanner_tcp)))
    });

    let scanner_udp = ArwahScanner::arwah_new(
        &addrs,
        10,
        Duration::from_millis(10),
        1,
        false,
        strategy_udp,
        true,
        vec![],
        true,
    );

    let mut udp_group = c.benchmark_group("portscan udp");
    udp_group.measurement_time(Duration::from_secs(20));
    udp_group.bench_function("portscan udp", |b| {
        b.iter(|| arwah_portscan_udp(black_box(&scanner_udp)))
    });
    udp_group.finish();
    c.bench_function("parse address", |b| b.iter(arwah_bench_address));
    c.bench_function("port strategy", |b| b.iter(arwah_bench_port_strategy));
    let mut address_group = c.benchmark_group("address parsing");
    address_group.measurement_time(Duration::from_secs(10));
    address_group.bench_function("parse addresses with exclusions", |b| {
        b.iter(|| arwah_bench_address_parsing())
    });
    address_group.finish();
}

criterion_group!(benches, arwah_criterion_benchmark);
criterion_main!(benches);
