#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use anyhow::{Context, Result};
use colorful::{Color, Colorful};

use futures::executor::block_on;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{self, IsTerminal};
use std::net::IpAddr;
use std::string::ToString;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use arwah::address::arwah_parse_addresses;
use arwah::benchmark::benchmark::{ArwahBenchmark, ArwahNamedTimer};
use arwah::centrifuge;

use arwah::fmt as ArwahFmt;
use arwah::input::{self, ArwahConfig, ArwahOpts, ArwahScriptsRequired};
use arwah::link::ArwahDataLink;
use arwah::sandbox;
use arwah::scanner::service::ArwahScanner;
use arwah::scripts::service::{ArwahScript, ArwahScriptFile, arwah_init_scripts};
use arwah::sniff;
use arwah::strategy::service::ArwahStrategy;
use arwah::{detail, opening, output, warning};

extern crate colorful;
extern crate dirs;

#[cfg(unix)]
const ARWAH_DEFAULT_FILE_DESCRIPTORS_LIMIT: u64 = 8000;
const ARWAH_AVERAGE_BATCH_SIZE: u16 = 3000;

extern crate log;

#[allow(clippy::items_after_statements, clippy::needless_raw_string_hashes)]
fn arwah_opening(opts: &ArwahOpts) {
    debug!("Printing opening");
    let s = r#"
    
                         ¶          ¶
                         ¶          ¶
                     ¶   ¶          ¶    ¶
                     ¶  ¶¶         ¶¶   ¶
                    ¶¶  ¶¶¶       ¶¶¶  ¶¶
             ¶      ¶¶   ¶¶¶     ¶¶¶   ¶¶         ¶
            ¶¶      ¶¶   ¶¶¶     ¶¶¶    ¶¶       ¶¶
            ¶¶      ¶¶    ¶¶¶¶   ¶¶¶¶    ¶¶      ¶¶
            ¶¶     ¶¶¶    ¶¶¶¶  ¶¶¶¶¶    ¶¶¶    ¶¶¶
        ¶  ¶¶¶    ¶¶¶¶    ¶¶¶¶   ¶¶¶¶    ¶¶¶¶  ¶¶¶¶   ¶
       ¶¶ ¶¶¶¶¶  ¶¶¶¶   ¶¶¶¶¶   ¶¶¶¶¶   ¶¶¶¶  ¶¶¶¶¶   ¶¶
       ¶¶ ¶¶¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶     ¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶¶¶   ¶¶
       ¶¶ ¶¶¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶     ¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶¶¶   ¶¶
      ¶¶¶  ¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶    ¶¶¶
     ¶¶¶¶  ¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶    ¶¶¶¶
     ¶¶¶¶   ¶¶¶¶¶ ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶ ¶¶¶¶¶   ¶¶¶¶
     ¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶
    ¶¶¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶¶
    ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
    ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
     ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
    ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
     ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
    ¶¶¶¶¶          ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶            ¶¶¶¶¶
    ¶¶¶¶¶¶           ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶              ¶¶¶¶¶¶
     ¶¶¶¶¶¶¶           ¶¶¶¶¶¶¶¶¶¶¶              ¶¶¶¶¶¶
      ¶¶¶¶¶¶¶¶           ¶¶¶¶¶¶¶             ¶¶¶¶¶¶¶¶
        ¶¶¶¶¶¶¶¶¶¶         ¶¶¶¶           ¶¶¶¶¶¶¶¶¶¶
        ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
            ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
                ¶¶¶¶¶¶¶¶¶¶      ¶¶¶¶¶¶¶¶¶¶
                 ¶¶¶¶¶¶¶¶       ¶¶¶¶¶¶¶¶
                ¶¶¶¶¶¶¶¶¶       ¶¶¶¶¶¶¶¶¶
                  ¶¶¶¶¶¶¶ ¶¶¶¶¶ ¶¶¶¶¶¶¶¶¶
                ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
                ¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶
                 ¶¶  ¶¶¶¶  ¶¶¶¶¶  ¶¶¶¶  ¶¶
                     ¶¶¶¶  ¶¶¶¶¶  ¶¶¶¶
                     

                                                   mm        
      @@                                           @@@        
     m@@m                                          @@        
    m@*@@!    *@@@m@@@ *@@*    m@    *@@* m@*@@m   @@@@@@@m  
   m@  *@@      @@* **   @@   m@@@   m@  @@   @@   @@    @@  
   @@@!@!@@     @!        @@ m@  @@ m@    m@@@!@   @@    @!  
  !*      @@    @!         @@@    @!!    @!   !@   @!    @!  
   !!!!@!!@     !!         !@!!   !:!     !!!!:!   !!    !!  
  !*      !!    !:         !!!    !:!    !!   :!   !:    !:  
: : :   : ::: : :::         :      :     :!: : !: : :   : : :
                                                             
"#;
    println!("{}", s.gradient(Color::Green).bold());
    let info = r#"
          ________________________________________
          :           Tawheed Network!           :
          :            Free Palestine!           :
          ----------------------------------------
             
             "#;
    println!("{}", info.gradient(Color::Yellow).bold());
    opening!();
    let config_path = opts.config_path.clone().unwrap_or_else(input::arwah_default_config_path);
    detail!(format!("The config file is expected to be at {config_path:?}"), opts.greppable, opts.accessible);
}

fn arwah_adjust_ulimit_size(opts: &ArwahOpts) -> u64 {
    use rlimit::Resource;

    if let Some(limit) = opts.ulimit {
        if Resource::NOFILE.set(limit, limit).is_ok() {
            detail!(format!("Automatically increasing ulimit value to {limit}."), opts.greppable, opts.accessible);
        } else {
            warning!("ERROR. Failed to set ulimit value.", opts.greppable, opts.accessible);
        }
    }
    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft
}

#[cfg(unix)]
fn arwah_inter_batch_size(opts: &ArwahOpts, ulimit: u64) -> u16 {
    let mut batch_size: u64 = opts.batch_size.into();

    if ulimit < batch_size {
        warning!("[ ETA ]: File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers", opts.greppable, opts.accessible);

        if ulimit < ARWAH_AVERAGE_BATCH_SIZE.into() {
            warning!(
                "[ ETA ]: Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. ",
                opts.greppable,
                opts.accessible
            );
            info!("[ ETA ]: Halving batch_size because ulimit is smaller than average batch size");
            batch_size = ulimit / 2;
        } else if ulimit > ARWAH_DEFAULT_FILE_DESCRIPTORS_LIMIT {
            info!("Batch size is now average batch size");
            batch_size = ARWAH_AVERAGE_BATCH_SIZE.into();
        } else {
            batch_size = ulimit - 100;
        }
    } else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        detail!(format!("[ ETA ]: File limit higher than batch size. Can increase speed by increasing batch size '-b {}'.", ulimit - 100), opts.greppable, opts.accessible);
    }
    batch_size.try_into().expect("[ ETA ]: Couldn't fit the batch size into a u16.")
}

fn arwah_sniffer(opts: &ArwahOpts) -> Result<()> {
    // Use default settings for sniffing mode
    let promisc = false;
    let debugging = false;
    let json = false;
    let verbose = 1;
    let read = false;
    let threads_count = num_cpus::get();
    let insecure_disable_seccomp = false;

    sandbox::service::arwah_activate_stage_o(insecure_disable_seccomp).context("[ ETA ]: Failed to init sandbox stage o")?;

    let device = sniff::arwah_default_interface().context("[ ETA ]: Failed to get default interface")?;

    let layout = if json {
        ArwahFmt::ArwahLayout::Json
    } else if debugging {
        ArwahFmt::ArwahLayout::Debugging
    } else {
        ArwahFmt::ArwahLayout::Compact
    };

    let colors = io::stdout().is_terminal();
    let fmt_config = ArwahFmt::ArwahConfig::arwah_new(layout, verbose, colors);

    let cap = if read {
        let cap = sniff::arwah_open_file(&device)?;
        eprintln!("[ ETA ]: Reading from file: {device:?}");
        cap
    } else {
        let cap = sniff::arwah_open(&device, &sniff::ArwahConfig { promisc, immediate_mode: true })?;

        let verbosity = fmt_config.arwah_filter().verbosity;
        eprintln!("[ ETA ]: Listening on device: {device:?}, verbosity {verbosity}/4");
        cap
    };

    debug!("[ ETA ]: Using {threads_count} threads");
    if !opts.greppable && !opts.accessible && !opts.no_banner {
        arwah_opening(&opts);
    }
    let datalink = ArwahDataLink::arwah_from_linktype(cap.arwah_datalink())?;
    let filter = fmt_config.arwah_filter();
    let (tx, rx) = mpsc::sync_channel(256);
    let cap = Arc::new(Mutex::new(cap));
    sandbox::service::arwah_activate_stage_t(insecure_disable_seccomp).context("[ ETA ]: Failed to init sandbox stage2")?;

    for _ in 0..threads_count {
        let cap = cap.clone();
        let datalink = datalink.clone();
        let filter = filter.clone();
        let tx = tx.clone();
        thread::spawn(move || {
            loop {
                let packet = {
                    let mut cap = cap.lock().unwrap();
                    cap.arwah_next_pkt()
                };

                if let Ok(Some(packet)) = packet {
                    let packet = centrifuge::service::arwah_parse(&datalink, &packet.data);
                    if filter.arwah_matches(&packet) {
                        if tx.send(packet).is_err() {
                            break;
                        }
                    }
                } else {
                    debug!("[ ETA ]: End of packet stream, shutting down reader thread");
                    break;
                }
            }
        });
    }
    drop(tx);
    let format = fmt_config.arwah_format();
    for packet in rx.iter() {
        format.arwah_print(packet);
    }
    Ok(())
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    #[cfg(not(unix))]
    let _ = ansi_term::enable_ansi_support();

    env_logger::init();
    let mut opts: ArwahOpts = ArwahOpts::arwah_read();
    let config = ArwahConfig::arwah_read(opts.config_path.clone());
    opts.arwah_merge(&config);
    debug!("[ ETA ]: Main() `opts` arguments are {opts:?}");

    // Determine operation mode based on flags
    match (opts.scan, opts.sniff) {
        (true, true) => {
            // Both scanning and sniffing requested
            arwah_scan_mode(&opts)?;
            println!("\n[ ETA ]: Scanning completed. Starting packet sniffing...");
            arwah_sniffer(&opts)?;
        }
        (true, false) => {
            // Only scanning
            arwah_scan_mode(&opts)?;
        }
        (false, true) => {
            // Only sniffing
            arwah_sniffer(&opts)?;
        }
        (false, false) => {
            // Default mode - scanning (preserve original behavior)
            arwah_scan_mode(&opts)?;
        }
    }
    Ok(())
}

fn arwah_scan_mode(opts: &ArwahOpts) -> Result<()> {
    let mut benchmarks = ArwahBenchmark::arwah_init();
    let mut arwah_bench = ArwahNamedTimer::arwah_start("RustScan");

    let scripts_to_run: Vec<ArwahScriptFile> = match arwah_init_scripts(&opts.scripts) {
        Ok(scripts_to_run) => scripts_to_run,
        Err(e) => {
            warning!(format!("[ ETA ]: Initiating scripts failed!\n{e}"), opts.greppable, opts.accessible);
            std::process::exit(1);
        }
    };
    debug!("[ ETA ]: Scripts initialized {:?}", &scripts_to_run);

    if !opts.greppable && !opts.accessible && !opts.no_banner {
        arwah_opening(&opts);
    }
    let ips: Vec<IpAddr> = arwah_parse_addresses(&opts);

    if ips.is_empty() {
        warning!("No IPs could be resolved, aborting scan.", opts.greppable, opts.accessible);
        std::process::exit(1);
    }

    #[cfg(unix)]
    let batch_size: u16 = arwah_inter_batch_size(&opts, arwah_adjust_ulimit_size(&opts));

    #[cfg(not(unix))]
    let batch_size: u16 = ARWAH_AVERAGE_BATCH_SIZE;

    let scanner = ArwahScanner::arwah_new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        ArwahStrategy::arwah_pick(&opts.range, opts.ports.clone(), opts.scan_order),
        opts.accessible,
        opts.exclude_ports.clone().unwrap_or_default(),
        opts.udp,
    );
    debug!("Scanner finished building: {scanner:?}");
    let portscan_bench = ArwahNamedTimer::arwah_start("Portscan");
    let scan_result = block_on(scanner.arwah_run());
    arwah_bench.arwah_end();
    benchmarks.arwah_push(portscan_bench);
    let mut ports_per_ip = HashMap::new();

    for socket in scan_result {
        ports_per_ip.entry(socket.ip()).or_insert_with(Vec::new).push(socket.port());
    }

    for ip in ips {
        if ports_per_ip.contains_key(&ip) {
            continue;
        }
        let x = format!(
            "Looks like I didn't find any open ports for {:?}. This is usually caused by a high batch size.
        \n*I used {} batch size, consider lowering it with {} or a comfortable number for your system.
        \n Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.\n",
            ip, opts.batch_size, "'arwah -b <batch_size> -a <ip address>'"
        );
        warning!(x, opts.greppable, opts.accessible);
    }

    let mut script_bench = ArwahNamedTimer::arwah_start("Scripts");
    for (ip, ports) in &ports_per_ip {
        let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();
        let ports_str = vec_str_ports.join(",");

        if opts.greppable || opts.scripts == ArwahScriptsRequired::None {
            println!("{} -> [{}]", &ip, ports_str);
            continue;
        }
        detail!("Starting Script(s)", opts.greppable, opts.accessible);

        for mut script_f in scripts_to_run.clone() {
            if !opts.command.is_empty() {
                let user_extra_args = &opts.command.join(" ");
                debug!("Extra args vec {user_extra_args:?}");
                if script_f.call_format.is_some() {
                    let mut call_f = script_f.call_format.unwrap();
                    call_f.push(' ');
                    call_f.push_str(user_extra_args);
                    output!(format!("Running script {:?} on ip {}\nDepending on the complexity of the script, results may take some time to appear.", call_f, &ip), opts.greppable, opts.accessible);
                    debug!("Call format {call_f}");
                    script_f.call_format = Some(call_f);
                }
            }
            let script = ArwahScript::arwah_build(script_f.path, *ip, ports.clone(), script_f.port, script_f.ports_separator, script_f.tags, script_f.call_format);

            match script.arwah_run() {
                Ok(script_result) => {
                    detail!(script_result.to_string(), opts.greppable, opts.accessible);
                }
                Err(e) => {
                    warning!(&format!("Error {e}"), opts.greppable, opts.accessible);
                }
            }
        }
    }
    script_bench.arwah_end();
    benchmarks.arwah_push(script_bench);
    arwah_bench.arwah_end();
    benchmarks.arwah_push(arwah_bench);
    debug!("[ ETA ]: Benchmarks raw {benchmarks:?}");
    info!("[ ETA ]: {}", benchmarks.arwah_summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ArwahOpts, arwah_opening};
    #[cfg(unix)]
    use super::{arwah_adjust_ulimit_size, arwah_inter_batch_size};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let opts = ArwahOpts { batch_size: 50_000, ..Default::default() };
        let batch_size = arwah_inter_batch_size(&opts, 120);
        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let opts = ArwahOpts { batch_size: 50_000, ..Default::default() };
        let batch_size = arwah_inter_batch_size(&opts, 9_000);
        assert!(batch_size == 3_000);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        let opts = ArwahOpts { batch_size: 50_000, ..Default::default() };
        let batch_size = arwah_inter_batch_size(&opts, 5_000);
        assert!(batch_size == 4_900);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        let opts = ArwahOpts { batch_size: 50_000, ulimit: Some(2_000), ..Default::default() };
        let batch_size = arwah_adjust_ulimit_size(&opts);
        assert!(batch_size == 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit_no_greppable_mode() {
        let opts = ArwahOpts { batch_size: 10, greppable: false, ..Default::default() };
        let batch_size = arwah_inter_batch_size(&opts, 1_000_000);
        assert!(batch_size == opts.batch_size);
    }

    #[test]
    fn test_print_opening_no_panic() {
        let opts = ArwahOpts { ulimit: Some(2_000), ..Default::default() };
        arwah_opening(&opts);
    }
}
