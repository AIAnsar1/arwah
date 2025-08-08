use clap::{ArgAction, Parser};
use clap_complete::Shell;
use serde_derive::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Debug, clap::ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ArwahScanOrder {
    Serial,
    Random,
}

#[derive(Deserialize, Debug, clap::ValueEnum, Clone, PartialEq, Eq, Copy)]
pub enum ArwahScriptsRequired {
    None,
    Default,
    Custom,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ArwahPortRange {
    pub start: u16,
    pub end: u16,
}

const ARW_LOWEST_PORT_NUMBER: u16 = 1;
const ARW_TOP_PORT_NUMBER: u16 = 65535;

#[cfg(not(tarpaulin_include))]
fn arwah_parse_range(input: &str) -> Result<ArwahPortRange, String> {
    let range = input.split('-').map(str::parse).collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from("[ ETA ]: the range format must be 'start-end'. Example: 1-1000."));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(ArwahPortRange { start: *start, end: *end }),
        _ => Err(String::from("[ ETA ]: the range format must be 'start-end'. Example: 1-1000.")),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "arwah", 
    version = env!("CARGO_PKG_VERSION"), 
    max_term_width = 120, 
    about = "Fast network scanner and packet sniffer - combines RustScan and Sniffglue functionality",
    help_template = "{bin} {version}\n{about}\n\nUSAGE:\n    {usage}\n\nSCANNING OPTIONS:\n{scanning}\n\nSNIFFING OPTIONS:\n{sniffing}\n\nOTHER OPTIONS:\n{options}"
)]
#[allow(clippy::struct_excessive_bools)]
pub struct ArwahUnifiedCli {
    // === SCANNING OPTIONS (from RustScan) ===
    #[arg(short, long, value_delimiter = ',', help = "IP addresses to scan")]
    pub addresses: Vec<String>,

    #[arg(short, long, value_delimiter = ',', help = "Specific ports to scan")]
    pub ports: Option<Vec<u16>>,

    #[arg(long, conflicts_with = "ports", value_parser = arwah_parse_range, help = "Port range to scan (e.g., 1-1000)")]
    pub range: Option<ArwahPortRange>,

    #[arg(short, long, help = "Disable configuration file")]
    pub no_config: bool,

    #[arg(long, help = "Disable banner")]
    pub no_banner: bool,

    #[arg(short, long, value_parser, help = "Custom config file path")]
    pub config_path: Option<PathBuf>,

    #[arg(short, long, help = "Greppable output")]
    pub greppable: bool,

    #[arg(long, help = "Accessible output")]
    pub accessible: bool,

    #[arg(long, help = "DNS resolver")]
    pub resolver: Option<String>,

    #[arg(short, long, default_value = "4500", help = "Batch size for scanning")]
    pub batch_size: u16,

    #[arg(short, long, default_value = "1500", help = "Timeout in milliseconds")]
    pub timeout: u32,

    #[arg(long, default_value = "1", help = "Number of tries")]
    pub tries: u8,

    #[arg(short, long, help = "Set ulimit")]
    pub ulimit: Option<u64>,

    #[arg(long, value_enum, ignore_case = true, default_value = "serial", help = "Scan order")]
    pub scan_order: ArwahScanOrder,

    #[arg(long, value_enum, ignore_case = true, default_value = "default", help = "Script execution")]
    pub scripts: ArwahScriptsRequired,

    #[arg(long, help = "Use top ports")]
    pub top: bool,

    #[arg(last = true, help = "Additional commands")]
    pub command: Vec<String>,

    #[arg(short, long, value_delimiter = ',', help = "Exclude specific ports")]
    pub exclude_ports: Option<Vec<u16>>,

    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',', help = "Exclude specific addresses")]
    pub exclude_addresses: Option<Vec<String>>,

    #[arg(long, help = "UDP scan")]
    pub udp: bool,

    // === SNIFFING OPTIONS (from Sniffglue) ===
    #[arg(long = "promisc", help = "Enable promiscuous mode")]
    pub promisc: bool,

    #[arg(long = "debugging", help = "Enable debugging output")]
    pub debugging: bool,

    #[arg(short = 'j', long = "json", help = "JSON output format")]
    pub json: bool,

    #[arg(long = "verbose", action(ArgAction::Count), help = "Increase filter sensitivity to show more packets (can be used multiple times, max: 4)")]
    pub verbose: u8,

    #[arg(long = "read", help = "Read from pcap file")]
    pub read: bool,

    #[arg(long = "sniff-threads", alias = "cpus", help = "Number of threads for packet processing")]
    pub sniff_threads: Option<usize>,

    #[arg(long, help = "Disable seccomp sandbox")]
    pub insecure_disable_seccomp: bool,

    #[arg(long, hide = true, help = "Generate shell completions")]
    pub gen_completions: Option<Shell>,

    #[arg(help = "Network device or pcap file")]
    pub device: Option<String>,

    // === UNIFIED OPTIONS ===
    #[arg(long, help = "Enable packet sniffing after scanning")]
    pub sniff: bool,
}

impl Default for ArwahUnifiedCli {
    fn default() -> Self {
        Self {
            // Scanning defaults
            addresses: vec![],
            ports: None,
            range: None,
            greppable: false,
            batch_size: 4500,
            timeout: 1500,
            tries: 1,
            ulimit: None,
            command: vec![],
            accessible: false,
            resolver: None,
            scan_order: ArwahScanOrder::Serial,
            no_config: false,
            no_banner: false,
            top: false,
            scripts: ArwahScriptsRequired::Default,
            config_path: None,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,

            // Sniffing defaults
            promisc: false,
            debugging: false,
            json: false,
            verbose: 1,
            read: false,
            sniff_threads: None,
            insecure_disable_seccomp: false,
            gen_completions: None,
            device: None,

            // Unified defaults
            sniff: false,
        }
    }
}

impl ArwahUnifiedCli {
    pub fn arwah_read() -> Self {
        let mut opts = ArwahUnifiedCli::parse();

        // Initialize default port range if no ports specified
        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(ArwahPortRange { start: ARW_LOWEST_PORT_NUMBER, end: ARW_TOP_PORT_NUMBER });
        }

        opts
    }

    pub fn has_scan_options(&self) -> bool {
        // Scanning is explicitly requested if we have addresses to scan
        !self.addresses.is_empty()
    }

    pub fn has_sniff_options(&self) -> bool {
        // Sniffing is requested if any sniffing-specific flags are used
        self.sniff || self.read || self.device.is_some() || self.promisc || self.json || self.debugging || self.verbose > 1 || self.sniff_threads.is_some()
    }

    pub fn should_default_to_scan(&self) -> bool {
        // Default to scanning if addresses are provided but no sniffing flags
        !self.addresses.is_empty() && !self.has_explicit_sniff_flags()
    }

    pub fn has_explicit_sniff_flags(&self) -> bool {
        // Check for explicit sniffing flags (excluding --sniff which is for combined mode)
        self.read || self.promisc || self.json || self.debugging || self.verbose > 1 || self.sniff_threads.is_some()
    }
}
