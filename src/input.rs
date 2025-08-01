use clap::{Parser, ValueEnum};
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

const ARW_LOWEST_PORT_NUMBER: u16 = 1;
const ARW_TOP_PORT_NUMBER: u16 = 65535;

#[derive(Deserialize, Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ArwahScanOrder {
    Serial,
    Random,
}

#[derive(Deserialize, Debug, ValueEnum, Clone, PartialEq, Eq, Copy)]
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

#[cfg(not(tarpaulin_include))]
fn arwah_parse_range(input: &str) -> Result<ArwahPortRange, String> {
    let range = input
        .split('-')
        .map(str::parse)
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from(
            "[ ETA ]: the range format must be 'start-end'. Example: 1-1000.",
        ));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(ArwahPortRange {
            start: *start,
            end: *end,
        }),
        _ => Err(String::from(
            "[ ETA ]: the range format must be 'start-end'. Example: 1-1000.",
        )),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "arwah", version = env!("CARGO_PKG_VERSION"), max_term_width = 120, help_template = "{bin} {version}\n{about}\n\nUSAGE:\n    {usage}\n\nOPTIONS:\n{options}")]
#[allow(clippy::struct_excessive_bools)]
pub struct ArwahOpts {
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,

    #[arg(short, long, value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    #[arg(short, long, conflicts_with = "ports", value_parser = arwah_parse_range)]
    pub range: Option<ArwahPortRange>,

    #[arg(short, long)]
    pub no_config: bool,

    #[arg(long)]
    pub no_banner: bool,

    #[arg(short, long, value_parser)]
    pub config_path: Option<PathBuf>,

    #[arg(short, long)]
    pub greppable: bool,

    #[arg(long)]
    pub accessible: bool,

    #[arg(long)]
    pub resolver: Option<String>,

    #[arg(short, long, default_value = "4500")]
    pub batch_size: u16,

    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    #[arg(long, default_value = "1")]
    pub tries: u8,

    #[arg(short, long)]
    pub ulimit: Option<u64>,

    #[arg(long, value_enum, ignore_case = true, default_value = "serial")]
    pub scan_order: ArwahScanOrder,

    #[arg(long, value_enum, ignore_case = true, default_value = "default")]
    pub scripts: ArwahScriptsRequired,

    #[arg(long)]
    pub top: bool,

    #[arg(last = true)]
    pub command: Vec<String>,

    #[arg(short, long, value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',')]
    pub exclude_addresses: Option<Vec<String>>,

    #[arg(long)]
    pub udp: bool,
}

#[cfg(not(tarpaulin_include))]
#[derive(Debug, Deserialize)]
pub struct ArwahConfig {
    addresses: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    range: Option<ArwahPortRange>,
    greppable: Option<bool>,
    accessible: Option<bool>,
    batch_size: Option<u16>,
    timeout: Option<u32>,
    tries: Option<u8>,
    ulimit: Option<u64>,
    resolver: Option<String>,
    scan_order: Option<ArwahScanOrder>,
    command: Option<Vec<String>>,
    scripts: Option<ArwahScriptsRequired>,
    exclude_ports: Option<Vec<u16>>,
    exclude_addresses: Option<Vec<String>>,
    udp: Option<bool>,
}

#[cfg(not(tarpaulin_include))]
impl ArwahOpts {
    pub fn arwah_read() -> Self {
        let mut opts = ArwahOpts::parse();

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(ArwahPortRange {
                start: ARW_LOWEST_PORT_NUMBER,
                end: ARW_TOP_PORT_NUMBER,
            });
        }

        opts
    }

    pub fn arwah_merge(&mut self, config: &ArwahConfig) {
        if !self.no_config {
            self.arwah_merge_required(config);
            self.arwah_merge_optional(config);
        }
    }

    fn arwah_merge_required(&mut self, config: &ArwahConfig) {
        macro_rules! arwah_merge_required {
            ($($field: ident),+) => {
                $(
                    if let Some(e) = &config.$field {
                        self.$field = e.clone();
                    }
                )+
            }
        }
        arwah_merge_required!(
            addresses, greppable, accessible, batch_size, timeout, tries, scan_order, scripts,
            command, udp
        );
    }

    fn arwah_merge_optional(&mut self, config: &ArwahConfig) {
        macro_rules! arwah_merge_optional {
            ($($field: ident),+) => {
                $(
                    if config.$field.is_some() {
                        self.$field = config.$field.clone();
                    }
                )+
            }
        }

        if self.top && config.ports.is_some() {
            self.ports = config.ports.clone();
        }
        arwah_merge_optional!(range, resolver, ulimit, exclude_ports, exclude_addresses);
    }
}

impl Default for ArwahOpts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
            range: None,
            greppable: true,
            batch_size: 0,
            timeout: 0,
            tries: 0,
            ulimit: None,
            command: vec![],
            accessible: false,
            resolver: None,
            scan_order: ArwahScanOrder::Serial,
            no_config: true,
            no_banner: false,
            top: false,
            scripts: ArwahScriptsRequired::Default,
            config_path: None,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
        }
    }
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::doc_link_with_quotes)]
#[allow(clippy::manual_unwrap_or_default)]
impl ArwahConfig {
    pub fn arwah_read(custom_config_path: Option<PathBuf>) -> Self {
        let mut content = String::new();
        let config_path = custom_config_path.unwrap_or_else(arwah_default_config_path);
        if config_path.exists() {
            content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(_) => String::new(),
            }
        }

        let config: ArwahConfig = match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                println!("Found {e} in configuration file.\nAborting scan.\n");
                std::process::exit(1);
            }
        };

        config
    }
}

pub fn arwah_default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::home_dir() else {
        panic!("[ ETA ]: Could not infer config file path.");
    };
    config_path.push(".arwah.toml");
    config_path
}

#[cfg(test)]
mod tests {
    use super::{ArwahConfig, ArwahOpts, ArwahPortRange, ArwahScanOrder, ArwahScriptsRequired};
    use clap::{CommandFactory, Parser};
    use parameterized::parameterized;

    impl ArwahConfig {
        fn default() -> Self {
            Self {
                addresses: Some(vec!["127.0.0.1".to_owned()]),
                ports: None,
                range: None,
                greppable: Some(true),
                batch_size: Some(25_000),
                timeout: Some(1_000),
                tries: Some(1),
                ulimit: None,
                command: Some(vec!["-A".to_owned()]),
                accessible: Some(true),
                resolver: None,
                scan_order: Some(ArwahScanOrder::Random),
                scripts: None,
                exclude_ports: None,
                exclude_addresses: None,
                udp: Some(false),
            }
        }
    }

    #[test]
    fn verify_cli() {
        ArwahOpts::command().debug_assert();
    }

    #[parameterized(input = {
        vec!["arwah", "--addresses", "127.0.0.1"],
        vec!["arwah", "--addresses", "127.0.0.1", "--", "-sCV"],
        vec!["arwah", "--addresses", "127.0.0.1", "--", "-A"],
        vec!["arwah", "-t", "1500", "-a", "127.0.0.1", "--", "-A", "-sC"],
        vec!["arwah", "--addresses", "127.0.0.1", "--", "--script", r#""'(safe and vuln)'""#],
    }, command = {
        vec![],
        vec!["-sCV".to_owned()],
        vec!["-A".to_owned()],
        vec!["-A".to_owned(), "-sC".to_owned()],
        vec!["--script".to_owned(), "\"'(safe and vuln)'\"".to_owned()],
    })]
    fn parse_trailing_command(input: Vec<&str>, command: Vec<String>) {
        let opts = ArwahOpts::parse_from(input);
        assert_eq!(vec!["127.0.0.1".to_owned()], opts.addresses);
        assert_eq!(command, opts.command);
    }

    #[test]
    fn opts_no_merge_when_config_is_ignored() {
        let mut opts = ArwahOpts::default();
        let config = ArwahConfig::default();

        opts.arwah_merge(&config);

        assert_eq!(opts.addresses, vec![] as Vec<String>);
        assert!(opts.greppable);
        assert!(!opts.accessible);
        assert_eq!(opts.timeout, 0);
        assert_eq!(opts.command, vec![] as Vec<String>);
        assert_eq!(opts.scan_order, ArwahScanOrder::Serial);
    }

    #[test]
    fn opts_merge_required_arguments() {
        let mut opts = ArwahOpts::default();
        let config = ArwahConfig::default();

        opts.arwah_merge_required(&config);

        assert_eq!(opts.addresses, config.addresses.unwrap());
        assert_eq!(opts.greppable, config.greppable.unwrap());
        assert_eq!(opts.timeout, config.timeout.unwrap());
        assert_eq!(opts.command, config.command.unwrap());
        assert_eq!(opts.accessible, config.accessible.unwrap());
        assert_eq!(opts.scan_order, config.scan_order.unwrap());
        assert_eq!(opts.scripts, ArwahScriptsRequired::Default);
    }

    #[test]
    fn opts_merge_optional_arguments() {
        let mut opts = ArwahOpts::default();
        let mut config = ArwahConfig::default();
        config.range = Some(ArwahPortRange {
            start: 1,
            end: 1_000,
        });
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.arwah_merge_optional(&config);

        assert_eq!(opts.range, config.range);
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }
}
