use clap::ArgAction;
use clap_complete::Shell;

#[derive(Debug, clap::Parser)]
#[allow(clippy::struct_excessive_bools)]
pub struct ArwahArgs {
    #[arg(short = 'p', long = "promisc")]
    pub promisc: bool,

    #[arg(long = "debugging")]
    pub debugging: bool,

    #[arg(short = 'j', long = "json")]
    pub json: bool,
    #[arg(
        short = 'v',
        long = "verbose",
        action(ArgAction::Count),
        help = "Increase filter sensitivity to show more (possibly less useful) packets. The default only shows few packets, this flag can be specified multiple times. (maximum: 4)"
    )]
    pub verbose: u8,

    #[arg(short = 'r', long = "read")]
    pub read: bool,

    #[arg(short = 'n', long = "threads", alias = "cpus")]
    pub threads: Option<usize>,

    #[arg(long)]
    pub insecure_disable_seccomp: bool,

    #[arg(long, hide = true)]
    pub gen_completions: Option<Shell>,

    pub device: Option<String>,
}
