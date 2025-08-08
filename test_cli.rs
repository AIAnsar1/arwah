use arwah::input::ArwahOpts;
use clap::Parser;

fn main() {
    let opts = ArwahOpts::parse();
    println!("Parsed successfully: {:?}", opts);
}