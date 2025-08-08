use anyhow::{Context, Error, Result, anyhow, bail};
use data_encoding::BASE64;
use log::{debug, info, warn};
use std::env;

fn main() -> Result<()> {
    env_logger::init();

    for arg in env::args().skip(1) {
        let bytes = BASE64.decode(arg.as_bytes()).context("Failed to base64 decode")?;
        println!("{:?}", bytes);
        let packet = arwah::centrifuge::service::arwah_parse_eth(&bytes);
        println!("{:?}", packet);
    }
    Ok(())
}
