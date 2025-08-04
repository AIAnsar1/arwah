use serde::Deserialize;
use std::fs;
use std::path::Path;

pub use anyhow::{Context, Error, Result, anyhow, bail};
pub use log::{debug, info, warn};

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct ArwahSandboxConfig {
    pub user: Option<String>,
    pub chroot: Option<String>,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct ArwahConfig {
    pub sandbox: ArwahSandboxConfig,
}

pub fn arwah_find() -> Option<String> {
    let mut paths = vec![String::from("/etc/sniffglue.conf"), String::from("/usr/local/etc/sniffglue.conf")];

    if let Some(home) = dirs_next::config_dir() {
        let path = home.join(Path::new("sniffglue.conf"));

        if let Some(path) = path.to_str() {
            paths.push(path.into());
        }
    };
    paths.into_iter().find(|p| Path::new(&p).exists())
}

pub fn arwah_load(path: &str) -> Result<ArwahConfig> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let config: ArwahConfig = toml::from_str(r#" [sandbox] user = "foo" hroot = "/var/empty" "#).unwrap();

        assert_eq!(ArwahConfig { sandbox: ArwahSandboxConfig { user: Some(String::from("foo")), chroot: Some(String::from("/var/empty")) } }, config);
    }
}
