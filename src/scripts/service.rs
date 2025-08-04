#![allow(clippy::module_name_repetitions)]
use crate::input::ArwahScriptsRequired;
use anyhow::{Result, anyhow};

use log::debug;
use serde_derive::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::string::ToString;
use text_placeholder::Template;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

static DEFAULT: &str = r#"tags = ["core_approved", "Arwah", "default"]
developer = [ "Arwah", "" ]
ports_separator = ","
call_format = "nmap -vvv -p {{port}} -{{ipversion}} {{ip}}"
"#;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ArwahScript {
    path: Option<PathBuf>,

    ip: IpAddr,

    open_ports: Vec<u16>,

    trigger_port: Option<String>,

    ports_separator: Option<String>,

    tags: Option<Vec<String>>,

    call_format: Option<String>,
}

#[derive(Serialize)]
struct ArwahExecPartsScript {
    script: String,
    ip: String,
    port: String,
    ipversion: String,
}

#[derive(Serialize)]
struct ArwahExecParts {
    ip: String,
    port: String,
    ipversion: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArwahScriptFile {
    pub path: Option<PathBuf>,
    pub tags: Option<Vec<String>>,
    pub developer: Option<Vec<String>>,
    pub port: Option<String>,
    pub ports_separator: Option<String>,
    pub call_format: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ArwahScriptConfig {
    pub tags: Option<Vec<String>>,
    pub ports: Option<Vec<String>>,
    pub developer: Option<Vec<String>>,
    pub directory: Option<String>,
}

#[cfg(not(tarpaulin_include))]
pub fn arwah_init_scripts(scripts: &ArwahScriptsRequired) -> Result<Vec<ArwahScriptFile>> {
    let mut scripts_to_run: Vec<ArwahScriptFile> = Vec::new();

    match scripts {
        ArwahScriptsRequired::None => {}
        ArwahScriptsRequired::Default => {
            let default_script = toml::from_str::<ArwahScriptFile>(DEFAULT).expect("[ ETA ]: Failed to parse Script file.");
            scripts_to_run.push(default_script);
        }
        ArwahScriptsRequired::Custom => {
            let script_config = ArwahScriptConfig::arwah_read_config()?;
            debug!("[ ETA ]: Script config \n{script_config:?}");
            let script_dir_base = if let Some(config_directory) = &script_config.directory {
                PathBuf::from(config_directory)
            } else {
                dirs::home_dir().ok_or_else(|| anyhow!("[ ETA ]: Could not infer scripts path."))?
            };
            let script_paths = arwah_find_scripts(script_dir_base)?;
            debug!("[ ETA ]: Scripts paths \n{script_paths:?}");
            let parsed_scripts = arwah_parse_scripts(script_paths);
            debug!("[ ETA ]: Scripts parsed \n{parsed_scripts:?}");

            if let Some(config_hashset) = script_config.tags {
                for script in parsed_scripts {
                    if let Some(script_hashset) = &script.tags {
                        if script_hashset.iter().all(|tag| config_hashset.contains(tag)) {
                            scripts_to_run.push(script);
                        } else {
                            debug!("\n [ ETA ]: Script tags does not match config tags {:?} {}", &script_hashset, script.path.unwrap().display());
                        }
                    }
                }
            }
            debug!("\n[ ETA ]: Script(s) to run {scripts_to_run:?}");
        }
    }
    Ok(scripts_to_run)
}

pub fn arwah_parse_scripts(scripts: Vec<PathBuf>) -> Vec<ArwahScriptFile> {
    let mut parsed_scripts: Vec<ArwahScriptFile> = Vec::with_capacity(scripts.len());

    for script in scripts {
        debug!("[ ETA ]: Parsing script {}", script.display());

        if let Some(script_file) = ArwahScriptFile::new(script) {
            parsed_scripts.push(script_file);
        }
    }
    parsed_scripts
}

impl ArwahScript {
    pub fn arwah_build(
        path: Option<PathBuf>, ip: IpAddr, open_ports: Vec<u16>, trigger_port: Option<String>, ports_separator: Option<String>, tags: Option<Vec<String>>, call_format: Option<String>,
    ) -> Self {
        Self { path, ip, open_ports, trigger_port, ports_separator, tags, call_format }
    }

    #[allow(unused_assignments)]
    pub fn arwah_run(self) -> Result<String> {
        debug!("[ ETA ]: un self {:?}", &self);
        let separator = self.ports_separator.unwrap_or_else(|| ",".into());
        let mut ports_str = self.open_ports.iter().map(ToString::to_string).collect::<Vec<String>>().join(&separator);

        if let Some(port) = self.trigger_port {
            ports_str = port;
        }
        let mut final_call_format = String::new();

        if let Some(call_format) = self.call_format {
            final_call_format = call_format;
        } else {
            return Err(anyhow!("[ ETA ]: Failed to parse execution format."));
        }
        let default_template: Template = Template::new(&final_call_format);
        let mut to_run = String::new();

        if final_call_format.contains("{{script}}") {
            let exec_parts_script: ArwahExecPartsScript = ArwahExecPartsScript {
                script: self.path.unwrap().to_str().unwrap().to_string(),
                ip: self.ip.to_string(),
                port: ports_str,
                ipversion: match &self.ip {
                    IpAddr::V4(_) => String::from("4"),
                    IpAddr::V6(_) => String::from("6"),
                },
            };
            to_run = default_template.fill_with_struct(&exec_parts_script)?;
        } else {
            let exec_parts: ArwahExecParts = ArwahExecParts {
                ip: self.ip.to_string(),
                port: ports_str,
                ipversion: match &self.ip {
                    IpAddr::V4(_) => String::from("4"),
                    IpAddr::V6(_) => String::from("6"),
                },
            };
            to_run = default_template.fill_with_struct(&exec_parts)?;
        }
        debug!("\n[ ETA ]: Script format to run {to_run}");
        arwah_execute_script(&to_run)
    }
}

#[cfg(not(tarpaulin_include))]
fn arwah_execute_script(script: &str) -> Result<String> {
    debug!("\n[ ETA ]: Script arguments {script}");

    let (cmd, arg) = if cfg!(unix) { ("sh", "-c") } else { ("cmd.exe", "/c") };

    match Command::new(cmd).args([arg, script]).stdin(Stdio::piped()).stderr(Stdio::piped()).output() {
        Ok(output) => {
            let status = output.status;

            let es = match status.code() {
                Some(code) => code,
                _ => {
                    #[cfg(unix)]
                    {
                        status.signal().unwrap()
                    }

                    #[cfg(windows)]
                    {
                        return Err(anyhow!("[ ETA ]:Unknown exit status"));
                    }
                }
            };

            if es != 0 {
                return Err(anyhow!("[ ETA ]: Exit code = {}", es));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Err(error) => {
            debug!("[ ETA ]: Command error {error}",);
            Err(anyhow!(error.to_string()))
        }
    }
}

pub fn arwah_find_scripts(path: PathBuf) -> Result<Vec<PathBuf>> {
    if path.is_dir() {
        debug!("[ ETA ]: Scripts folder found {}", &path.display());
        let mut files_vec: Vec<PathBuf> = Vec::new();

        for entry in fs::read_dir(path)? {
            let entry = entry?;
            files_vec.push(entry.path());
        }
        Ok(files_vec)
    } else {
        Err(anyhow!("[ ETA ]: Can't find scripts folder {}", path.display()))
    }
}

impl ArwahScriptFile {
    fn new(script: PathBuf) -> Option<ArwahScriptFile> {
        let real_path = script.clone();
        let mut lines_buf = String::new();
        if let Ok(file) = File::open(script) {
            for mut line in io::BufReader::new(file).lines().skip(1).flatten() {
                if line.starts_with('#') {
                    line.retain(|c| c != '#');
                    line = line.trim().to_string();
                    line.push('\n');
                    lines_buf.push_str(&line);
                } else {
                    break;
                }
            }
        } else {
            debug!("[ ETA ]: Failed to read file: {}", &real_path.display());
            return None;
        }
        debug!("[ ETA ]: ScriptFile {} lines\n{}", &real_path.display(), &lines_buf);

        match toml::from_str::<ArwahScriptFile>(&lines_buf) {
            Ok(mut parsed) => {
                debug!("[ ETA ]: Parsed ScriptFile{} \n{:?}", &real_path.display(), &parsed);
                parsed.path = Some(real_path);
                // parsed_scripts.push(parsed);
                Some(parsed)
            }
            Err(e) => {
                debug!("[ ETA ]: Failed to parse ScriptFile headers {e}");
                None
            }
        }
    }
}

#[cfg(not(tarpaulin_include))]
impl ArwahScriptConfig {
    pub fn arwah_read_config() -> Result<ArwahScriptConfig> {
        let Some(mut home_dir) = dirs::home_dir() else {
            return Err(anyhow!("Could not infer ScriptConfig path."));
        };
        home_dir.push(".arwah_scripts.toml");
        let content = fs::read_to_string(home_dir)?;
        let config = toml::from_str::<ArwahScriptConfig>(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arwah_into_script(script_f: ArwahScriptFile) -> ArwahScript {
        ArwahScript::arwah_build(script_f.path, "127.0.0.1".parse().unwrap(), vec![80, 8080], script_f.port, script_f.ports_separator, script_f.tags, script_f.call_format)
    }

    #[test]
    fn test_find_and_parse_scripts() {
        let scripts = arwah_find_scripts("examples/.arwah_scripts".into()).unwrap();
        let scripts = arwah_parse_scripts(scripts);
        assert_eq!(scripts.len(), 4)
    }

    #[test]
    #[should_panic]
    fn test_find_invalid_folder() {
        let _scripts = arwah_find_scripts("Cargo.toml".into()).unwrap();
    }

    #[test]
    #[should_panic]
    fn open_script_file_invalid_headers() {
        ArwahScriptFile::new("examples/.arwah_scripts/test_script_invalid_headers.txt".into()).unwrap();
    }

    #[test]
    #[should_panic]
    fn open_script_file_invalid_call_format() {
        let mut script_f = ArwahScriptFile::new("examples/.arwah_scripts/test_script.txt".into()).unwrap();
        script_f.call_format = Some("qwertyuiop".to_string());
        let script: ArwahScript = arwah_into_script(script_f);
        let _output = script.arwah_run().unwrap();
    }

    #[test]
    #[should_panic]
    fn open_script_file_missing_call_format() {
        let mut script_f = ArwahScriptFile::new("examples/.arwah_scripts/test_script.txt".into()).unwrap();
        script_f.call_format = None;
        let script: ArwahScript = arwah_into_script(script_f);
        let _output = script.arwah_run().unwrap();
    }

    #[test]
    #[should_panic]
    fn open_nonexisting_script_file() {
        ArwahScriptFile::new("qwertyuiop.txt".into()).unwrap();
    }

    #[test]
    fn parse_txt_script() {
        let script_f = ArwahScriptFile::new("examples/.arwah_scripts/test_script.txt".into()).unwrap();
        assert_eq!(script_f.tags, Some(vec!["core_approved".to_string(), "example".to_string()]));
        assert_eq!(script_f.developer, Some(vec!["example".to_string(), "https://example.org".to_string()]));
        assert_eq!(script_f.ports_separator, Some(",".to_string()));
        assert_eq!(script_f.call_format, Some("nmap -vvv -p {{port}} {{ip}}".to_string()));
    }

    #[test]
    #[cfg(unix)]
    fn run_bash_script() {
        let script_f = ArwahScriptFile::new("examples/.arwah_scripts/test_script.sh".into()).unwrap();
        let script: ArwahScript = arwah_into_script(script_f);
        let output = script.arwah_run().unwrap();
        // output has a newline at the end by default, .trim() trims it
        assert_eq!(output.trim(), "127.0.0.1 80,8080");
    }

    #[test]
    fn run_python_script() {
        let script_f = ArwahScriptFile::new("examples/.arwah_scripts/test_script.py".into()).unwrap();
        let script: ArwahScript = arwah_into_script(script_f);
        let output = script.arwah_run().unwrap();
        // output has a newline at the end by default, .trim() trims it
        assert_eq!(output.trim(), "Python script ran with arguments ['examples/.arwah_scripts/test_script.py', '127.0.0.1', '80,8080']");
    }

    #[test]
    #[cfg(unix)]
    fn run_perl_script() {
        let script_f = ArwahScriptFile::new("examples/.arwah_scripts/test_script.pl".into()).unwrap();
        let script: ArwahScript = arwah_into_script(script_f);
        let output = script.arwah_run().unwrap();
        // output has a newline at the end by default, .trim() trims it
        assert_eq!(output.trim(), "Total args passed to examples/.arwah_scripts/test_script.pl : 2\nArg # 1 : 127.0.0.1\nArg # 2 : 80,8080");
    }

    #[test]
    fn test_custom_directory_config() {
        // Create test config
        let config_str = r#"
            tags = ["core_approved", "example"]
            directory = "examples/.arwah_scripts"
        "#;

        let config: ArwahScriptConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.directory, Some("examples/.arwah_scripts".to_string()));
        let script_dir_base = PathBuf::from(config.directory.unwrap());
        let scripts = arwah_find_scripts(script_dir_base).unwrap();
        assert!(scripts.iter().any(|p| { p.file_name().and_then(|f| f.to_str()).map(|s| s == "test_script.txt").unwrap_or(false) }));
    }

    #[test]
    fn test_default_directory_fallback() {
        let config_str = r#"
            tags = ["core_approved", "example"]
        "#;
        let config: ArwahScriptConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.directory, None);
        let script_dir_base = if let Some(config_directory) = &config.directory { PathBuf::from(config_directory) } else { dirs::home_dir().unwrap() };
        assert_eq!(script_dir_base, dirs::home_dir().unwrap());
    }
}
