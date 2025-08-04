use crate::sandbox::config::*;
use nix::unistd::{Gid, Uid, setgid, setuid};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "linux")]
use nix::unistd::{getgroups, setgroups};

pub use anyhow::{Context, Error, Result, anyhow, bail};
pub use log::{debug, info, warn};

pub fn arwah_activate_stage_o(disable_seccomp: bool) -> Result<()> {
    if disable_seccomp {
        warn!("[ ETA ]: DANGER seccomp sandbox is disabled")
    } else {
        #[cfg(target_os = "linux")]
        seccomp::activate_stage1()?;
    }
    info!("[ ETA ]: stage 1/2 is active");
    Ok(())
}

pub fn arwah_chroot(path: &str) -> Result<()> {
    let metadata = fs::metadata(path)?;

    if !metadata.is_dir() {
        bail!("[ ETA ]: chroot target is no directory");
    }

    if metadata.uid() != 0 {
        bail!("[ ETA ]: chroot target isn't owned by root");
    }

    if metadata.mode() & 0o22 != 0 {
        bail!("[ ETA ]: chroot is writable by group or world");
    }
    nix::unistd::chroot(path)?;
    env::set_current_dir("/")?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn arwah_id() -> String {
    let uid = uzers::get_current_uid();
    let euid = uzers::get_effective_uid();
    let gid = uzers::get_current_gid();
    let egid = uzers::get_effective_gid();
    let groups = getgroups().unwrap();
    format!("[ ETA ]: uid={:?} euid={:?} gid={:?} egid={:?} groups={:?}", uid, euid, gid, egid, groups)
}

#[cfg(not(target_os = "linux"))]
pub fn arwah_id() -> String {
    let uid = uzers::get_current_uid();
    let euid = uzers::get_effective_uid();
    let gid = uzers::get_current_gid();
    let egid = uzers::get_effective_gid();
    format!("[ ETA ]: uid={:?} euid={:?} gid={:?} egid={:?}", uid, euid, gid, egid,)
}

fn arwah_apply_config(config: ArwahConfig) -> Result<()> {
    debug!("got config: {:?}", config);

    let user = if let Some(user) = config.sandbox.user {
        let user = match uzers::get_user_by_name(&user) {
            Some(user) => user,
            None => bail!("[ ETA ]: Invalid sandbox user"),
        };
        Some((user.uid(), user.primary_group_id()))
    } else {
        None
    };
    let is_root = Uid::current().is_root();

    match config.sandbox.chroot.as_ref() {
        Some(path) if is_root => {
            info!("[ ETA ]: starting chroot: {:?}", path);
            arwah_chroot(path)?;
            info!("[ ETA ]: successfully chrooted");
        }
        _ => (),
    }

    if is_root {
        match user {
            Some((uid, gid)) => {
                info!("[ ETA ]: id: {}", arwah_id());
                info!("[ ETA ]: setting uid to {:?}", uid);
                #[cfg(target_os = "linux")]
                setgroups(&[])?;
                setgid(Gid::from_raw(gid))?;
                setuid(Uid::from_raw(uid))?;
                info!("[ ETA ]: id: {}", arwah_id());
            }
            None => {
                warn!("[ ETA ]: executing as root!");
            }
        }
    } else {
        info!("[ ETA ]: can't drop privileges, executing as {}", arwah_id());
    }
    Ok(())
}

pub fn arwah_activate_stage_t(disable_seccomp: bool) -> Result<()> {
    let config = if let Some(config_path) = arwah_find() {
        arwah_load(&config_path)?
    } else {
        warn!("couldn't find config");
        ArwahConfig::default()
    };
    arwah_apply_config(config)?;

    if !disable_seccomp {
        #[cfg(target_os = "linux")]
        seccomp::activate_stage2()?;
    }
    info!("[ ETA ]: stage 2/2 is active");
    Ok(())
}
