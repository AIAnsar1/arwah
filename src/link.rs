use anyhow::{Result, bail};

#[derive(Debug, Clone)]
pub enum ArwahDataLink {
    Ethernet,
    Tun,
    Sll,
    RadioTap,
}

impl ArwahDataLink {
    pub fn arwah_from_linktype(linktype: i32) -> Result<ArwahDataLink> {
        match linktype {
            1 => Ok(ArwahDataLink::Ethernet),
            12 => Ok(ArwahDataLink::Tun),
            113 => Ok(ArwahDataLink::Sll),
            127 => Ok(ArwahDataLink::RadioTap),
            x => bail!("[ ETA ]: Unknown link type: {:?}", x),
        }
    }
}
