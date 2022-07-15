use byteorder::{ByteOrder, NetworkEndian};

use crate::*;

#[derive(Debug, Layer)]
pub struct DHCP {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    options: Option<Vec<u8>>,
}

impl DHCP {
    const START_OPTIONS: [u8; 4] = [99, 130, 83, 99];

    pub fn try_make(data: &[u8]) -> Option<DHCP> {
        let op = data.get(0)?.clone();
        if ![0x01, 0x02].contains(&op) { return None; }
        let htype = data.get(1)?.clone();
        let hlen = data.get(2)?.clone();
        let hops = data.get(3)?.clone();
        let xid = NetworkEndian::read_u32(data.get(4..8)?);
        let secs = NetworkEndian::read_u16(data.get(8..10)?);
        let flags = NetworkEndian::read_u16(data.get(10..12)?);
        let ciaddr = NetworkEndian::read_u32(data.get(12..16)?);
        let yiaddr = NetworkEndian::read_u32(data.get(16..20)?);
        let siaddr = NetworkEndian::read_u32(data.get(20..24)?);
        let giaddr = NetworkEndian::read_u32(data.get(24..28)?);
        let chaddr = data.get(28..44)?;
        let sname = data.get(44..108)?;
        let file = data.get(108..236)?;
        let data = data.get(236..);
        let options = if let Some(data) = data {
            if data.starts_with(&Self::START_OPTIONS) {
                Some(data.get(4..).expect("Has magic but no options").to_vec())
            } else { None }
        } else { None };
        Some(DHCP {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr: chaddr.try_into().unwrap(),
            sname: sname.try_into().unwrap(),
            file: file.try_into().unwrap(),
            options,
        })
    }
}
