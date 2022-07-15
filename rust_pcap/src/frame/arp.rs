use byteorder::{ByteOrder, NetworkEndian};

use crate::*;

#[derive(Debug, Layer)]
pub struct ARP {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: u64,
    spa: u32,
    tha: u64,
    tpa: u32,
}

impl ARP {
    pub fn new(data: &[u8]) -> ARP {
        const MASK48: u64 = 0xFF_FF_FF_FF_FF_FF_00_00;
        ARP {
            htype: NetworkEndian::read_u16(data.get(0..2).unwrap()),
            ptype: NetworkEndian::read_u16(data.get(2..4).unwrap()),
            hlen: data.get(4).unwrap().clone(),
            plen: data.get(5).unwrap().clone(),
            oper: NetworkEndian::read_u16(data.get(6..8).unwrap()),
            sha: (NetworkEndian::read_u64(data.get(8..16).unwrap()) & MASK48) >> 16,
            spa: NetworkEndian::read_u32(data.get(14..18).unwrap()),
            tha: (NetworkEndian::read_u64(data.get(18..26).unwrap()) & MASK48) >> 16,
            tpa: NetworkEndian::read_u32(data.get(24..28).unwrap()),
        }
    }
}
