use std::fmt::Formatter;
use crate::split;

pub struct Ethernet<'frame> {
    src: &'frame [u8; 6],
    dst: &'frame [u8; 6],
    eth_type: &'frame [u8; 2],
    crc: &'frame [u8; 4],
}

impl std::fmt::Debug for Ethernet<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let src = self.src.map(|b| format!("{:X}", b)).join(":");
        let dst = self.dst.map(|b| format!("{:X}", b)).join(":");
        let eth_type = self.eth_type.map(|b| format!("{:0>2x}", b)).join("");
        write!(f, "Ethernet(Mac({}->{:}) Type(0x{}))", src, dst, eth_type)
    }
}

impl<'frame> Ethernet<'frame> {
    pub fn has_ipv4(&self) -> bool {
        self.eth_type.eq(&[0x08, 0x00])
    }

    pub fn from_raw(data: &'frame [u8]) -> (Ethernet<'frame>, &'frame [u8]) {
        let (src, data) = split(data, 6);
        let (dst, data) = split(data, 6);
        let (eth_type, data) = split(data, 2);
        let (data, crc) = split(data, data.len() - 4);
        let ethernet = Ethernet {
            src: src.try_into().unwrap(),
            dst: dst.try_into().unwrap(),
            eth_type: eth_type.try_into().unwrap(),
            crc: crc.try_into().unwrap(),
        };
        (ethernet, data)
    }
}
