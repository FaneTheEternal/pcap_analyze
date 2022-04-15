use byteorder::{ByteOrder, NetworkEndian};
use crate::split;

pub struct IP<'frame> {
    version: u8,
    ip: IPTypes<'frame>,
}

impl<'frame> IP<'frame> {
    pub fn try_extract(data: &'frame [u8]) -> Option<(IP<'frame>, &'frame [u8])> {
        let first = data.get(0).unwrap().clone();
        let version = first >> 4;
        match version {
            4 => {
                let (ip, data) = IPv4::from_raw(data);
                let ip = IP { version, ip: IPTypes::V4(ip) };
                Some((ip, data))
            }
            6 => { todo!() }
            _ => unreachable!()
        }
    }
}

pub enum IPTypes<'frame> {
    V4(IPv4<'frame>),
    // TODO: v6
}

pub struct IPv4<'frame> {
    // offset: 0
    ihl: u8,
    dscp: u8,
    ecn: u8,
    size: u16,
    // offset: 4
    id: u16,
    flags: (bool, bool, bool),
    fragments_offset: u16,
    // offset: 8
    ttl: u8,
    protocol: u8,
    checksum: u16,
    // offset: 12
    src: &'frame [u8; 4],
    // offset: 16
    dst: &'frame [u8; 4],
    // optional offset: 20
    opt: Option<&'frame [u8; 4]>,
}

impl<'frame> IPv4<'frame> {
    fn from_raw(data: &'frame [u8]) -> (IPv4, &'frame [u8]) {
        let ihl = data.get(0).unwrap().clone();
        let ihl = ihl & 0x0F;
        let dscp = data.get(1).unwrap().clone();
        let ecn = dscp & 0b000000_11;
        let dscp = dscp >> 2;
        let size = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let id = NetworkEndian::read_u16(data.get(4..6).unwrap());
        let fragments_offset = NetworkEndian::read_u16(data.get(6..8).unwrap());
        let flags = (
            fragments_offset & 0b100_00000 > 0,
            fragments_offset & 0b010_00000 > 0,
            fragments_offset & 0b001_00000 > 0
        );
        let fragments_offset = fragments_offset & 0b000_11111;
        let ttl = data.get(8).unwrap().clone();
        let protocol = data.get(9).unwrap().clone();
        let checksum = NetworkEndian::read_u16(data.get(10..12).unwrap());
        let (_, data) = split(data, 12);
        let (src, data) = split(data, 4);
        let (dst, data) = split(data, 4);
        let (opt, data) = if ihl > 5 {
            let (o, d) = split(data, 4);
            (Some(o.try_into().unwrap()), d)
        } else {
            (None, data)
        };
        let ip = IPv4 {
            ihl,
            dscp,
            ecn,
            size,
            id,
            flags,
            fragments_offset,
            ttl,
            protocol,
            checksum,
            src: src.try_into().unwrap(),
            dst: dst.try_into().unwrap(),
            opt,
        };
        (ip, data)
    }
}
