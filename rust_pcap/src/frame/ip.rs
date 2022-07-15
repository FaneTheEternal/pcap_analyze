use byteorder::{ByteOrder, NetworkEndian};

use crate::*;
use crate::frame::icmp::ICMP;

#[derive(Layer, Debug)]
pub struct IPFlags {
    pub null: bool,
    pub df: bool,
    pub mf: bool,
}

#[derive(Layer, Debug)]
pub struct IPv4 {
    // offset: 0
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub size: u16,
    // offset: 4
    pub id: u16,
    pub flags: IPFlags,
    pub fragments_offset: u16,
    // offset: 8
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    // offset: 12
    pub src: [u8; 4],
    // offset: 16
    pub dst: [u8; 4],
    // optional offset: 20
    pub opt: Option<[u8; 4]>,
    layers: Layers,
}

impl IPv4 {
    pub fn new(data: &[u8]) -> IPv4 {
        let ihl = data.get(0).unwrap().clone();
        let ihl = ihl & 0x0F;
        let dscp = data.get(1).unwrap().clone();
        let ecn = dscp & 0b000000_11;
        let dscp = dscp >> 2;
        let size = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let id = NetworkEndian::read_u16(data.get(4..6).unwrap());
        let fragments_offset = NetworkEndian::read_u16(data.get(6..8).unwrap());
        let flags = IPFlags {
            null: fragments_offset & 0b100_00000 > 0,
            df: fragments_offset & 0b010_00000 > 0,
            mf: fragments_offset & 0b001_00000 > 0,
        };
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
        let mut layers = Layers::default();
        match protocol {
            1 => {
                layers.insert(ICMP::new(data));
            }
            6 => {
                layers.insert(TCP::new(data));
            }
            17 => {
                layers.insert(UDP::new(data));
            }
            _ => {}
        }
        IPv4 {
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
            layers,
        }
    }
}

impl HasLayers for IPv4 {
    fn layers(&self) -> &Layers {
        &self.layers
    }
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer {
        get_layer_descendants!(self, T, UDP, TCP)
    }
}


#[derive(Layer)]
pub struct IPv6 {
    // offset 0
    qos: u8,
    label: u32,
    // offset 4
    len: u16,
    header: u8,
    hops: u8,
    // offset 8
    src: [u8; 16],
    // offset 24
    dst: [u8; 16],
}

impl IPv6 {
    pub fn new(data: &[u8]) -> IPv6 {
        let qos = NetworkEndian::read_u16(data.get(0..2).unwrap());
        let qos = (qos << 4) as u8;
        let label = NetworkEndian::read_u32(data.get(..4).unwrap());
        let label = label << 12;
        let len = NetworkEndian::read_u16(data.get(4..6).unwrap());
        let header = data.get(6).unwrap().clone();
        let hops = data.get(7).unwrap().clone();
        let src = get_array!(data, 8..24);
        let dst = get_array!(data, 24..40);
        IPv6 {
            qos,
            label,
            len,
            header,
            hops,
            src,
            dst,
        }
    }
}
