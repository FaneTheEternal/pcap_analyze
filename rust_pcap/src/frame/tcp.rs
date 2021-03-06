use byteorder::{ByteOrder, NetworkEndian};

use crate::*;

#[derive(Debug)]
pub struct TCPFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

#[derive(Debug, Layer)]
pub struct TCP {
    pub src: u16,
    pub dst: u16,
    sn: u32,
    ack_sn: u32,
    header_len: u8,
    pub flags: TCPFlags,
    window_size: u16,
    checksum: u16,
    urgent_point: u16,
    options: Vec<u8>,
    pub data: Vec<u8>,
    layers: Layers,
}

impl TCP {
    pub fn new(data: &[u8]) -> TCP {
        let src = NetworkEndian::read_u16(data.get(..2).unwrap());
        let dst = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let sn = NetworkEndian::read_u32(data.get(4..8).unwrap());
        let ack_sn = NetworkEndian::read_u32(data.get(8..12).unwrap());
        let header_len = (data.get(12).unwrap() & 0b11110000) >> 4;
        let flags = NetworkEndian::read_u16(data.get(12..14).unwrap());
        let flags = TCPFlags {
            ns: flags & 0b0000000100000000 > 0,
            cwr: flags & 0b0000000010000000 > 0,
            ece: flags & 0b0000000001000000 > 0,
            urg: flags & 0b0000000000100000 > 0,
            ack: flags & 0b0000000000010000 > 0,
            psh: flags & 0b0000000000001000 > 0,
            rst: flags & 0b0000000000000100 > 0,
            syn: flags & 0b0000000000000010 > 0,
            fin: flags & 0b0000000000000001 > 0,
        };
        let window_size = NetworkEndian::read_u16(data.get(14..16).unwrap());
        let checksum = NetworkEndian::read_u16(data.get(16..18).unwrap());
        let urgent_point = NetworkEndian::read_u16(data.get(18..20).unwrap());
        let options = data.get(20..(header_len.clone() as usize * 4)).unwrap().to_vec();
        let data = data.get((header_len.clone() as usize * 4)..).unwrap().to_vec();
        let mut layers = Layers::default();
        if let Some(http) = HTTP::try_make(data.as_slice()) {
            layers.insert(http);
        }
        TCP {
            src,
            dst,
            sn,
            ack_sn,
            header_len: header_len.clone(),
            flags,
            window_size,
            checksum,
            urgent_point,
            options,
            data,
            layers,
        }
    }
}

impl HasLayers for TCP {
    fn layers(&self) -> &Layers {
        &self.layers
    }
}
