use crate::*;
use byteorder::{ByteOrder, NetworkEndian};


#[derive(Layer)]
pub struct GOOSE {
    pub app_id: u16,
    pub len: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub apdu: Vec<u8>,
    pub ext: Vec<u8>,
}

impl GOOSE {
    pub fn new(data: &[u8]) -> GOOSE {
        let m = data.len();
        let app_id = NetworkEndian::read_u16(data.get(..2).unwrap());
        let len = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let reserved1 = NetworkEndian::read_u16(data.get(4..6).unwrap());
        let reserved2 = NetworkEndian::read_u16(data.get(6..8).unwrap());
        let ln = len as usize;
        GOOSE {
            app_id,
            len,
            reserved1,
            reserved2,
            apdu: data.get(8..ln).unwrap().to_vec(),
            ext: data.get(ln..m).unwrap().to_vec(),
        }
    }
}
