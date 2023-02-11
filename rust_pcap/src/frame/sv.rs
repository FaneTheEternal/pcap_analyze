use crate::*;
use byteorder::{ByteOrder, NetworkEndian};


#[derive(Layer)]
pub struct SampledValue {
    app_id: u16,  //  0x4000 ～ 0x7fff
    pub len: u16,
    pub reserved1: u16,
    pub reserved2: u16,
    pub apdu: Vec<u8>,
}

impl SampledValue {
    pub fn new(data: &[u8]) -> SampledValue {
        // let m = data.len();
        let app_id = NetworkEndian::read_u16(data.get(..2).unwrap());
        let len = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let reserved1 = NetworkEndian::read_u16(data.get(4..6).unwrap());
        let reserved2 = NetworkEndian::read_u16(data.get(6..8).unwrap());
        let ln = len as usize;
        SampledValue {
            app_id,
            len,
            reserved1,
            reserved2,
            apdu: data.get(8..ln).unwrap().to_vec(),
        }
    }
}
