use crate::*;
use byteorder::{ByteOrder, NetworkEndian};


#[derive(Layer)]
pub struct TPKT {
    version: u8,
    reserved: u8,
    len: u16,
}

impl TPKT {
    pub fn try_make(ctx: &TCPSequence) -> Option<TPKT> {
        let data = &ctx.data;
        let version = *data.get(0)?;
        let reserved = *data.get(1)?;
        let len = NetworkEndian::read_u16(data.get(2..4)?);
        let tpkt = TPKT {
            version,
            reserved,
            len,
        };
        Some(tpkt)
    }
}
