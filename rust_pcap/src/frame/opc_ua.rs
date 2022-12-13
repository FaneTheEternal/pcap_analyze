use byteorder::{ByteOrder, LittleEndian};
use strum::{IntoEnumIterator};
use strum_macros::EnumIter;

use crate::*;


#[derive(Debug, EnumIter)]
pub enum MessageType {
    HEL,
    // Hello Message
    ASK,
    // Acknowledge Message
    ERP,
    // Error Message
    RHE,
    // ReverseHello Message
    MSG,  // ??? Message
}

impl TryFrom<&[u8]> for MessageType {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value = value.get(..3).ok_or(())?;
        let value = String::from_utf8_lossy(value);
        for kind in MessageType::iter() {
            let kind_str = format!("{:?}", kind);
            if kind_str.as_str() == value.as_ref() {
                return Ok(kind);
            }
        }
        Err(())
    }
}


#[derive(Layer, Debug)]
pub struct OpcUa {
    pub msg_type: MessageType,
    pub chunk_type: char,
    pub message_size: u32,
    pub data: Vec<u8>,
}

impl OpcUa {
    pub fn try_make(tcp: &TCP) -> Option<Self> {
        let data = tcp.data.as_slice();
        let kind = MessageType::try_from(data).ok()?;
        let chunk_type = *data.get(3)? as char;
        let message_size = LittleEndian::read_u32(data.get(4..8)?);
        println!("{:X}", message_size);
        return Some(OpcUa {
            msg_type: kind,
            chunk_type,
            message_size,
            data: data.get(8..).map(|s| s.to_vec()).unwrap_or_default(),
        });
    }
}
