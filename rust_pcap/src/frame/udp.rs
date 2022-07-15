use byteorder::{ByteOrder, NetworkEndian};

use crate::*;

#[derive(Debug, Layer)]
pub struct UDP {
    src: u16,
    dst: u16,
    len: u16,
    checksum: u16,
    pub payload: Vec<u8>,

    layers: Layers,
}

impl HasLayers for UDP {
    fn layers(&self) -> &Layers {
        &self.layers
    }
}

impl UDP {
    pub fn new(data: &[u8]) -> UDP {
        let mut layers = Layers::default();
        if let Some(dhcp) = DHCP::try_make(data.get(8..).unwrap()) {
            layers.insert(dhcp);
        }
        UDP {
            src: NetworkEndian::read_u16(data.get(..2).unwrap()),
            dst: NetworkEndian::read_u16(data.get(2..4).unwrap()),
            len: NetworkEndian::read_u16(data.get(4..6).unwrap()),
            checksum: NetworkEndian::read_u16(data.get(6..8).unwrap()),
            payload: data.get(8..).unwrap().to_vec(),
            layers,
        }
    }
}

