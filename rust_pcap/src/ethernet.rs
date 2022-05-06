use std::fmt::Formatter;
use std::ptr::NonNull;
use crate::*;

#[derive(Layer)]
pub struct Ethernet {
    src: [u8; 6],
    dst: [u8; 6],
    eth_type: [u8; 2],
    crc: [u8; 4],
    layers: Layers,
}

impl std::fmt::Debug for Ethernet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let src = self.src.map(|b| format!("{:X}", b)).join(":");
        let dst = self.dst.map(|b| format!("{:X}", b)).join(":");
        let eth_type = self.eth_type.map(|b| format!("{:0>2x}", b)).join("");
        write!(f, "Ethernet(Mac({}->{:}) Type(0x{}))", src, dst, eth_type)
    }
}

impl Ethernet {
    const IP4: [u8; 2] = [0x08, 0x00];
    const IP6: [u8; 2] = [0x86, 0xDD];

    pub fn new(data: &[u8]) -> Ethernet {
        let mut layers = Layers::default();
        let eth_type = get_array!(data, 12..14);
        match eth_type {
            Self::IP4 => {
                layers.insert(IPv4::new(data.get(14..(data.len() - 4)).unwrap()));
            }
            _ => {}
        }
        Ethernet {
            src: get_array!(data, 0..6),
            dst: get_array!(data, 6..12),
            eth_type,
            crc: get_array!(data, (data.len() - 4)..),
            layers,
        }
    }
}

impl HasLayers for Ethernet {
    fn layers(&self) -> &Layers {
        &self.layers
    }
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer {
        get_layer_descendants!(self, T, IPv4)
    }
}