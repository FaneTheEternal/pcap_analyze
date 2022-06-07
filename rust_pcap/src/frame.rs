use pcap_parser::LegacyPcapBlock;
use crate::*;
use crate::ethernet::Ethernet;

#[derive(Layer)]
pub struct Frame {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub caplen: u32,
    pub origlen: u32,
    pub data: Vec<u8>,

    layers: Layers,
}

impl Frame {
    pub fn new(data: &[u8], ts_sec: u32, ts_usec: u32, caplen: u32, origlen: u32) -> Frame {
        let mut layers = Layers::default();
        layers.insert(Ethernet::new(data));
        Frame { ts_sec, ts_usec, caplen, origlen, data: data.to_vec(), layers }
    }

    pub fn from_legacy(block: &LegacyPcapBlock) -> Frame {
        Self::new(block.data, block.ts_sec, block.ts_usec, block.caplen, block.origlen)
    }
}

impl HasLayers for Frame {
    fn layers(&self) -> &Layers {
        &self.layers
    }
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer {
        get_layer_descendants!(self, T, Ethernet)
    }
}
