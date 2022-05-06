use crate::*;
use crate::ethernet::Ethernet;

#[derive(Layer)]
pub struct Frame {
    layers: Layers,
}

impl Frame {
    pub fn new(data: &[u8]) -> Frame {
        let mut layers = Layers::default();
        let eth = Ethernet::new(data);
        layers.insert(Ethernet::name().to_string(), Box::new(eth));
        Frame { layers }
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
