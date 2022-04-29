use crate::*;
use crate::ethernet::Ethernet;

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

impl Layer for Frame {
    fn name() -> &'static str where Self: Sized {
        "Frame"
    }
}

impl HasLayers for Frame {
    fn layers(&self) -> &Layers {
        &self.layers
    }
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer {
        self.get_layer::<Ethernet>().and_then(|eth| { eth.get_layer::<T>() })
    }
}
