mod frame;
mod ethernet;
mod ip;

pub use frame::*;
pub use ethernet::*;
pub use ip::*;

pub fn split(data: &[u8], i: usize) -> (&[u8], &[u8]) {
    (data.get(..i).unwrap(), data.get(i..).unwrap())
}

pub fn default<T: Default>() -> T {
    T::default()
}

#[macro_export]
macro_rules! get_array {
    ($source:expr, $slice:expr) => {
        $source.get($slice).unwrap().try_into().unwrap()
    }
}
use std::collections::HashMap;
use std::ptr::NonNull;

pub trait Layer {
    // TODO: Derive {name}
    fn name() -> &'static str where Self: Sized;
    fn as_ptr(&self) -> NonNull<usize> {
        NonNull::from(self).cast::<usize>()
    }
}

pub type Layers = HashMap<String, Box<dyn Layer>>;

pub trait HasLayers {
    fn layers(&self) -> &Layers;
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer { None }
}

pub trait GetLayers {
    fn get_layer<T>(&self) -> Option<&T> where T: Layer;
}

impl<L: Layer + HasLayers> GetLayers for L {
    fn get_layer<T>(&self) -> Option<&T> where T: Layer {
        get_layer(self).or_else(|| self.get_layer_descendants::<T>())
    }
}

pub fn get_layer<O, T>(origin: &O) -> Option<&T>
    where
        O: Layer + HasLayers,
        T: Layer
{
    let key = T::name();
    if let Some(layer) = origin.layers().get(key) {
        let ptr = layer.as_ptr().cast::<T>();
        return Some(unsafe { ptr.as_ref() });
    }
    None
}

