#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::Formatter;
use std::ptr::NonNull;

mod frame;
mod ethernet;
mod ip;
mod udp;
mod icmp;
mod tcp;
mod arp;
mod http;

pub use frame::*;
pub use ethernet::*;
pub use ip::*;
pub use udp::*;
pub use icmp::*;
pub use tcp::*;
pub use arp::*;
pub use http::*;

pub use analyze_derive::*;

pub fn split(data: &[u8], i: usize) -> (&[u8], &[u8]) {
    (data.get(..i).unwrap(), data.get(i..).unwrap())
}

pub fn default<T: Default>() -> T {
    Default::default()
}

#[macro_export]
macro_rules! get_array {
    ($source:expr, $slice:expr) => {
        $source.get($slice).unwrap().try_into().unwrap()
    }
}

#[macro_export]
macro_rules! get_layer_descendants {
    ($self:expr, $target:ident, $($type:ident),+ $(,)?) => {
        None
        $(
        .or_else(|| get_layer::<_, $type>($self).and_then(|l| { l.get_layer::<$target>() }))
        )+
    }
}

pub trait Layer {
    fn name() -> &'static str where Self: Sized;
    fn as_ptr(&self) -> NonNull<usize> {
        NonNull::from(self).cast::<usize>()
    }
}

#[derive(Default, derive_more::Deref, derive_more::DerefMut)]
pub struct Layers(HashMap<String, Box<dyn Layer>>);

impl Layers {
    pub fn insert<T: Layer + 'static>(&mut self, layer: T) {
        self.0.insert(T::name().to_string(), Box::new(layer));
    }
}

impl std::fmt::Debug for Layers {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0.iter().map(|(e, _)| e.clone()).collect::<Vec<String>>())
    }
}

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

