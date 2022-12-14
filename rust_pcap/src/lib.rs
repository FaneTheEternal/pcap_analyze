#![allow(dead_code)]

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Formatter;
use std::hash::{Hash, Hasher};
use std::ops::{AddAssign, Range, RangeFrom, RangeFull, RangeTo};
use std::path::Path;
use std::ptr::NonNull;
use std::slice::SliceIndex;
use csv::ReaderBuilder;

pub use analyze_derive::*;
pub use frame::*;
pub use frame::arp::*;
pub use frame::dhcp::*;
pub use frame::ethernet::*;
pub use frame::http::*;
pub use frame::icmp::*;
pub use frame::ip::*;
pub use frame::tcp::*;
pub use frame::udp::*;
pub use iter::*;

mod frame;
mod iter;
pub mod counter;
pub mod tf;

pub fn split(data: &[u8], i: usize) -> (&[u8], &[u8]) {
    (data.get(..i).unwrap(), data.get(i..).unwrap())
}

pub fn to_string<S: std::fmt::Display + Sized>(s: S) -> String {
    s.to_string()
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

#[macro_export]
macro_rules! fmt_iter {
    ($iter:expr, $separator:expr, $fmt:tt) => {
        $iter.iter()
            .map(|e| format!($fmt, e))
            .collect::<Vec<_>>()
            .join($separator)
    };
    ($iter:expr, $separator:expr) => {
        fmt_iter!($iter, $separator, "{}")
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

pub struct MultipartSlice<'t> {
    pub slices: Vec<&'t [u8]>,
}

impl<'t> MultipartSlice<'t> {
    #[inline]
    pub fn get<I>(&self, range: I) -> Option<&'t [u8]>
        where I: SliceIndex<[u8]> + Into<MyRange<usize>>
    {
        let mut range: MyRange<usize> = range.into();
        for slice in &self.slices {
            if range.start.or_else(|| { range.end }).unwrap() >= slice.len() {
                if let Some(start) = range.start.as_mut() { *start -= slice.len() }
                if let Some(end) = range.end.as_mut() { *end -= slice.len() }
            } else {
                return if let (Some(start), Some(end)) = (range.start, range.end) {
                    slice.get(start..end)
                } else if let Some(start) = range.start {
                    slice.get(start..)
                } else if let Some(end) = range.end {
                    slice.get(..end)
                } else {
                    slice.get(..)
                };
            }
        }
        None
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.slices.iter().map(|s| s.len()).sum()
    }
}

impl<'t> From<&'t [u8]> for MultipartSlice<'t> {
    #[inline]
    fn from(source: &'t [u8]) -> Self {
        Self { slices: vec![source] }
    }
}

#[derive(Debug)]
pub struct MyRange<Idx> {
    pub start: Option<Idx>,
    pub end: Option<Idx>,
}

impl<Idx> From<Range<Idx>> for MyRange<Idx> {
    #[inline]
    fn from(o: Range<Idx>) -> Self {
        Self { start: Some(o.start), end: Some(o.end) }
    }
}

impl<Idx> From<RangeFrom<Idx>> for MyRange<Idx> {
    #[inline]
    fn from(o: RangeFrom<Idx>) -> Self {
        Self { start: Some(o.start), end: None }
    }
}

impl<Idx> From<RangeTo<Idx>> for MyRange<Idx> {
    #[inline]
    fn from(o: RangeTo<Idx>) -> Self {
        Self { start: None, end: Some(o.end) }
    }
}


pub fn print_stats<P: AsRef<Path>>(
    path: P, range: Range<usize>, headers: &[&str],
) -> Result<(), Box<dyn Error>>
{
    assert_eq!(range.end - range.start, headers.len());

    #[derive(PartialEq, Debug)]
    struct Row(Vec<f32>);
    impl Hash for Row {
        fn hash<H: Hasher>(&self, state: &mut H) {
            format!("{:?}", self.0).hash(state)
        }
    }
    impl From<Vec<f32>> for Row {
        fn from(v: Vec<f32>) -> Self {
            Row(v)
        }
    }
    impl Eq for Row {}

    let mut rdr = ReaderBuilder::new()
        .delimiter(b',')
        .from_path(path)?;
    let mut stats = HashMap::<Row, usize>::new();
    let mut count = 0usize;
    for record in rdr.records() {
        count += 1;
        let record = record?;
        let record = record.into_iter()
            .map(|r| r.parse::<f32>().unwrap())
            .collect::<Vec<_>>();
        let record = record.get(range.clone()).unwrap().to_vec();
        match stats.entry(record.into()) {
            Entry::Occupied(mut oc) => {
                oc.get_mut().add_assign(1);
            }
            Entry::Vacant(vac) => {
                vac.insert(1);
            }
        }
    }
    let headers = headers.iter()
        .map(|&h| format!("{:^12}", h)).collect::<Vec<_>>();
    println!("{}", headers.join(" "));
    let partial = stats.iter()
        .fold(vec![0; headers.len()], |acc, (k, v)| {
            acc.into_iter().zip(k.0.iter())
                .map(|(a, r)| a + (*r as usize) * (*v))
                .collect::<Vec<_>>()
        })
        .into_iter()
        .map(|e| e as f32 / count as f32 * 100.0)
        .map(|e| format!("{:^12}", e))
        .collect::<Vec<_>>();
    println!("{}", partial.join(" "));
    for (k, v) in stats {
        let row = k.0.into_iter()
            .map(|e| format!("{:^12}", e))
            .collect::<Vec<_>>();
        println!("{}: {}", row.join(" "), v as f32 / count as f32 * 100.0);
    }
    Ok(())
}
