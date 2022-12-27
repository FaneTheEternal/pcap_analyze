#![allow(dead_code)]


use std::collections::HashMap;
use std::error::Error;
use std::fmt::Formatter;
use std::ops::{Range, RangeFrom, RangeTo};
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
mod combo;

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


pub fn print_stats<I, II>(data: II, headers: &[&str])
    where
        I: IntoIterator<Item=f32>,
        II: IntoIterator<Item=I>,
{
    let mut stats = Vec::<(Vec<f32>, usize)>::new();
    let mut count = 0;
    let width = headers.len();
    for row in data.into_iter() {
        count += 1;
        let row = row.into_iter().collect::<Vec<_>>();
        let pos = stats.iter()
            .position(|(r, _)| {
                r.iter().zip(row.iter())
                    .fold(true, |acc, (&l, &r)| acc && l == r)
            });
        let stat = if let Some(idx) = pos {
            let mut stat = stats.remove(idx);
            stat.1 += 1;
            stat
        } else {
            (row, 1)
        };
        stats.push(stat);
    }
    stats.sort_by_key(|i| format!("{:?}", i.1));
    let headers = headers.iter()
        .map(|&h| format!("{:^12}", h)).collect::<Vec<_>>();
    println!("{}", headers.join(" "));

    let partial = stats.iter()
        .fold(vec![0_f32; width], |acc, (row, cnt)| {
            acc.into_iter().zip(row)
                .map(|(a, &v)| a + v * (*cnt as f32))
                .collect::<Vec<_>>()
        })
        .into_iter()
        .map(|stat| format!("{:^12}", stat / count as f32 * 100.0))
        .collect::<Vec<_>>();
    println!("{}", partial.join(" "));
    let stats = stats.into_iter()
        .map(|(k, v)| {
            let v = (v as f32 / count as f32) * 100.0;
            let row = k.iter()
                .map(|e| format!("{:^12}", e))
                .collect::<Vec<_>>();
            println!("{}: {}", row.join(" "), v);
            (k, v)
        })
        .collect::<Vec<(Vec<f32>, f32)>>();
    let stats = stats.iter().map(|v| v.1).collect::<Vec<_>>();
    println!("Row kinds: {}", stats.len());
    let avg = stats.iter().sum::<f32>() / stats.len() as f32;
    println!("AVG: {}", avg);
    let avg_delta = stats.iter()
        .map(|&s| (s - avg).abs())
        .sum::<f32>() / stats.len() as f32;
    println!("AVG DELTA: {}", avg_delta);
}


pub fn print_csv_stats<P: AsRef<Path>>(
    path: P, range: Range<usize>, headers: &[&str],
) -> Result<(), Box<dyn Error>>
{
    assert_eq!(range.end - range.start, headers.len());

    let mut rdr = ReaderBuilder::new()
        .delimiter(b',')
        .from_path(path)?;
    let mut records = vec![];
    for record in rdr.records() {
        let record = record?;
        let record = record.into_iter()
            .map(|r| r.parse::<f32>().unwrap())
            .collect::<Vec<_>>();
        records.push(record[range.clone()].to_vec())
    }
    print_stats(records, headers);
    Ok(())
}
