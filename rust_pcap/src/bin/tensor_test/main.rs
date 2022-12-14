use std::error::Error;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
use ::csv::ReaderBuilder;

use rand::prelude::*;
use rayon::prelude::*;
use tensorflow::train::AdadeltaOptimizer;
use tracing::error;

use rust_pcap::counter::Count;
use rust_pcap::tf::NeuralNetwork;

use crate::combo::WORD;
use crate::nn::{GenericNeuralNetwork};
use crate::profile::*;

mod nn;
mod profile;
mod csv;
mod combo;

const PERIOD: f64 = 2.0;

#[allow(dead_code)]
fn read3() -> Vec<(Count, [f32; 3])> {
    let normal = File::open("ping_normal.pcapng").unwrap();
    let normal = Count::compute_ng(normal, Some(PERIOD));
    let not_normal = File::open("ping_not_normal.pcapng").unwrap();
    let not_normal = Count::compute_ng(not_normal, Some(PERIOD));
    let unreachable = File::open("ping_unreachable.pcapng").unwrap();
    let unreachable = Count::compute_ng(unreachable, Some(PERIOD));

    const TRUE: f32 = 100.0;
    const FALSE: f32 = 0.0;

    normal.into_iter()
        .map(|e| (e, [TRUE, FALSE, FALSE]))
        .chain(not_normal.into_iter()
            .map(|e| (e, [FALSE, TRUE, FALSE])))
        .chain(unreachable.into_iter()
            .map(|e| (e, [FALSE, FALSE, TRUE])))
        .collect::<Vec<_>>()
}

#[allow(dead_code)]
fn read_generated() -> Vec<(Count, [f32; 4])> {
    const DELAY: u8 = 0b0100;
    const UNREACHABLE: u8 = 0b1000;
    const PAYLOAD: u8 = 0b0010;
    const RANGE: u8 = 0b0001;

    let mut out = File::open("out.txt").unwrap();
    let mut out_target = String::new();
    out.read_to_string(&mut out_target).unwrap();
    let out_target = out_target
        .split("\r\n")
        .filter(|e| !e.is_empty())
        .map(|e| e.parse::<u8>().unwrap())
        .map(|e| [
            if e & DELAY > 0 { 1.0 } else { 0.0 },
            if e & UNREACHABLE > 0 { 1.0 } else { 0.0 },
            if e & PAYLOAD > 0 { 1.0 } else { 0.0 },
            if e & RANGE > 0 { 1.0 } else { 0.0 },
        ])
        .collect::<Vec<_>>();

    let out = File::open("out.pcap").unwrap();
    let out = Count::compute_legacy(out, Some(PERIOD));

    let mut offset = 0usize;
    out.into_iter()
        .map(|c| {
            let before = offset + c.total;
            let target = out_target.get(offset..before).unwrap();
            offset = before;
            // let target_len = target.len() as f32;
            // (c, [
            //     target.iter().map(|&t| t[0]).sum::<f32>() / target_len,
            //     target.iter().map(|&t| t[1]).sum::<f32>() / target_len,
            //     target.iter().map(|&t| t[2]).sum::<f32>() / target_len,
            //     target.iter().map(|&t| t[3]).sum::<f32>() / target_len,
            // ])

            let target = target.into_iter()
                .fold([0.0; 4], |acc, &r| {
                    [
                        (acc[0] as u8 | r[0] as u8) as f32,
                        (acc[1] as u8 | r[1] as u8) as f32,
                        (acc[2] as u8 | r[2] as u8) as f32,
                        (acc[3] as u8 | r[3] as u8) as f32,
                    ]
                });
            (c, target)
        })
        .collect()
}

fn q_del<P: AsRef<Path>>(path: P) -> Result<(), Box<dyn Error>> {
    match std::fs::remove_dir_all(path.as_ref()) {
        Err(e) => {
            if e.kind() != ErrorKind::NotFound {
                return Err(Box::new(e));
            }
        }
        Ok(_) => {}
    };
    Ok(())
}

trait FixBoxError<T> {
    fn fix_box(self) -> Result<T, Box<dyn Error + Send + Sync>>;
}

impl<T> FixBoxError<T> for Result<T, Box<dyn Error>> {
    fn fix_box(self) -> Result<T, Box<dyn Error + Send + Sync>> {
        match self {
            Err(err) => Err(err.to_string().into()),
            Ok(t) => Ok(t),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let format = tracing_subscriber::fmt::format()
        .with_target(false);
    tracing_subscriber::fmt()
        .event_format(format)
        .init();

    let mut data = vec![];
    const FILE: &str = "data_set_purified.csv";
    // const FILE: &str = "data_set_generated.csv";
    rust_pcap::print_stats(
        FILE, 6..10,
        &["over_count", "over_size", "over_addr", "has_unr"]
    )?;
    let mut rdr = ReaderBuilder::new()
        .delimiter(b',')
        .from_path(FILE)?;
    for record in rdr.records() {
        let record = record?;
        let record = record.into_iter()
            .map(|r| r.parse::<f32>().unwrap())
            .collect::<Vec<_>>();
        data.push((
            record.get(..6).unwrap().to_vec(),
            record.get(6..).unwrap().to_vec(),
        ));
    }
    let mut rng = thread_rng();
    data.shuffle(&mut rng);

    let mut nn = NeuralNetwork::new(
        [24, 48, 24],
        10000,
        25,
    );

    let split = (data.len() as f32 * 1.0) as usize;
    let train = data.get(..split).unwrap();
    nn.train(train)?;

    Ok(())
}