mod nn;
mod counter;

use std::collections::HashSet;
use std::env;
use std::error::Error;
use pcap_parser::*;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::time::Instant;
use rand::prelude::*;
use rust_pcap::*;

use crate::counter::Count;
use crate::nn::{eval, train};

fn read3() -> Vec<(Count, [f32; 3])> {
    let normal = File::open("ping_normal.pcapng").unwrap();
    let normal = Count::compute(normal);
    let not_normal = File::open("ping_not_normal.pcapng").unwrap();
    let not_normal = Count::compute(not_normal);
    let unreachable = File::open("ping_unreachable.pcapng").unwrap();
    let unreachable = Count::compute(unreachable);

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
            if e & DELAY > 0 {1.0} else {0.0},
            if e & UNREACHABLE > 0 {1.0} else {0.0},
            if e & PAYLOAD > 0 {1.0} else {0.0},
            if e & RANGE > 0 {1.0} else {0.0},
        ])
        .collect::<Vec<_>>();

    let out = File::open("out.cap").unwrap();
    let out = Count::compute_legacy(out);

    out.into_iter()
        .zip(out_target.into_iter())
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    // let mut data_set = read3();
    let mut data_set = read_generated();
    let mut rng = thread_rng();
    data_set.shuffle(&mut rng);
    println!("TOTAL {} ROWS", data_set.len());

    let data = data_set.into_iter()
        .map(|(d, res)| {
            let row = [
                d.total as f32,
                d.ip as f32,
                d.icmp as f32,
                d.tcp as f32,
                d.udp as f32,
                d.arp as f32,
                d.smtp as f32,
                d.dhcp as f32,
                d.addresses.len() as f32,
                d.ports.len() as f32,
                d.bytes as f32,
                d.data_bytes as f32,
                d.avg_size,
                d.avg_deltas_size,
                d.avg_time,
                d.avg_deltas_time,
            ];
            // println!("{:?}", row);
            (row, res)
        })
        .collect::<Vec<_>>();

    let mut model_path = env::temp_dir();
    model_path.push("tf-pcapgn-analyze-model");
    match std::fs::remove_dir_all(&model_path) {
        Err(e) => {
            if e.kind() != ErrorKind::NotFound {
                return Err(Box::new(e));
            }
        }
        Ok(_) => {}
    }
    train(&model_path, data.as_slice())?;
    Ok(())
}