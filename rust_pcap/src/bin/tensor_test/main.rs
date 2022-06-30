mod nn;
mod counter;
mod profile;

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
use tensorflow::train::AdadeltaOptimizer;
use rust_pcap::*;

use crate::counter::Count;
use crate::nn::{eval, train, gtrain, GenericNeuralNetwork};
use crate::profile::LearnInstance;

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
            if e & DELAY > 0 { 1.0 } else { 0.0 },
            if e & UNREACHABLE > 0 { 1.0 } else { 0.0 },
            if e & PAYLOAD > 0 { 1.0 } else { 0.0 },
            if e & RANGE > 0 { 1.0 } else { 0.0 },
        ])
        .collect::<Vec<_>>();

    let out = File::open("out.cap").unwrap();
    let out = Count::compute_legacy(out);

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
                        (acc[0] as u8 & r[0] as u8) as f32,
                        (acc[1] as u8 & r[1] as u8) as f32,
                        (acc[2] as u8 & r[2] as u8) as f32,
                        (acc[3] as u8 & r[3] as u8) as f32,
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

fn main() -> Result<(), Box<dyn Error>> {
    let format = tracing_subscriber::fmt::format()
        .with_target(false);
    tracing_subscriber::fmt()
        .event_format(format)
        .init();

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
            // println!("{:?}", res);
            (row, res)
        })
        .collect::<Vec<_>>();

    let split = (data.len() as f32 * 0.8) as usize;
    let train_data = data.get(..split).unwrap();
    let eval_data = data.get(split..).unwrap();

    let model = GenericNeuralNetwork::new(
        &[4],
        500,
        100,
        Box::new(AdadeltaOptimizer::new()),
    );
    model.train(&train_data)?;
    model.check(&eval_data)?;
    Ok(())
}