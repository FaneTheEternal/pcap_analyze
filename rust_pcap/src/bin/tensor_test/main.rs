mod nn;
mod counter;

use std::collections::HashSet;
use std::env;
use std::error::Error;
use pcap_parser::*;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Instant;
use rand::prelude::*;
use rust_pcap::*;

use tensorflow::{
    ops,
    train::{AdadeltaOptimizer, MinimizeOptions, Optimizer},
    Code,
    DataType,
    Graph,
    Output,
    OutputName,
    SavedModelBundle,
    Scope,
    Session,
    SessionOptions,
    SessionRunArgs,
    Shape,
    SignatureDef,
    Status,
    Tensor,
    TensorInfo,
    Variable,
    REGRESS_INPUTS, REGRESS_METHOD_NAME, REGRESS_OUTPUTS,
};
use crate::counter::Count;
use crate::nn::{eval, train};

fn main() -> Result<(), Box<dyn Error>> {
    const WANNA_TRAIN: bool = true;  // or else eval

    let normal = File::open("pingNormal.pcapng").unwrap();
    let normal = Count::compute(normal);
    let not_normal = File::open("pingNotNormal.pcapng").unwrap();
    let not_normal = Count::compute(not_normal);
    let unreachable = File::open("pingUnreachable.pcapng").unwrap();
    let unreachable = Count::compute(unreachable);

    const TRUE: f32 = 100.0;
    const FALSE: f32 = 10.0;

    let mut data_set: Vec<(Count, (f32, f32, f32))> = normal.into_iter()
        .map(|e| (e, (TRUE, FALSE, FALSE)))
        .chain(not_normal.into_iter()
            .map(|e| (e, (FALSE, TRUE, FALSE))))
        .chain(unreachable.into_iter()
            .map(|e| (e, (FALSE, FALSE, TRUE))))
        .collect();
    let mut rng = thread_rng();
    data_set.shuffle(&mut rng);
    println!("TOTAL {} ROWS", data_set.len());

    let data: Vec<([f32; 9], (f32, f32, f32))> = data_set.into_iter()
        .map(|(d, res)| {
            let row = [
                d.addresses.len() as f32,
                d.ports.len() as f32,
                d.total as f32,
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
        .collect();

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