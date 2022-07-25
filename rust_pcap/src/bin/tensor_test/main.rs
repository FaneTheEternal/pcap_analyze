use std::error::Error;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};

use rand::prelude::*;
use rayon::prelude::*;
use tensorflow::train::AdadeltaOptimizer;
use tracing::error;

use rust_pcap::counter::Count;

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
    let normal = Count::compute(normal, PERIOD);
    let not_normal = File::open("ping_not_normal.pcapng").unwrap();
    let not_normal = Count::compute(not_normal, PERIOD);
    let unreachable = File::open("ping_unreachable.pcapng").unwrap();
    let unreachable = Count::compute(unreachable, PERIOD);

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
    let out = Count::compute_legacy(out, PERIOD);

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

    // let mut data_set = read3();
    let mut data_set = read_generated();
    let mut rng = thread_rng();
    data_set.shuffle(&mut rng);
    println!("TOTAL {} ROWS", data_set.len());

    let data = data_set.into_iter()
        .map(|(d, res)| {
            let row = [
                d.total as f32,
                d.echo_req as f32,
                d.echo_res as f32,
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

    let word = WORD::new((2..=9).collect(), 3);

    let mut state = State::get();
    if !state.is_done("Model".into()) {
        state.append(
            vec!["Model",
                 "error squared 1", "error squared 2", "error squared 3", "error squared 4",
                 "check error 1", "check error 1", "check error 1", "check error 1"]
        )?;
    }

    rayon::ThreadPoolBuilder::new().num_threads(
        std::env::var("NUM_THREADS").map_or(2, |s| s.parse::<usize>().unwrap())
    ).build_global()?;
    let state = Arc::new(Mutex::new(state));
    let configs = word.into_iter()
        .map(|w| {
            w.into_iter().map(|e| 2u64.pow(e)).collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let g_result: Vec<Result<(), Box<dyn Error + Send + Sync>>> = configs.into_par_iter().map(|h| {
        let mut model = GenericNeuralNetwork::new(
            &h,
            1_000,
            100,
            Box::new(AdadeltaOptimizer::new()),
        );
        if state.lock().unwrap().is_done(model.name()) {
            return Ok(());
        }
        const CONTROL: usize = 3;
        let mut avg = Vec::new();
        for _ in 0..CONTROL {
            q_del(model.model_path()).fix_box()?;
            let errors = model.train(&train_data).fix_box()?;
            let error = errors.into_iter().last().unwrap();
            let check = model.check(&eval_data).fix_box()?;
            avg.push(error.into_iter().chain(check).collect::<Vec<_>>())
        }
        let mut row = avg.into_iter()
            .fold(vec![0f32; 8], |acc, e| {
                acc.into_iter().zip(e)
                    .map(|(a, e)| a + e)
                    .collect::<Vec<_>>()
            })
            .into_iter()
            .map(|e| (e / CONTROL as f32).to_string())
            .collect::<Vec<_>>();
        row.insert(0, model.name());
        state.lock().unwrap().append(row).fix_box()?;
        Ok(())
    }).collect::<Vec<_>>();

    let g_result = g_result.into_iter()
        .filter_map(|r| {
            match r {
                Ok(_) => { None }
                Err(e) => { Some(e) }
            }
        })
        .collect::<Vec<_>>();
    if g_result.is_empty() {
        let state = Arc::try_unwrap(state).unwrap();
        csv::csv_write_file("3.csv", state.into_inner().unwrap())?;
    } else {
        for e in g_result {
            error!("{}", e);
        }
    }

    Ok(())
}