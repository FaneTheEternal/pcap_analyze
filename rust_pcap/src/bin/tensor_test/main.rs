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
    // const FILE: &str = "data_set_purified.csv";
    const FILE: &str = "data_set_generated.csv";
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
        [12, 12],
        1000,
        25,
    );

    let split = (data.len() as f32 * 1.0) as usize;
    let train = data.get(..split).unwrap();
    q_del(nn.model_path())?;
    nn.train(train)?;

    Ok(())
}