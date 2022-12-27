use std::error::Error;
use std::io::ErrorKind;
use std::ops::Add;
use std::path::Path;

use ::csv::ReaderBuilder;

use rand::prelude::*;

use rust_pcap::default;
use rust_pcap::tf::{TFBuilder, TrainConfig};

mod csv;

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
    const HEADERS: &[&str] = &["over_count", "over_size", "over_addr", "has_unr"];
    rust_pcap::print_csv_stats(
        FILE, 6..10,
        HEADERS,
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

    let mut nn = TFBuilder::new(6, 4)?
        .with_hidden([12])
        .build()?;

    let train_cfg = TrainConfig {
        epoch: 1000,
        capture_period: 12,
    };

    let split = (data.len() as f32 * 0.9) as usize;
    let train = data.get(..split).unwrap();
    let errors = nn.train(&train_cfg, train)?;
    if let Some(errors) = errors.last() {
        let avg_error = errors.iter()
            .fold(0.0, |acc, i| acc.add(i)) / errors.len() as f32;
        let avg_error = avg_error.sqrt();
        println!("Train accuracies: {}", 1.0 - avg_error);
    }
    q_del(nn.name())?;
    nn.save(nn.name())?;

    let test = data.get(split..).unwrap();
    println!("Test data: {}", test.len());
    let mut test_errors = vec![];
    let mut test_stats = vec![];
    let mut printed_headers = false;
    let mut print_headers = move || {
        if !printed_headers {
            printed_headers = true;
            println!("count size addresses req res unr");
        }
    };
    for (row, target) in test {
        // let result = nn.eval(row)?;
        let result = nn.restored_eval(row)?;
        let error = target.into_iter().zip(&result)
            .map(|(&t, &r)| (t - r).abs())
            .collect::<Vec<_>>();

        let stat_flag = error.iter()
            .map(|&v| if v >= 0.5 { 1.0 } else { 0.0 })
            .collect::<Vec<_>>();
        test_stats.push(stat_flag);

        let error = error.iter().sum::<f32>() / result.len() as f32;
        if error >= 0.5 {
            print_headers();
            println!("{:?}", row);
        }
        test_errors.push(error);
    }
    let avg_test_error = test_errors.iter().sum::<f32>() / test_errors.len() as f32;
    println!("Test accuracies: {}", 1.0 - avg_test_error);
    rust_pcap::print_stats(test_stats, HEADERS);
    Ok(())
}