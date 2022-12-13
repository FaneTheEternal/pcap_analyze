use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::ops::Mul;
use csv::ReaderBuilder;

use rand::prelude::*;

use rust_pcap::counter::Count;

fn main() -> Result<(), Box<dyn Error>> {
    let data = std::fs::read("data_set_default.csv")?;
    let mut rdr = ReaderBuilder::new()
        .delimiter(b',')
        .from_reader(data.as_slice());
    let mut default = vec![0.0; 20];
    for record in rdr.records() {
        let record = record?;
        default.iter_mut()
            .zip(record.iter())
            .for_each(|(d, r)| {
                let max = f64::max(*d, r.parse::<f64>().unwrap());
                *d = max;
            });
    }
    println!("{:?}", default);


    let mut rdr = ReaderBuilder::new()
        .delimiter(b',')
        .from_path("data_set.csv")?;
    let mut rdr2 = ReaderBuilder::new().delimiter(b',')
        .from_path("data_set_default.csv")?;
    let mut data = Vec::<Vec<f64>>::new();
    for record in rdr.records().chain(rdr2.records()) {
        let record = record?;
        let mut record = record.into_iter()
            .map(|r| r.parse::<f64>().unwrap())
            .collect::<Vec<_>>();

        let count = if record[0] > default[0] { 1.0 } else { 0.0 };

        let bytes = if record[16] > default[16] { 1.0 } else { 0.0 };

        let addresses = if record[12] > default[12] { 1.0 } else { 0.0 };

        let unreachable = if record[1] != record[2] { 1.0 } else { 0.0 };
        data.push(vec![
            record[0],  // Кол-во пакетов icmp
            record[16],  // Обьем нагрузки пакетов
            record[12],  // Разнообразие адресов
            record[1],  // количество пинг
            record[2],  // количество эхо
            record[1] - record[2],  // количество unreach
            count,  // Кол-во больше нормы
            bytes,  // Объём больше нормы
            addresses,  // Слишком на много адресов
            unreachable,  // Есть недостижимые
        ]);
    }

    let mut wrt = csv::Writer::from_path("data_set_purified.csv")?;
    for row in data {
        let row = row.into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        wrt.write_record(row)?;
    }
    wrt.flush()?;
    Ok(())
}
