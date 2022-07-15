use std::error::Error;
use std::fs::File;
use std::io::Read;

use rand::prelude::*;

use rust_pcap::counter::Count;

const PERIOD: f64 = 2.0;

fn main() -> Result<(), Box<dyn Error>> {
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
    let mut data_set = out.into_iter()
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
        .collect::<Vec<_>>();

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
            row.into_iter().chain(res).map(|e| e.to_string()).collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut wtr = csv::Writer::from_path("data_set.csv")?;
    wtr.write_record([
        "total", "ip", "icmp", "tcp", "udp", "arp", "smtp", "dhcp",
        "addresses", "ports", "bytes", "data_bytes",
        "avg_size", "avg_deltas_size", "avg_time", "avg_deltas_time",
        "DELAY", "UNREACHABLE", "PAYLOAD", "RANGE",
    ])?;
    for row in data {
        wtr.write_record(row)?;
    }
    Ok(())
}
