use std::fs::File;
use std::time::Instant;

use rust_pcap::counter::Count;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file_name = args.get(1).unwrap();
    let file = File::open(file_name).unwrap();
    let now = Instant::now();
    let counts = if file_name.ends_with(".pcapng") {
        Count::compute_ng(file, None)
    } else {
        Count::compute_legacy(file, None)
    };
    println!("Elapsed {}ms", now.elapsed().as_millis());
    let count = counts.get(0).unwrap();
    dbg!(count.total);
    dbg!(count.ip);
    dbg!(count.tcp);
    dbg!(count.udp);
    dbg!(count.icmp);
    dbg!(count.arp);
    dbg!(count.http);
    dbg!(count.dhcp);
    dbg!(count.opc_ua);
    dbg!(count.addresses.len());
    dbg!(count.ports.len());
    dbg!(count.bytes);
    dbg!(count.data_bytes);
    dbg!(count.avg_size);
    dbg!(count.avg_deltas_size);
    dbg!(count.avg_time);
    dbg!(count.avg_deltas_time);
}
