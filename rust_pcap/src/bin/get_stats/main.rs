use std::fs::File;
use std::time::Instant;

use rust_pcap::counter::Count;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file = File::open(args.get(1).unwrap()).unwrap();
    let now = Instant::now();
    let counts = Count::compute_legacy(file, 1000000.0);
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
    dbg!(count.addresses.len());
    dbg!(count.ports.len());
    dbg!(count.bytes);
    dbg!(count.data_bytes);
    dbg!(count.avg_size);
    dbg!(count.avg_deltas_size);
    dbg!(count.avg_time);
    dbg!(count.avg_deltas_time);
}
