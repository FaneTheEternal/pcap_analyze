use std::fs::File;

use rust_pcap::*;
use rust_pcap::counter::Count;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file = File::open(args.get(1).unwrap()).unwrap();
    let mut pkt_sizes = Vec::new();
    let mut last_time = None;
    let mut pkt_times = Vec::new();

    let mut count = Count::default();
    // for frame in PcapNG::new(file) {
    for frame in Pcap::new(file) {
        pkt_sizes.push(frame.data.len());
        if let Some(time) = last_time {
            pkt_times.push(time - frame.ts);
        }
        last_time = Some(frame.ts);

        count.apply(frame);
    }
    let count = count.flush(&mut pkt_sizes, &mut pkt_times);
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
