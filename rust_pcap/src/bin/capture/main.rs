use pcap::*;

use rust_pcap::counter::Count;
use rust_pcap::{Codec, PcapIterator};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let device_name = args.get(1).unwrap();
    let capture_period = args.get(2).unwrap()
        .parse::<f64>().unwrap();
    let device = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.desc.as_ref().unwrap().contains(device_name))
        .unwrap();
    println!("{:?}", device);
    let mut capture = Capture::from_device(device).unwrap()
        .immediate_mode(true)
        .open().unwrap()
        .setnonblock().unwrap();

    let mut packets = vec![];
    let now = chrono::Local::now();
    let mut pkt_iter = capture.iter(Codec);
    loop {
        if let Some(pkt) = pkt_iter.next() {
            if let Ok(pkt) = pkt {
                packets.push(pkt);
            }
        }
        if (chrono::Local::now() - now).num_seconds() > capture_period as i64 {
            break;
        }
    }

    let counts = Count::compute(
        PcapIterator::new(packets),
        capture_period + 1.0,
    );
    let stats = counts.get(0).unwrap();
    dbg!(stats);
}