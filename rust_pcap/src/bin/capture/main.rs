use std::fs::File;

use pcap::*;

use rust_pcap::counter::Count;

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

    let now = chrono::Local::now();
    let file = now.format("capture_%Y%m%d_%H%M%S.pcap").to_string();
    let mut save_file = capture.savefile(&file).unwrap();
    loop {
        if let Ok(pkt) = capture.next_packet() {
            save_file.write(&pkt);
        }
        if (chrono::Local::now() - now).num_seconds() > capture_period as i64 {
            break;
        }
    }

    let counts = Count::compute_legacy(File::open(&file).unwrap(), capture_period + 1.0);
    let stats = counts.get(0).unwrap();
    dbg!(stats);
}