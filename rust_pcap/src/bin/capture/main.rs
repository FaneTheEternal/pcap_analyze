use pcap::*;
use tracing::info;

use rust_pcap::{Codec, default, PcapIterator};
use rust_pcap::counter::Count;
use rust_pcap::tf::{NeuralNetwork, NNContext};

fn main() -> Result<(), Box<dyn ::std::error::Error>> {
    let format = tracing_subscriber::fmt::format()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339());
    tracing_subscriber::fmt()
        .event_format(format)
        .init();

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
    let mut capture = Capture::from_device(device.clone()).unwrap()
        .immediate_mode(true)
        .open().unwrap()
        .setnonblock().unwrap();
    capture.filter("icmp", true)?;
    let mut pkt_iter = capture.iter(Codec);

    let mut model = NeuralNetwork::new(
        vec![16, 256, 128],
        0,
        0,
    );
    model.ctx.replace(NNContext {
        input: 18,
        output: 4,
        ..default()
    });
    loop {
        let mut packets = vec![];
        let now = chrono::Local::now();
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
        if counts.is_empty() {
            info!("PASS EMPTY");
            continue;
        }
        let stats = counts.get(0).unwrap();
        dbg!(stats);
        let result = model.eval(&stats.as_row())?;
        info!(
            "DELAY: {:^12} UNREACHABLE: {:^12} PAYLOAD: {:^12} RANGE: {:^12}",
            result.get(0).unwrap(),
            result.get(1).unwrap(),
            result.get(2).unwrap(),
            result.get(3).unwrap()
        );
    }
}