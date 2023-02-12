use pcap::*;
use tracing::info;

use rust_pcap::{Codec, PcapIterator};
use rust_pcap::counter::Count;
use rust_pcap::tf::TFBuilder;

fn main() -> Result<(), Box<dyn ::std::error::Error>> {
    let format = tracing_subscriber::fmt::format()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339());
    tracing_subscriber::fmt()
        .event_format(format)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let device_name = args.get(1).unwrap();
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

    let mut nn = TFBuilder::new(6, 4)?
        .with_hidden([12])
        .build()?;

    nn.restore()?;

    let mut _printed_headers = false;
    let mut print_headers = move || {
        if !_printed_headers {
            _printed_headers = true;
            info!(
                "{}",
                [
                    "count", "size", "addresses", "req", "res", "unr",
                    "over_count", "over_size", "over_addr", "has_unr"
                ].into_iter().map(|e| format!("{:^12}", e))
                    .collect::<Vec<_>>().join("|"),
            );
        }
    };

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let mut packets = vec![];
        loop {
            if let Some(pkt) = pkt_iter.next() {
                match pkt {
                    Ok(pkt) => {
                        packets.push(pkt);
                    }
                    Err(e) => {
                        match e {
                            pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired => {
                                break;
                            }
                            _ => { dbg!(&e); }
                        }
                    }
                }
            } else {
                break;
            }
        }
        let mut stats = Count::compute(PcapIterator::new(packets), None);
        if let Some(stat) = stats.pop() {
            let row = [
                stat.total as f32,
                stat.avg_size as f32,
                stat.addresses.len() as f32,
                stat.echo_req as f32,
                stat.echo_res as f32,
                (stat.echo_req - stat.echo_res) as f32,
            ];

            let result = nn.restored_eval(&row)?;
            let result = result.into_iter()
                .map(|r| { r.max(0.0).min(1.0) })
                .collect::<Vec<_>>();
            print_headers();
            info!(
                "{}|{}",
                row.iter().map(|e| format!("{:^12}", e))
                    .collect::<Vec<_>>().join("|"),
                result.iter()
                    .map(|r| format!("{:^12}", format!("{:.3}", r)))
                    .collect::<Vec<_>>().join("|")
            );
        }
    }

    Ok(())
}