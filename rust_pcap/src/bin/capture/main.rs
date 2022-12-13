use std::io::Write;
use pcap::*;
use rand::{Rng, thread_rng};
use rand::rngs::ThreadRng;
use tracing::info;

use rust_pcap::{Codec, default, PcapIterator};
use rust_pcap::counter::Count;
use rust_pcap::tf::{NeuralNetwork, NNContext};

const RNG: bool = true;

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
        .parse::<i64>().unwrap();
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

    let mut packets = vec![];
    let start = chrono::Local::now();

    let addresses = if RNG { ADDRESSES } else { ADDRESSES.get(..5).unwrap() };
    let pinger = Pinger::new(addresses);

    loop {
        let now = chrono::Local::now();
        let elapsed = (now - start).num_seconds();
        if elapsed > capture_period {
            break;
        }
        if RNG {
            pinger.ping(PingerRNG::default())?;
        } else {
            pinger.ping(PingerDefault)?;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
        loop {
            if let Some(pkt) = pkt_iter.next() {
                match pkt {
                    Ok(pkt) => {
                        packets.push(pkt);
                    }
                    Err(e) => {
                        match e {
                            Error::NoMorePackets | Error::TimeoutExpired => {
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
        info!("{}/{}; Pick {} packets", elapsed, capture_period, packets.len());
    }
    let counts = Count::compute(PcapIterator::new(packets), Some(3.0));
    // dbg!(counts);

    let path = if RNG { "data_set.csv" } else { "data_set_default.csv" };
    let mut wtr = csv::Writer::from_path(path)?;
    {
        wtr.write_record([
            "total",
            "echo_req",
            "echo_res",
            "ip",
            "icmp",
            "tcp",
            "udp",
            "arp",
            "http",
            "smtp",
            "dhcp",
            "opc_ua",
            "addresses",
            "ports",
            "bytes",
            "data_bytes",
            "avg_size",
            "avg_deltas_size",
            "avg_time",
            "avg_deltas_time",
        ])?;
    }
    for count in counts {
        let row = [
            count.total as f32,
            count.echo_req as f32,
            count.echo_res as f32,
            count.ip as f32,
            count.icmp as f32,
            count.tcp as f32,
            count.udp as f32,
            count.arp as f32,
            count.http as f32,
            count.smtp as f32,
            count.dhcp as f32,
            count.opc_ua as f32,
            count.addresses.len() as f32,
            count.ports.len() as f32,
            count.bytes as f32,
            count.data_bytes as f32,
            count.avg_size,
            count.avg_deltas_size,
            count.avg_time,
            count.avg_deltas_time,
        ];
        wtr.write_record(row.map(|e| e.to_string()))?;
    }
    Ok(())
}

const ADDRESSES: &'static [&str] = &[
    "192.168.50.157",
    "192.168.50.11",
    "192.168.50.50",
    "182.168.50.52",
    "182.168.50.54",
    "182.168.50.55",
    "182.168.50.56",
];

struct Pinger {
    addresses: Vec<String>,
}

impl Pinger {
    fn new<I, V>(addresses: I) -> Self
        where V: ToString, I: IntoIterator<Item=V>
    {
        Self {
            addresses: addresses.into_iter()
                .map(|i| i.to_string())
                .collect()
        }
    }

    fn ping(&self, mut params: impl PingerParams) -> Result<(), Box<dyn ::std::error::Error>> {
        let pings = self.addresses.iter()
            .filter_map(|addr| {
                if params.should_ping() {
                    let mut cmd = std::process::Command::new("ping");
                    cmd.arg(addr);
                    cmd.args(["-n", &params.num().to_string()]);
                    if let Some(payload) = params.payload() {
                        cmd.args(["-l", &payload.to_string()]);
                    }
                    cmd.stdout(std::process::Stdio::piped());
                    cmd.stderr(std::process::Stdio::piped());
                    Some(cmd.spawn().unwrap())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for ping in pings {
            // let output = ping.wait_with_output()?;
            // std::io::stdout().write_all(&output.stdout)?;
            // std::io::stderr().write_all(&output.stderr)?;
        }
        Ok(())
    }
}

trait PingerParams {
    fn should_ping(&mut self) -> bool { true }
    fn num(&mut self) -> usize { 4 }
    fn payload(&mut self) -> Option<usize> { None }
}

struct PingerDefault;

impl PingerParams for PingerDefault {}


struct PingerRNG {
    rng: ThreadRng,
}

impl Default for PingerRNG {
    fn default() -> Self {
        Self { rng: Default::default() }
    }
}

impl PingerParams for PingerRNG {
    fn should_ping(&mut self) -> bool {
        self.rng.gen_bool(1.0 / 3.0)
    }

    fn num(&mut self) -> usize {
        self.rng.gen_range(1..16)
    }

    fn payload(&mut self) -> Option<usize> {
        Some(self.rng.gen_range(1..512))
    }
}
