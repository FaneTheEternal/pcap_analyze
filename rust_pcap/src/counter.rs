use std::collections::HashSet;
use std::fs::File;

use derivative::Derivative;

use crate::*;

#[derive(Default, Debug)]
pub struct IPCount {
    pub null: usize,
    pub df: usize,
    pub mf: usize,
}

#[derive(Default, Debug)]
pub struct TCPCount {
    pub ns: usize,
    pub cwr: usize,
    pub ece: usize,
    pub urg: usize,
    pub ack: usize,
    pub psh: usize,
    pub rst: usize,
    pub syn: usize,
    pub fin: usize,
}

fn _count_fmt<T>(
    iter: &HashSet<T>,
    fmt: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error>
{
    write!(fmt, "{}", iter.len())
}

#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct Count {
    pub total: usize,
    pub echo_req: usize,
    pub echo_res: usize,

    pub ip: usize,
    pub ip_flags: IPCount,
    pub icmp: usize,
    pub tcp: usize,
    pub tcp_flags: TCPCount,
    pub udp: usize,
    pub arp: usize,
    pub http: usize,
    pub smtp: usize,
    pub dhcp: usize,

    #[derivative(Debug(format_with = "_count_fmt"))]
    pub addresses: HashSet<[u8; 4]>,
    #[derivative(Debug(format_with = "_count_fmt"))]
    pub ports: HashSet<u16>,

    pub bytes: usize,
    pub data_bytes: usize,

    pub avg_size: f32,
    pub avg_deltas_size: f32,
    pub avg_time: f32,
    pub avg_deltas_time: f32,
}

impl Count {
    pub fn flush(&mut self, sizes: &mut Vec<usize>, intervals: &mut Vec<f64>) -> Self {
        let pkt_count = sizes.len();

        self.bytes = sizes.iter().sum();
        self.avg_size = self.bytes as f32 / pkt_count as f32;
        self.avg_deltas_size = sizes.iter()
            .map(|&s| (self.avg_size - s as f32).abs())
            .sum::<f32>() / pkt_count as f32;

        self.avg_time = intervals.iter().sum::<f64>() as f32
            / intervals.len().max(1) as f32;
        self.avg_deltas_time = intervals.iter()
            .map(|&t| (self.avg_time - t as f32).abs())
            .sum::<f32>() / intervals.len().max(1) as f32;
        sizes.clear();
        intervals.clear();
        std::mem::replace(self, Count::default())
    }

    pub fn apply(&mut self, frame: &Frame) {
        self.total += 1;
        if let Some(ip) = frame.get_layer::<IPv4>() {
            self.ip += 1;
            if ip.flags.null { self.ip_flags.null += 1 }
            if ip.flags.df { self.ip_flags.df += 1 }
            if ip.flags.mf { self.ip_flags.mf += 1 }
            self.addresses.insert(ip.src);
            self.addresses.insert(ip.dst);
        }
        if let Some(icmp) = frame.get_layer::<ICMP>() {
            self.icmp += 1;
            if let ICMPData::Echo { kind, .. } = &icmp.data {
                match kind {
                    Echo::Request => { self.echo_req += 1 }
                    Echo::Response => { self.echo_res += 1 }
                }
            }
        }
        if let Some(tcp) = frame.get_layer::<TCP>() {
            self.tcp += 1;
            if tcp.flags.ns { self.tcp_flags.ns += 1 }
            if tcp.flags.cwr { self.tcp_flags.cwr += 1 }
            if tcp.flags.ece { self.tcp_flags.ece += 1 }
            if tcp.flags.urg { self.tcp_flags.urg += 1 }
            if tcp.flags.ack { self.tcp_flags.ack += 1 }
            if tcp.flags.psh { self.tcp_flags.psh += 1 }
            if tcp.flags.rst { self.tcp_flags.rst += 1 }
            if tcp.flags.syn { self.tcp_flags.syn += 1 }
            if tcp.flags.fin { self.tcp_flags.fin += 1 }
            self.ports.insert(tcp.src);
            self.ports.insert(tcp.dst);
            self.data_bytes += tcp.data.len();
        }
        if let Some(udp) = frame.get_layer::<UDP>() {
            self.udp += 1;
            self.data_bytes += udp.payload.len();
        }
        if let Some(_arp) = frame.get_layer::<ARP>() {
            self.arp += 1;
        }
        if let Some(http) = frame.get_layer::<HTTP>() {
            if http.is_finalized {
                self.http += 1;
            }
        }
        if let Some(_dhcp) = frame.get_layer::<DHCP>() {
            self.dhcp += 1;
        }
    }

    pub fn compute_ng(file: File, period: f64) -> Vec<Count> {
        Self::compute(PcapNG::new(file), period)
    }

    pub fn compute_legacy(file: File, period: f64) -> Vec<Count> {
        Self::compute(Pcap::new(file), period)
    }

    pub fn compute(pcap: impl Iterator<Item=Frame>, period: f64) -> Vec<Count> {
        let mut counter = 0usize;

        let mut counts = Vec::new();

        let mut count = Count::default();

        let mut sizes = Vec::new();

        let mut _first = None;
        let mut _last = None;

        let mut start = None;
        let mut last = None;

        let mut intervals = Vec::new();

        for frame in pcap {
            _first.get_or_insert(frame.ts);
            _last = Some(frame.ts);
            counter += 1;

            if start.is_none() {
                start = Some(frame.ts);
            } else {
                let mut diff = frame.ts - start.unwrap();
                if diff > period {
                    // println!("FLUSH {} with {} of {}", counts.len(), count.total, counter);
                    counts.push(count.flush(&mut sizes, &mut intervals));
                    diff -= period;
                    while diff > period {
                        diff -= period;
                        counts.push(Count::default());
                    }
                    start = Some(frame.ts - diff);
                    last = None;
                }
            }
            if let Some(last) = last {
                intervals.push(frame.ts - last);
            }
            last = Some(frame.ts);
            sizes.push(frame.data.len());
            count.apply(&frame);
        }

        if !sizes.is_empty() {
            counts.push(count.flush(&mut sizes, &mut intervals));
        }
        // println!("COUNTS EXPECT TOTAL PERIOD {}", _last.unwrap() - _first.unwrap());
        // println!("COUNTS COMPUTE TOTAL PERIOD {}", counts.len() * period as usize);
        println!("COUNTS APPLY {} FRAMES", counter);
        counts
    }

    pub fn as_row(&self) -> Vec<f32> {
        vec![
            self.total as f32,
            self.echo_req as f32,
            self.echo_res as f32,
            self.ip as f32,
            self.icmp as f32,
            self.tcp as f32,
            self.udp as f32,
            self.arp as f32,
            self.smtp as f32,
            self.dhcp as f32,
            self.addresses.len() as f32,
            self.ports.len() as f32,
            self.bytes as f32,
            self.data_bytes as f32,
            self.avg_size,
            self.avg_deltas_size,
            self.avg_time,
            self.avg_deltas_time,
        ]
    }
}