use std::collections::HashSet;
use std::fs::File;
use rust_pcap::*;

#[derive(Default)]
pub struct IPCount {
    pub null: usize,
    pub df: usize,
    pub mf: usize,
}

#[derive(Default)]
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

#[derive(Default)]
pub struct Count {
    pub total: usize,

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

    pub addresses: HashSet<[u8; 4]>,
    pub ports: HashSet<u16>,

    pub bytes: usize,
    pub data_bytes: usize,

    pub avg_size: f32,
    pub avg_deltas_size: f32,
    pub avg_time: f32,
    pub avg_deltas_time: f32,
}

impl Count {
    pub fn _compute(&mut self, sizes: &Vec<usize>, intervals: &Vec<u32>) {
        let pkt_count = sizes.len();

        self.bytes = sizes.iter().sum();
        self.avg_size = self.bytes as f32 / pkt_count as f32;
        self.avg_deltas_size = sizes.iter()
            .map(|&s| (self.avg_size - s as f32).abs())
            .sum::<f32>() / pkt_count as f32;

        self.avg_time = intervals.iter().sum::<u32>() as f32
            / intervals.len() as f32;
        self.avg_deltas_time = intervals.iter()
            .map(|&t| (self.avg_time - t as f32).abs())
            .sum::<f32>() / intervals.len() as f32;
    }

    pub fn compute(file: File) -> Vec<Count> {
        let mut counts = Vec::new();

        let mut count = Self::default();

        let mut sizes = Vec::new();

        let mut start = None;
        let mut last = None;

        let mut intervals = Vec::new();

        iter_over_pcapng(file, |frame| {
            count.total += 1;

            if let Some(time) = last {
                intervals.push(frame.ts_sec - time)
            } else {
                start = Some(frame.ts_sec);
                last = Some(frame.ts_sec);
            }

            sizes.push(frame.data.len());

            if let Some(ip) = frame.get_layer::<IPv4>() {
                count.ip += 1;
                if ip.flags.null { count.ip_flags.null += 1 }
                if ip.flags.df { count.ip_flags.df += 1 }
                if ip.flags.mf { count.ip_flags.mf += 1 }
                count.addresses.insert(ip.src);
                count.addresses.insert(ip.dst);
            }
            if let Some(icmp) = frame.get_layer::<ICMP>() {
                count.icmp += 1;
            }
            if let Some(tcp) = frame.get_layer::<TCP>() {
                count.tcp += 1;
                if tcp.flags.ns { count.tcp_flags.ns += 1 }
                if tcp.flags.cwr { count.tcp_flags.cwr += 1 }
                if tcp.flags.ece { count.tcp_flags.ece += 1 }
                if tcp.flags.urg { count.tcp_flags.urg += 1 }
                if tcp.flags.ack { count.tcp_flags.ack += 1 }
                if tcp.flags.psh { count.tcp_flags.psh += 1 }
                if tcp.flags.rst { count.tcp_flags.rst += 1 }
                if tcp.flags.syn { count.tcp_flags.syn += 1 }
                if tcp.flags.fin { count.tcp_flags.fin += 1 }
                count.ports.insert(tcp.src);
                count.ports.insert(tcp.dst);
                count.data_bytes += tcp.data.len();
            }
            if let Some(udp) = frame.get_layer::<UDP>() {
                count.udp += 1;
                count.data_bytes += udp.payload.len();
            }
            if let Some(arp) = frame.get_layer::<ARP>() {
                count.arp += 1;
            }
            if let Some(http) = frame.get_layer::<HTTP>() {
                count.http += 1;
            }
            if let Some(dhcp) = frame.get_layer::<DHCP>() {
                count.dhcp += 1;
            }

            if frame.ts_sec - start.unwrap() > 2 {
                count._compute(&sizes, &intervals);
                counts.push(std::mem::replace(&mut count, Self::default()));

                start = None;
                last = None;
                intervals.clear();
                sizes.clear();
            }

            false
        });
        if sizes.len() > 1 {
            count._compute(&sizes, &intervals);
            counts.push(count);
        }
        counts
    }
}