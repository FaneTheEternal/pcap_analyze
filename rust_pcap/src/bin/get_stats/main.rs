use std::collections::HashSet;
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::time::Instant;
use rust_pcap::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file = File::open(args.get(1).unwrap()).unwrap();
    let mut num_blocks = 0usize;
    let mut ip_count = 0;
    let mut tcp_count = 0;
    let mut udp_count = 0;
    let mut icmp_count = 0;
    let mut arp_count = 0;
    let mut http_count = 0;
    let mut dhcp_count = 0;
    let mut addresses = HashSet::new();
    let mut ports = HashSet::new();
    let mut data_bytes = 0;
    let mut pkt_sizes = Vec::new();
    let mut last_time = None;
    let mut pkt_times = Vec::new();
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        println!("{hdr:?}")
                    }
                    PcapBlockOwned::Legacy(b) => {
                        pkt_sizes.push(b.data.len());
                        if let Some(time) = last_time {
                            pkt_times.push(time - b.ts_sec);
                        }
                        last_time = Some(b.ts_sec);

                        let frame = Frame::new(b.data);
                        // let eth = frame.get_layer::<Ethernet>().unwrap();
                        if let Some(ipv4) = frame.get_layer::<IPv4>() {
                            ip_count += 1;
                            addresses.insert(ipv4.src);
                            addresses.insert(ipv4.dst);
                        }
                        if let Some(udp) = frame.get_layer::<UDP>() {
                            udp_count += 1;
                            data_bytes += udp.payload.len();
                        }
                        if let Some(tcp) = frame.get_layer::<TCP>() {
                            tcp_count += 1;
                            ports.insert(tcp.src);
                            ports.insert(tcp.dst);
                            data_bytes += tcp.data.len();
                        }
                        if let Some(_) = frame.get_layer::<ICMP>() {
                            icmp_count += 1;
                        }
                        if let Some(_) = frame.get_layer::<ARP>() {
                            arp_count += 1;
                        }
                        if let Some(_) = frame.get_layer::<HTTP>() {
                            http_count += 1;
                        }
                        if let Some(_) = frame.get_layer::<DHCP>() {
                            dhcp_count += 1;
                        }
                        // break;
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    dbg!(num_blocks);
    dbg!(ip_count);
    dbg!(tcp_count);
    dbg!(udp_count);
    dbg!(icmp_count);
    dbg!(arp_count);
    dbg!(http_count);
    dbg!(dhcp_count);
    dbg!(addresses.len());
    dbg!(ports.len());
    let bytes: usize = pkt_sizes.iter().sum();
    dbg!(bytes);
    dbg!(data_bytes);
    let avg_size = bytes as f32 / num_blocks as f32;
    dbg!(avg_size);
    let avg_deltas_size = pkt_sizes.iter()
        .map(|&s| (avg_size - s as f32).abs())
        .sum::<f32>() / num_blocks as f32;
    dbg!(avg_deltas_size);
    let avg_time = pkt_times.iter().sum::<u32>() as f32 / pkt_times.len() as f32;
    dbg!(avg_time);
    let avg_delta_time = pkt_times.iter()
        .map(|&t| (avg_time - t as f32).abs())
        .sum::<f32>() / pkt_times.len() as f32;
    dbg!(avg_delta_time);
}
