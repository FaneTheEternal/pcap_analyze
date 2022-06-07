use std::collections::HashSet;
use pcap_parser::*;
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
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
    let mut collect_stats = |frame: Frame| -> bool  {
        num_blocks += 1;
        pkt_sizes.push(frame.data.len());
        if let Some(time) = last_time {
            pkt_times.push(time - frame.ts_sec);
        }
        last_time = Some(frame.ts_sec);
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
        false
    };
    // iter_over_pcap(file, collect_stats);
    iter_over_pcapng(file, collect_stats);
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


fn iter_over_pcap(file: File, mut fun: impl FnMut(Frame) -> bool) {
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        println!("{hdr:?}")
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frame = Frame::from_legacy(&b);
                        if fun(frame) {
                            break;
                        }
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
}

fn iter_over_pcapng(file: File, mut fun: impl FnMut(Frame) -> bool) {
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        // starting a new section, clear known interfaces
                        if_linktypes = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];
                        // let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);

                        let frame = Frame::new(
                            epb.packet_data(),
                            epb.ts_low, epb.ts_high,
                            epb.caplen, epb.orig_len(),
                        );
                        if fun(frame) { break; }
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        // let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);

                        let frame = Frame::new(
                            spb.packet_data(),
                            0, 0,
                            0, spb.orig_len(),
                        );
                        if fun(frame) { break; }

                    }
                    PcapBlockOwned::NG(_) => {
                        // can be statistics (ISB), name resolution (NRB), etc.
                        eprintln!("unsupported block");
                    }
                    PcapBlockOwned::Legacy(_)
                    | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                eprintln!("Could not read complete data block.");
                eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                break;
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
}
