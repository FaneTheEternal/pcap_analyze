use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use rust_pcap::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file = File::open(args.get(1).unwrap()).unwrap();
    let mut num_blocks = 0;
    let mut ip_count = 0;
    let mut tcp_count = 0;
    let mut udp_count = 0;
    let mut icmp_count = 0;
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
                        let frame = Frame::new(b.data);
                        // let eth = frame.get_layer::<Ethernet>().unwrap();
                        if let Some(_) = frame.get_layer::<IPv4>() {
                            ip_count += 1;
                        }
                        if let Some(_) = frame.get_layer::<UDP>() {
                            udp_count += 1;
                        }
                        if let Some(_) = frame.get_layer::<TCP>() {
                            tcp_count += 1;
                        }
                        if let Some(_) = frame.get_layer::<ICMP>() {
                            icmp_count += 1;
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
}
