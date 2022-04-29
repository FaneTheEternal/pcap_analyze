use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use rust_pcap::{Ethernet, Frame, GetLayers, IPv4};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let file = File::open(args.get(1).unwrap()).unwrap();
    let mut num_blocks = 0;
    let mut ip_count = 0;
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
                        if let Some(ip) = frame.get_layer::<IPv4>() {
                            ip_count += 1;
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
    println!("num_blocks: {}", num_blocks);
    println!("IP count: {}", ip_count);
}
