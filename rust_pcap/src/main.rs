mod ethernet;
mod ip;

use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use pcap_parser::data::{get_packetdata, PacketData};
use crate::ethernet::Ethernet;
use crate::ip::IP;


pub fn split(data: &[u8], i: usize) -> (&[u8], &[u8]) {
    (data.get(..i).unwrap(), data.get(i..).unwrap())
}

fn main() {
    let file = File::open("2022-01-07-traffic-analysis-exercise.pcap").unwrap();
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
                        let (e, data) = Ethernet::from_raw(b.data);
                        if e.has_ipv4() {
                            let (ip, data) = IP::try_extract(data).unwrap();
                            ip_count += 1;
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
    println!("num_blocks: {}", num_blocks);
    println!("IP count: {}", ip_count);
}
