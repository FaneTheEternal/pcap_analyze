use std::fs::File;

use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError, Block, PcapNGReader};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};

use crate::Frame;

pub fn iter_over_pcap(file: File, mut fun: impl FnMut(Frame) -> bool) {
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

pub fn iter_over_pcapng(file: File, mut fun: impl FnMut(Frame) -> bool) {
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
