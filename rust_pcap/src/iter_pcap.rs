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

pub struct Pcap {
    reader: LegacyPcapReader<File>,
}

impl Pcap {
    pub fn new(file: File) -> Self {
        let reader = LegacyPcapReader::new(65536, file)
            .expect("LegacyPcapReader");
        Self {
            reader,
        }
    }
}

impl Iterator for Pcap {
    type Item = Frame;

    fn next(&mut self) -> Option<Self::Item> {
        let mut item = None;
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            println!("{hdr:?}")
                        }
                        PcapBlockOwned::Legacy(b) => {
                            item = Some(Frame::from_legacy(&b));
                        }
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    self.reader.consume(offset);
                    if item.is_some() { break; }
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    self.reader.refill().unwrap();
                }
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }
        item
    }
}

pub fn iter_over_pcapng(file: File, mut fun: impl FnMut(Frame) -> bool) {
    let pcapng = PcapNG::new(file);
    for frame in pcapng {
        if fun(frame) { break; }
    }
}

pub struct PcapNG {
    reader: PcapNGReader<File>,
    if_linktypes: Vec<pcap_parser::Linktype>,
}

impl PcapNG {
    pub fn new(file: File) -> Self {
        let reader = PcapNGReader::new(u16::MAX as usize, file)
            .expect("PcapNGReader");
        Self {
            reader,
            if_linktypes: vec![],
        }
    }
}

impl Iterator for PcapNG {
    type Item = Frame;

    fn next(&mut self) -> Option<Self::Item> {
        let mut item = None;
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                            // starting a new section, clear known interfaces
                            self.if_linktypes = Vec::new();
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                            self.if_linktypes.push(idb.linktype);
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                            assert!((epb.if_id as usize) < self.if_linktypes.len());
                            // let linktype = self.if_linktypes[epb.if_id as usize];
                            // let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);

                            item = Some(Frame::new(
                                epb.packet_data(),
                                epb.ts_low, epb.ts_high,
                                epb.caplen, epb.orig_len(),
                            ));
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                            assert!(self.if_linktypes.len() > 0);
                            // let linktype = self.if_linktypes[0];
                            // let blen = (spb.block_len1 - 16) as usize;
                            // let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);

                            item = Some(Frame::new(
                                spb.packet_data(),
                                0, 0,
                                0, spb.orig_len(),
                            ));
                        }
                        PcapBlockOwned::NG(_) => {
                            // can be statistics (ISB), name resolution (NRB), etc.
                            eprintln!("unsupported block");
                        }
                        PcapBlockOwned::Legacy(_)
                        | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
                    }
                    self.reader.consume(offset);
                    if item.is_some() { break; }
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
        item
    }
}
