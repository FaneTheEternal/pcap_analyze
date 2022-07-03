use std::fs::File;

use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError, Block, PcapNGReader, Linktype};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};

use crate::Frame;

pub struct Pcap {
    reader: LegacyPcapReader<File>,
    link_type: Linktype,
}

impl Pcap {
    pub fn new(file: File) -> Self {
        let reader = LegacyPcapReader::new(65536, file)
            .expect("LegacyPcapReader");
        Self {
            reader,
            link_type: Linktype::NULL,
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
                            println!("{hdr:?}");
                            self.link_type = hdr.network;
                        }
                        PcapBlockOwned::Legacy(b) => {
                            item = Some(Frame::from_legacy(&b, self.link_type));
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

pub struct PcapNG {
    reader: PcapNGReader<File>,
    if_linktypes: Vec<pcap_parser::Linktype>,

    if_tsresol: u8,
    if_tsoffset: u64,
}

impl PcapNG {
    pub fn new(file: File) -> Self {
        let reader = PcapNGReader::new(u16::MAX as usize, file)
            .expect("PcapNGReader");
        Self {
            reader,
            if_linktypes: vec![],
            if_tsresol: 0,
            if_tsoffset: 0,
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
                            self.if_tsoffset = idb.if_tsoffset;
                            self.if_tsresol = idb.if_tsresol;
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                            assert!((epb.if_id as usize) < self.if_linktypes.len());
                            let linktype = self.if_linktypes[epb.if_id as usize];
                            // let res = pcap_parser::data::get_packetdata(epb.data, linktype, epb.caplen as usize);

                            item = Some(Frame::from_enhanced(
                                epb, linktype,
                                self.if_tsoffset, self.if_tsresol,
                            ));
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                            assert!(self.if_linktypes.len() > 0);
                            let linktype = self.if_linktypes[0];
                            // let blen = (spb.block_len1 - 16) as usize;
                            // let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);

                            item = Some(Frame::new(
                                spb.packet_data(),
                                0.0,
                                0,
                                spb.orig_len(),
                                linktype,
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
