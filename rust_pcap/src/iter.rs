use std::fs::File;
use std::vec::IntoIter;

use pcap::{Packet, PacketCodec, PacketHeader};
use pcap_parser::{Block, LegacyPcapReader, Linktype, PcapBlockOwned, PcapError, PcapNGReader};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};

use crate::{default, DissectionContext, Frame};

pub struct Pcap {
    reader: LegacyPcapReader<File>,
    link_type: Linktype,
    ctx: DissectionContext,
}

impl Pcap {
    pub fn new(file: File) -> Self {
        let reader = LegacyPcapReader::new(65536, file)
            .expect("LegacyPcapReader");
        Self {
            reader,
            link_type: Linktype::NULL,
            ctx: default(),
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
                            println!("{:?}", hdr);
                            println!("Pcap root is {}", hdr.network);
                            self.link_type = hdr.network;
                        }
                        PcapBlockOwned::Legacy(b) => {
                            item = Some(Frame::from_legacy(&b, self.link_type, &mut self.ctx));
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
    if_linktypes: Vec<Linktype>,

    if_tsresol: u8,
    if_tsoffset: u64,

    ctx: DissectionContext,
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
            ctx: default(),
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
                                &mut self.ctx,
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
                                &mut self.ctx,
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

pub struct PcapIterator {
    packets: IntoIter<PacketOwned>,

    ctx: DissectionContext,
}

impl PcapIterator{
    pub fn new(packets: Vec<PacketOwned>) -> Self {
        return Self { packets: packets.into_iter(), ctx: default() };
    }
}

impl Iterator for PcapIterator {
    type Item = Frame;

    fn next(&mut self) -> Option<Self::Item> {
        self.packets.next().and_then(|pkt| Some(Frame::from_packed(pkt, &mut self.ctx)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>,
}

/// Simple codec that tranform [`pcap::Packet`] into [`PacketOwned`]
pub struct Codec;

impl PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        PacketOwned {
            header: *packet.header,
            data: packet.data.into(),
        }
    }
}
