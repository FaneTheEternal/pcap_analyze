use std::fmt::Formatter;

use byteorder::{ByteOrder, NetworkEndian};

use crate::*;
use crate::goose::GOOSE;

#[derive(Layer)]
pub struct Ethernet {
    src: [u8; 6],
    dst: [u8; 6],
    eth_type: u16,
    crc: [u8; 4],
    layers: Layers,
}

impl std::fmt::Debug for Ethernet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let src = self.src.map(|b| format!("{:X}", b)).join(":");
        let dst = self.dst.map(|b| format!("{:X}", b)).join(":");
        write!(f, "Ethernet(Mac({}->{:}) Type(0x{:#04x}))", src, dst, self.eth_type)
    }
}

static WARN_ETHER_TYPE: bool = false;

impl Ethernet {
    const IP4: u16 = 0x0800;
    const ARP: u16 = 0x0806;
    const WAKE_ON_LAN: u16 = 0x0842;
    const AVTP: u16 = 0x22F0;
    const TRILL: u16 = 0x22F3;
    const SRP: u16 = 0x22EA;
    const DEC_MOP: u16 = 0x6002;
    const DEC_NET: u16 = 0x6003;
    const DEC_LAT: u16 = 0x6004;
    const RARP: u16 = 0x8035;
    const ETHERTALK: u16 = 0x809B;
    const AARP: u16 = 0x80F3;
    const IEEE_802_1Q: u16 = 0x8100;
    const SLPP: u16 = 0x8102;
    const VLACP: u16 = 0x8103;
    const IPX: u16 = 0x8137;
    const QNET: u16 = 0x8204;
    const IP6: u16 = 0x86DD;
    /// Ethernet flow control
    const EFC: u16 = 0x8808;
    const LACP: u16 = 0x8809;
    const COBRA_NET: u16 = 0x8819;
    const MPLS_UNICAST: u16 = 0x8847;
    const MPLS_MULTICAST: u16 = 0x8848;
    // TODO: Many others from https://en.wikipedia.org/wiki/EtherType
    const GOOSE: u16 = 0x88B8;

    pub fn new(data: MultipartSlice, ctx: &mut DissectionContext) -> Ethernet {
        let mut layers = Layers::default();
        let eth_type = NetworkEndian::read_u16(data.get(12..14).unwrap());
        match eth_type {
            Self::IP4 => {
                layers.insert(IPv4::new(data.get(14..).unwrap(), ctx));
            }
            Self::ARP => {
                layers.insert(ARP::new(data.get(14..).unwrap()));
            }
            Self::WAKE_ON_LAN => { if WARN_ETHER_TYPE { println!("WAKE_ON_LAN not implemented") } }
            Self::AVTP => { if WARN_ETHER_TYPE { println!("AVTP not implemented") } }
            Self::TRILL => { if WARN_ETHER_TYPE { println!("TRILL not implemented") } }
            Self::SRP => { if WARN_ETHER_TYPE { println!("SRP not implemented") } }
            Self::DEC_MOP => { if WARN_ETHER_TYPE { println!("DEC_MOP not implemented") } }
            Self::DEC_NET => { if WARN_ETHER_TYPE { println!("DEC_NET not implemented") } }
            Self::DEC_LAT => { if WARN_ETHER_TYPE { println!("DEC_LAT not implemented") } }
            Self::RARP => { if WARN_ETHER_TYPE { println!("RARP not implemented") } }
            Self::ETHERTALK => { if WARN_ETHER_TYPE { println!("ETHERTALK not implemented") } }
            Self::AARP => { if WARN_ETHER_TYPE { println!("AARP not implemented") } }
            Self::IEEE_802_1Q => {
                // TODO: maybe need tag layer?
                // let data = [&data[..12], &data[16..]].concat();
                // return Self::new(data.as_slice(), ctx);
                let slice = MultipartSlice {
                    slices: vec![
                        data.get(..12).unwrap(),
                        data.get(16..).unwrap(),
                    ]
                };
                return Self::new(slice, ctx);
            }
            Self::SLPP => { if WARN_ETHER_TYPE { println!("SLPP not implemented") } }
            Self::VLACP => { if WARN_ETHER_TYPE { println!("VLACP not implemented") } }
            Self::IPX => { if WARN_ETHER_TYPE { println!("IPX not implemented") } }
            Self::QNET => { if WARN_ETHER_TYPE { println!("QNET not implemented") } }
            Self::IP6 => { if WARN_ETHER_TYPE { println!("IP6 not implemented") } }
            Self::EFC => { if WARN_ETHER_TYPE { println!("EFC not implemented") } }
            Self::LACP => { if WARN_ETHER_TYPE { println!("LACP not implemented") } }
            Self::COBRA_NET => { if WARN_ETHER_TYPE { println!("COBRA_NET not implemented") } }
            Self::MPLS_UNICAST => { if WARN_ETHER_TYPE { println!("MPLS_UNICAST not implemented") } }
            Self::MPLS_MULTICAST => { if WARN_ETHER_TYPE { println!("MPLS_MULTICAST not implemented") } }
            Self::GOOSE => {
                layers.insert(GOOSE::new(data.get(14..).unwrap()));
            }
            _ => { if WARN_ETHER_TYPE { println!("unknown eth_type: {:#04x}", eth_type) } }
        }
        Ethernet {
            src: get_array!(data, 0..6),
            dst: get_array!(data, 6..12),
            eth_type,
            crc: get_array!(data, (data.len() - 4)..),
            layers,
        }
    }
}

impl HasLayers for Ethernet {
    fn layers(&self) -> &Layers {
        &self.layers
    }
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer {
        get_layer_descendants!(self, T, IPv4)
    }
}