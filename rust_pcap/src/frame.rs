use pcap_parser::{EnhancedPacketBlock, LegacyPcapBlock, Linktype};
use pcap_parser::traits::PcapNGPacketBlock;

use ethernet::Ethernet;

use crate::*;

pub mod arp;
pub mod dhcp;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod goose;
pub mod opc_ua;
pub mod sv;


#[derive(Default, Debug)]
pub struct DissectionContext {
    pub tcp: TCPContext,
}

#[derive(Layer)]
pub struct Frame {
    pub ts: f64,
    pub caplen: u32,
    pub origlen: u32,
    pub data: Vec<u8>,

    layers: Layers,
}

impl Frame {
    pub fn new(
        data: &[u8],
        ts: f64,
        caplen: u32, origlen: u32,
        link_type: Linktype,
        ctx: &mut DissectionContext,
    ) -> Frame
    {
        let mut layers = Layers::default();
        match link_type {
            Linktype::ETHERNET => layers.insert(Ethernet::new(data.into(), ctx)),
            Linktype::IPV4 => layers.insert(IPv4::new(data, ctx)),
            Linktype::IPV6 => layers.insert(IPv6::new(data, ctx)),
            _ => {}
        }
        Frame { ts, caplen, origlen, data: data.to_vec(), layers }
    }

    pub fn from_legacy(
        block: &LegacyPcapBlock,
        link_type: Linktype,
        ctx: &mut DissectionContext,
    ) -> Frame
    {
        let ts = block.ts_sec as f64 + block.ts_usec as f64 * 0.000001;
        Self::new(block.data, ts, block.caplen, block.origlen, link_type, ctx)
    }

    pub fn from_enhanced(
        block: &EnhancedPacketBlock,
        link_type: Linktype,
        ts_offset: u64,
        resolution: u8,
        ctx: &mut DissectionContext,
    ) -> Frame
    {
        Self::new(
            block.packet_data(),
            block.decode_ts_f64(ts_offset, resolution as u64),
            block.caplen, block.origlen,
            link_type,
            ctx,
        )
    }

    pub fn from_packed(pkt: PacketOwned, ctx: &mut DissectionContext) -> Self {
        let hdr = pkt.header;
        let ts = hdr.ts.tv_sec as f64 + hdr.ts.tv_usec as f64 * 0.000001;
        Self::new(pkt.data.as_ref(), ts, hdr.caplen, hdr.len, Linktype::ETHERNET, ctx)
    }
}

impl HasLayers for Frame {
    fn layers(&self) -> &Layers {
        &self.layers
    }
    fn get_layer_descendants<T>(&self) -> Option<&T> where T: Layer {
        get_layer_descendants!(self, T, Ethernet, IPv4)
    }
}
