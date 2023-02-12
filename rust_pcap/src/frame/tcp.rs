use byteorder::{ByteOrder, NetworkEndian};
use derivative::Derivative;

use crate::*;
use crate::opc_ua::OpcUa;
use crate::tpkt::TPKT;

#[derive(Debug)]
pub struct TCPFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

#[derive(Derivative, Layer)]
#[derivative(Debug)]
pub struct TCP {
    pub src: u16,
    pub dst: u16,
    pub sn: u32,
    pub ack_sn: u32,
    pub header_len: u8,
    pub flags: TCPFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_point: u16,
    pub options: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub data: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub whole_data: Vec<u8>,
    layers: Layers,
}

impl TCP {
    pub fn new(data: &[u8], ip: &impl IP, ctx: &mut DissectionContext) -> TCP {
        let src = NetworkEndian::read_u16(data.get(..2).unwrap());
        let dst = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let sn = NetworkEndian::read_u32(data.get(4..8).unwrap());
        let ack_sn = NetworkEndian::read_u32(data.get(8..12).unwrap());
        let header_len = (data.get(12).unwrap() & 0b11110000) >> 4;
        let flags = NetworkEndian::read_u16(data.get(12..14).unwrap());
        let flags = TCPFlags {
            ns: flags & 0b0000000100000000 > 0,
            cwr: flags & 0b0000000010000000 > 0,
            ece: flags & 0b0000000001000000 > 0,
            urg: flags & 0b0000000000100000 > 0,
            ack: flags & 0b0000000000010000 > 0,
            psh: flags & 0b0000000000001000 > 0,
            rst: flags & 0b0000000000000100 > 0,
            syn: flags & 0b0000000000000010 > 0,
            fin: flags & 0b0000000000000001 > 0,
        };
        let window_size = NetworkEndian::read_u16(data.get(14..16).unwrap());
        let checksum = NetworkEndian::read_u16(data.get(16..18).unwrap());
        let urgent_point = NetworkEndian::read_u16(data.get(18..20).unwrap());
        let options = data.get(20..(header_len.clone() as usize * 4)).unwrap().to_vec();
        let data = data.get((header_len.clone() as usize * 4)..).unwrap().to_vec();
        let mut tcp = TCP {
            src,
            dst,
            sn,
            ack_sn,
            header_len: header_len.clone(),
            flags,
            window_size,
            checksum,
            urgent_point,
            options,
            data,
            whole_data: default(),
            layers: default(),
        };
        let ctx = &mut ctx.tcp;
        let key = Self::_key(ip.src(), tcp.src, ip.dst(), tcp.dst);
        let mut sequence = ctx.entry(key.clone()).or_insert(default());
        sequence.data.extend(&tcp.data);
        if let Some(http) = HTTP::try_make(&mut sequence, &tcp) {
            tcp.layers.insert(http);
        } else if let Some(opc_ua) = OpcUa::try_make(&tcp) {
            tcp.layers.insert(opc_ua);
        } else if let Some(tpkt) = TPKT::try_make(&sequence) {
            tcp.layers.insert(tpkt);
        }
        if tcp.is_tail_of_sequence() {
            if let Some(seq) = ctx.remove(&key) {
                tcp.whole_data = seq.data;
            }
        }
        tcp
    }

    pub fn is_tail_of_sequence(&self) -> bool {
        self.flags.psh | self.flags.fin
    }

    fn _key(src_ip: &[u8], src: u16, dst_ip: &[u8], dst: u16) -> String {
        format!("{:?} {} -> {:?} {}", src_ip, src, dst_ip, dst)
    }
}

impl HasLayers for TCP {
    fn layers(&self) -> &Layers {
        &self.layers
    }
}

pub type TCPContext = HashMap<String, TCPSequence>;


#[derive(Debug, Default)]
pub struct TCPSequence {
    pub data: Vec<u8>,
    pub http: Option<HTTPContext>,
}
