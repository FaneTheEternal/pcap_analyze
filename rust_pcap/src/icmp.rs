use byteorder::{ByteOrder, NetworkEndian};
use crate::*;

#[derive(Debug, Layer)]
pub struct ICMP {
    kind: u8,
    code: u8,
    checksum: u16,
    data: ICMPData,
}

#[derive(Debug)]
pub enum ICMPData {
    Echo {
        id: u16,
        num: u16,
        data: Vec<u8>,
    },
    Reserved,
    DstUnreachable {
        kind: DSTUnreachable,
        not_use: u32,
        header_ip: u64,
    },
    SrcContainment,
    Forward {
        kind: Forward,
        addr: u32,
        header_ip: u64,
    },
    AltAddrNode,
    // TODO: IRDP
    RouterAdvertisement,
    // TODO: IRDP
    RouterRequest,
    TTLExpire {
        kind: TTLExpire,
        addr: u32,
        header_ip: u64,
    },
    InvalidParams(InvalidParams),
    ReqTime(ReqTime),
    ResTime(ReqTime),
    OutDate,
    Photuris(Photuris),
    Unknown,
}

#[derive(Debug)]
pub enum DSTUnreachable {
    NetUnreachable,
    NodeUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    FragRequired,
    WrongRoad,
    NetUnknown,
    NodeUnknown,
    SRCNodeIsolated,
    NetAdminForbidden,
    NodeAdminForbidden,
    NetUnavailableToS,
    NodeUnavailableToS,
    CommunicationAdminForbidden,
    NodeOrderViolation,
    PreferenceOrderPruning,
}

#[derive(Debug)]
pub enum Forward {
    PktNet,
    PktNode,
    ToS,
    PktNodeTos,
}

#[derive(Debug)]
pub enum TTLExpire {
    Transportation,
    BuildFrag,
}

#[derive(Debug)]
pub enum InvalidParams {
    PtrError {
        ptr: u8,
        not_use: u32,
        header_ip: u64,
    },
    MissingOptions {
        not_use: u32,
        header_ip: u64,
    },
    Length {
        not_use: u32,
        header_ip: u64,
    },
}

#[derive(Debug)]
pub struct ReqTime {
    id: u16,
    num: u16,
    begin_time: u32,
    recv_time: u32,
    send_time: u32,
}

#[derive(Debug)]
pub enum Photuris {
    Reserved,
    UnknownIndex,
    AuthError,
    DecodeError,
    NeedValid,
    NeedAuth,
}

impl ICMP {
    pub fn new(data: &[u8]) -> ICMP {
        let kind = data.get(0).unwrap().clone();
        let code = data.get(1).unwrap().clone();
        let checksum = NetworkEndian::read_u16(data.get(2..4).unwrap());
        let data = match (kind, code) {
            (0 | 8, _) => {
                ICMPData::Echo {
                    id: NetworkEndian::read_u16(data.get(4..6).unwrap()),
                    num: NetworkEndian::read_u16(data.get(6..8).unwrap()),
                    data: data.get(8..).unwrap().to_vec(),
                }
            }
            (1 | 2 | 7, _) => {
                ICMPData::Reserved
            }
            (3, code) => {
                let not_use = NetworkEndian::read_u32(data.get(4..8).unwrap());
                let header_ip = NetworkEndian::read_u64(data.get(8..16).unwrap());
                match code {
                    0 => ICMPData::DstUnreachable { kind: DSTUnreachable::NetUnreachable, not_use, header_ip },
                    1 => ICMPData::DstUnreachable { kind: DSTUnreachable::NodeUnreachable, not_use, header_ip },
                    2 => ICMPData::DstUnreachable { kind: DSTUnreachable::ProtocolUnreachable, not_use, header_ip },
                    3 => ICMPData::DstUnreachable { kind: DSTUnreachable::PortUnreachable, not_use, header_ip },
                    4 => ICMPData::DstUnreachable { kind: DSTUnreachable::FragRequired, not_use, header_ip },
                    5 => ICMPData::DstUnreachable { kind: DSTUnreachable::WrongRoad, not_use, header_ip },
                    6 => ICMPData::DstUnreachable { kind: DSTUnreachable::NetUnknown, not_use, header_ip },
                    7 => ICMPData::DstUnreachable { kind: DSTUnreachable::NodeUnknown, not_use, header_ip },
                    8 => ICMPData::DstUnreachable { kind: DSTUnreachable::SRCNodeIsolated, not_use, header_ip },
                    9 => ICMPData::DstUnreachable { kind: DSTUnreachable::NetAdminForbidden, not_use, header_ip },
                    10 => ICMPData::DstUnreachable { kind: DSTUnreachable::NodeAdminForbidden, not_use, header_ip },
                    11 => ICMPData::DstUnreachable { kind: DSTUnreachable::NetUnavailableToS, not_use, header_ip },
                    12 => ICMPData::DstUnreachable { kind: DSTUnreachable::NodeUnavailableToS, not_use, header_ip },
                    13 => ICMPData::DstUnreachable { kind: DSTUnreachable::CommunicationAdminForbidden, not_use, header_ip },
                    14 => ICMPData::DstUnreachable { kind: DSTUnreachable::NodeOrderViolation, not_use, header_ip },
                    15 => ICMPData::DstUnreachable { kind: DSTUnreachable::PreferenceOrderPruning, not_use, header_ip },
                    _ => unreachable!()
                }
            }
            (4 | 6, _) => ICMPData::OutDate,
            (5, code) => {
                let addr = NetworkEndian::read_u32(data.get(4..8).unwrap());
                let header_ip = NetworkEndian::read_u64(data.get(8..16).unwrap());
                match code {
                    0 => ICMPData::Forward { kind: Forward::PktNet, addr, header_ip },
                    1 => ICMPData::Forward { kind: Forward::PktNode, addr, header_ip },
                    2 => ICMPData::Forward { kind: Forward::ToS, addr, header_ip },
                    3 => ICMPData::Forward { kind: Forward::PktNodeTos, addr, header_ip },
                    _ => unreachable!()
                }
            }
            (9, _) => ICMPData::RouterAdvertisement,
            (10, _) => ICMPData::RouterRequest,
            (11, code) => {
                let addr = NetworkEndian::read_u32(data.get(4..8).unwrap());
                let header_ip = NetworkEndian::read_u64(data.get(8..16).unwrap());
                match code {
                    0 => ICMPData::TTLExpire { kind: TTLExpire::Transportation, addr, header_ip },
                    1 => ICMPData::TTLExpire { kind: TTLExpire::BuildFrag, addr, header_ip },
                    _ => unreachable!()
                }
            }
            _ => ICMPData::Unknown
        };
        ICMP {
            kind,
            code,
            checksum,
            data,
        }
    }
}
