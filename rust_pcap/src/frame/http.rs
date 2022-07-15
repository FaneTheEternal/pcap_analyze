use pcap_parser::nom::InputIter;

use crate::*;

#[derive(Debug)]
pub enum HTTPKind {
    Req { method: String, uri: String },
    Res { code: u16 },
}

#[derive(Debug, Layer)]
pub struct HTTP {
    kind: HTTPKind,
    version: (u8, u8),
    payload: String,
}

impl HTTP {
    fn _get_version(s: &str) -> (u8, u8) {
        // HTTP/major.minor
        let dot = s.position(|e| e == '.').unwrap();
        let major = s.as_bytes()[dot - 1] as char;
        let minor = s.as_bytes()[dot + 1] as char;
        (
            major.to_string().parse::<u8>().unwrap(),
            minor.to_string().parse::<u8>().unwrap(),
        )
    }

    pub fn try_make(data: &[u8]) -> Option<HTTP> {
        if data.is_empty() {
            return None;
        }
        let data = String::from_utf8(data.to_vec()).ok()?;
        let first = data.chars().position(|i| i == ' ')?;
        let first = data.get(..first).unwrap();
        let row: Vec<&str> = data.split(' ').collect();
        let (kind, version) = match first {
            "OPTIONS" | "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "TRACE"
            | "CONNECT" => (
                HTTPKind::Req {
                    method: first.to_string(),
                    uri: row.get(1).unwrap().to_string(),
                },
                Self::_get_version(row.get(2).unwrap()),
            ),
            _ if first.contains("HTTP") => (
                HTTPKind::Res {
                    code: row.get(1).unwrap().parse::<u16>().unwrap(),
                },
                Self::_get_version(first),
            ),
            _ => return None,
        };
        let http = HTTP {
            kind,
            version,
            payload: data,
        };
        Some(http)
    }
}
