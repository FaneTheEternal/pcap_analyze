use std::cell::RefCell;
use std::rc::Rc;

use derivative::Derivative;
use lazy_static::lazy_static;
use nom::bytes::complete::take_until;
use nom::IResult;
use nom_locate::{LocatedSpan, position};
use regex::Regex;

use crate::*;

#[derive(Debug)]
pub enum HTTPKind {
    Req {
        method: String,
        uri: String,
    },
    Res {
        status: u16,
        reason: String,
    },
}

#[derive(Derivative, Layer)]
#[derivative(Debug)]
pub struct HTTP {
    pub kind: HTTPKind,
    pub version: (u8, u8),
    pub headers: Vec<String>,
    #[derivative(Debug = "ignore")]
    pub payload: HTTPPayload,
    pub is_finalized: bool,
}

type HTTPPayload = Rc<RefCell<Vec<u8>>>;

#[derive(Default, Debug)]
pub struct HTTPContext {
    pub latest: Vec<u8>,
    // indexes
    pub first: Option<usize>,
    pub last: Option<usize>,
    pub payload: HTTPPayload,
}



lazy_static! {
    static ref REQ_REGEX: Regex = Regex::new(r"(?P<method>OPTIONS|GET|HEAD|POST|PUT|PATCH|DELETE|TRACE|CONNECT) (?P<uri>.+?) HTTP/(?P<major>\d)\.(?P<minor>\d)").unwrap();
    static ref RES_REGEX: Regex = Regex::new(r"HTTP/(?P<major>\d)\.(?P<minor>\d) (?P<status>\d\d\d) (?P<reason>.*)$").unwrap();
}

type Span<'a> = LocatedSpan<&'a [u8]>;

const LINE: &str = "\r\n";
const LINE2: &str = "\r\n\r\n";

struct Token<'a> {
    position: Span<'a>,
}

fn parse_line(s: Span) -> IResult<Span, Token> {
    let (s, _) = take_until(LINE.as_bytes())(s)?;
    let (s, pos) = position(s)?;
    Ok((s, Token { position: pos }))
}

fn parse_line2(s: Span) -> IResult<Span, Token> {
    let (s, _) = take_until(LINE2.as_bytes())(s)?;
    let (s, pos) = position(s)?;
    Ok((s, Token { position: pos }))
}

impl HTTP {
    pub fn try_make(ctx: &mut TCPSequence, tcp: &TCP) -> Option<HTTP> {
        let ctx = &mut ctx.http.get_or_insert(default());
        ctx.latest.extend(&tcp.data);
        let data = ctx.latest.as_slice();
        if data.is_empty() {
            return None;
        }
        let first = if let Some(first) = &ctx.first {
            *first
        } else {
            data.windows(LINE.len())
                .position(|e| e == LINE.as_bytes())?
        };
        ctx.first = Some(first);
        let first = data.get(..first).unwrap();
        let first = String::from_utf8_lossy(first);
        let pairs = rayon::join(
            || Self::_is_request(&first),
            || Self::_is_response(&first),
        );

        let (kind, version) = pairs.0.or_else(|| pairs.1)?;

        let headers_end = if let Some(end) = &ctx.last {
            *end
        } else {
            data
                .windows(LINE2.len())
                .position(|e| e == LINE2.as_bytes())?
        };
        let payload_start = headers_end + LINE2.len();
        let only_payload = ctx.last.is_some();
        ctx.last = Some(headers_end);
        if only_payload {
            ctx.payload.borrow_mut().extend(&tcp.data);
        } else {
            let payload = data
                .get(payload_start..).unwrap();
            ctx.payload.borrow_mut().extend(payload);
        };
        let http = HTTP {
            kind,
            version,
            headers: default(),
            payload: ctx.payload.clone(),
            is_finalized: tcp.is_tail_of_sequence(),
        };
        Some(http)
    }

    fn _is_request(s: &str) -> Option<(HTTPKind, (u8, u8))> {
        REQ_REGEX.captures(&s).map(|cap| {
            let major = cap["major"].parse::<u8>().unwrap();
            let minor = cap["minor"].parse::<u8>().unwrap();
            (
                HTTPKind::Req {
                    method: cap["method"].to_string(),
                    uri: cap["uri"].to_string(),
                },
                (major, minor)
            )
        })
    }

    fn _is_response(s: &str) -> Option<(HTTPKind, (u8, u8))> {
        RES_REGEX.captures(&s).map(|cap| {
            let major = cap["major"].parse::<u8>().unwrap();
            let minor = cap["minor"].parse::<u8>().unwrap();
            let status = cap["status"].parse::<u16>().unwrap();
            (
                HTTPKind::Res {
                    status,
                    reason: cap["reason"].to_string(),
                },
                (major, minor)
            )
        })
    }

    pub fn display(&self) -> String {
        let content_type = self.headers.iter()
            .find(|&r| r.starts_with("Content-Type"))
            .map_or(UNKNOWN_CONTENT_TYPE.to_string(), |t| t.clone());
        let content_type = content_type.get((content_type.find(":").unwrap() + 2)..).unwrap();
        match &self.kind {
            HTTPKind::Req { method, uri } => {
                format!("{} {} HTTP/{}.{} {}", method, uri, self.version.0, self.version.1, content_type)
            }
            HTTPKind::Res { status, reason } => {
                format!("HTTP/{}.{} {} {} {}", self.version.0, self.version.1, status, reason, content_type)
            }
        }
    }
}

const UNKNOWN_CONTENT_TYPE: &'static str = "Content-Type: Unknown";
