//! A minimal AAP 2.0 client for the uD3TN bundle protocol agent (feature
//! `ud3tn`, needs `std`).
//!
//! uD3TN has no BPSec, so this crate's blocks travel inside the payload
//! ([`crate::wire::encode_bundle`], [`crate::wire::encode_bulletin`]); uD3TN
//! forwards them like any other bundle. The client speaks just enough of AAP
//! 2.0 for an application endpoint: register, send an ADU, receive ADUs.
//! BDM dispatch and FIB control are not implemented.
//!
//! Framing (from the AAP 2.0 specification): the agent first sends the byte
//! `0x2F`, then a `Welcome`. Every message is a protobuf preceded by its
//! varint length. An ADU's payload follows its `BundleADU` message as raw
//! bytes, `payload_length` long. Every message is answered with an
//! `AAPResponse`. A connection sends or receives, never both: use two.
//!
//! The protobuf codec is hand-written (no dependency) and handles only the
//! fields this client touches; unknown fields are skipped. Field numbers live
//! in [`fields`], which `integrations/ud3tn/gen_fields.py` checks against, or
//! regenerates from, uD3TN's `aap2.proto`.

pub mod fields;

use fields::*;
use std::io::{self, Read, Write};
use std::string::String;
use std::vec::Vec;

/// The byte uD3TN sends first on an AAP 2.0 connection.
pub const AAP2_MAGIC: u8 = 0x2F;

/// Ceiling on a protobuf message (metadata only; payloads are separate).
pub const MAX_MESSAGE: u64 = 64 * 1024;
/// Ceiling on a received payload.
pub const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;

/// Client failures.
#[derive(Debug)]
pub enum Aap2Error {
    Io(io::Error),
    /// The peer sent something this client does not understand.
    Protocol(&'static str),
    /// The agent answered with a status other than success.
    Status(u64),
}

impl From<io::Error> for Aap2Error {
    fn from(e: io::Error) -> Self {
        Aap2Error::Io(e)
    }
}

impl core::fmt::Display for Aap2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Aap2Error::Io(e) => write!(f, "aap2 i/o: {e}"),
            Aap2Error::Protocol(m) => write!(f, "aap2 protocol: {m}"),
            Aap2Error::Status(s) => write!(f, "aap2 status {s} (not success)"),
        }
    }
}

impl std::error::Error for Aap2Error {}

// ---------------------------------------------------------------------------
// Protobuf (proto3) encoding, the subset needed here
// ---------------------------------------------------------------------------

/// Protobuf primitives, public so tests and tools can build fake agents.
pub mod pb {
    use super::Aap2Error;
    use std::vec::Vec;

    pub const VARINT: u8 = 0;
    pub const I64: u8 = 1;
    pub const LEN: u8 = 2;
    pub const I32: u8 = 5;

    pub fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        buf.push(v as u8);
    }

    fn put_key(buf: &mut Vec<u8>, field: u32, wire: u8) {
        put_varint(buf, ((field as u64) << 3) | wire as u64);
    }

    /// A varint field. Proto3 omits default (zero) values.
    pub fn put_uint(buf: &mut Vec<u8>, field: u32, v: u64) {
        if v != 0 {
            put_key(buf, field, VARINT);
            put_varint(buf, v);
        }
    }

    /// A length-delimited field (string, bytes, embedded message).
    pub fn put_bytes(buf: &mut Vec<u8>, field: u32, b: &[u8]) {
        put_key(buf, field, LEN);
        put_varint(buf, b.len() as u64);
        buf.extend_from_slice(b);
    }

    /// A string field, omitted when empty (proto3 default).
    pub fn put_str(buf: &mut Vec<u8>, field: u32, s: &str) {
        if !s.is_empty() {
            put_bytes(buf, field, s.as_bytes());
        }
    }

    /// One decoded field.
    pub enum Value<'a> {
        Varint(u64),
        Bytes(&'a [u8]),
        /// Fixed-width values: skipped by every reader here.
        Fixed,
    }

    pub fn get_varint(d: &[u8], p: &mut usize) -> Result<u64, Aap2Error> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *d.get(*p).ok_or(Aap2Error::Protocol("truncated varint"))?;
            *p += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b < 0x80 {
                return Ok(v);
            }
        }
        Err(Aap2Error::Protocol("varint too long"))
    }

    /// Iterate a message's fields in order, skipping nothing: the caller
    /// ignores what it does not know.
    pub fn fields(d: &[u8]) -> Result<Vec<(u32, Value<'_>)>, Aap2Error> {
        let mut out = Vec::new();
        let mut p = 0;
        while p < d.len() {
            let key = get_varint(d, &mut p)?;
            let field = (key >> 3) as u32;
            let value = match (key & 7) as u8 {
                VARINT => Value::Varint(get_varint(d, &mut p)?),
                LEN => {
                    let n = get_varint(d, &mut p)? as usize;
                    if n > d.len() - p {
                        return Err(Aap2Error::Protocol("truncated field"));
                    }
                    let b = &d[p..p + n];
                    p += n;
                    Value::Bytes(b)
                }
                I64 => {
                    p = p
                        .checked_add(8)
                        .filter(|&e| e <= d.len())
                        .ok_or(Aap2Error::Protocol("truncated fixed64"))?;
                    Value::Fixed
                }
                I32 => {
                    p = p
                        .checked_add(4)
                        .filter(|&e| e <= d.len())
                        .ok_or(Aap2Error::Protocol("truncated fixed32"))?;
                    Value::Fixed
                }
                _ => return Err(Aap2Error::Protocol("unsupported wire type")),
            };
            out.push((field, value));
        }
        Ok(out)
    }
}

/// Read one varint-length-prefixed message.
pub fn read_delimited<R: Read>(r: &mut R) -> Result<Vec<u8>, Aap2Error> {
    let mut len = 0u64;
    for shift in (0..64).step_by(7) {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        len |= ((b[0] & 0x7f) as u64) << shift;
        if b[0] < 0x80 {
            if len > MAX_MESSAGE {
                return Err(Aap2Error::Protocol("message too large"));
            }
            let mut msg = vec![0u8; len as usize];
            r.read_exact(&mut msg)?;
            return Ok(msg);
        }
    }
    Err(Aap2Error::Protocol("length varint too long"))
}

/// Write one varint-length-prefixed message.
pub fn write_delimited<W: Write>(w: &mut W, msg: &[u8]) -> Result<(), Aap2Error> {
    let mut buf = Vec::with_capacity(msg.len() + 10);
    pb::put_varint(&mut buf, msg.len() as u64);
    buf.extend_from_slice(msg);
    w.write_all(&buf)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// The `BundleADU` metadata this client reads and writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AduMeta {
    pub src_eid: String,
    pub dst_eid: String,
    pub creation_timestamp_ms: u64,
    pub sequence_number: u64,
    pub payload_length: u64,
}

impl AduMeta {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        pb::put_str(&mut b, BUNDLE_ADU_SRC_EID, &self.src_eid);
        pb::put_str(&mut b, BUNDLE_ADU_DST_EID, &self.dst_eid);
        pb::put_uint(
            &mut b,
            BUNDLE_ADU_CREATION_TIMESTAMP_MS,
            self.creation_timestamp_ms,
        );
        pb::put_uint(&mut b, BUNDLE_ADU_SEQUENCE_NUMBER, self.sequence_number);
        pb::put_uint(&mut b, BUNDLE_ADU_PAYLOAD_LENGTH, self.payload_length);
        b
    }

    pub fn decode(d: &[u8]) -> Result<Self, Aap2Error> {
        let mut m = AduMeta::default();
        for (f, v) in pb::fields(d)? {
            match (f, v) {
                (BUNDLE_ADU_SRC_EID, pb::Value::Bytes(b)) => m.src_eid = text(b)?,
                (BUNDLE_ADU_DST_EID, pb::Value::Bytes(b)) => m.dst_eid = text(b)?,
                (BUNDLE_ADU_CREATION_TIMESTAMP_MS, pb::Value::Varint(v)) => {
                    m.creation_timestamp_ms = v
                }
                (BUNDLE_ADU_SEQUENCE_NUMBER, pb::Value::Varint(v)) => m.sequence_number = v,
                (BUNDLE_ADU_PAYLOAD_LENGTH, pb::Value::Varint(v)) => m.payload_length = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

fn text(b: &[u8]) -> Result<String, Aap2Error> {
    String::from_utf8(b.to_vec()).map_err(|_| Aap2Error::Protocol("string not utf-8"))
}

/// `ConnectionConfig`, as this client sends it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub is_subscriber: bool,
    pub secret: String,
    pub endpoint_id: String,
    pub keepalive_seconds: u32,
}

impl Config {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        pb::put_uint(
            &mut b,
            CONNECTION_CONFIG_IS_SUBSCRIBER,
            self.is_subscriber as u64,
        );
        pb::put_uint(&mut b, CONNECTION_CONFIG_AUTH_TYPE, AUTH_TYPE_DEFAULT);
        pb::put_str(&mut b, CONNECTION_CONFIG_SECRET, &self.secret);
        pb::put_str(&mut b, CONNECTION_CONFIG_ENDPOINT_ID, &self.endpoint_id);
        pb::put_uint(
            &mut b,
            CONNECTION_CONFIG_KEEPALIVE_SECONDS,
            self.keepalive_seconds as u64,
        );
        b
    }

    pub fn decode(d: &[u8]) -> Result<Self, Aap2Error> {
        let mut c = Config::default();
        for (f, v) in pb::fields(d)? {
            match (f, v) {
                (CONNECTION_CONFIG_IS_SUBSCRIBER, pb::Value::Varint(v)) => c.is_subscriber = v != 0,
                (CONNECTION_CONFIG_SECRET, pb::Value::Bytes(b)) => c.secret = text(b)?,
                (CONNECTION_CONFIG_ENDPOINT_ID, pb::Value::Bytes(b)) => c.endpoint_id = text(b)?,
                (CONNECTION_CONFIG_KEEPALIVE_SECONDS, pb::Value::Varint(v)) => {
                    c.keepalive_seconds = v as u32
                }
                _ => {}
            }
        }
        Ok(c)
    }
}

/// An `AAPMessage`, reduced to the variants this client handles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Welcome {
        node_id: String,
    },
    Config(Config),
    Adu(AduMeta),
    Keepalive,
    /// A variant this client does not handle (dispatch events, links).
    Other(u32),
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Message::Welcome { node_id } => {
                let mut w = Vec::new();
                pb::put_str(&mut w, WELCOME_NODE_ID, node_id);
                pb::put_bytes(&mut b, AAP_MESSAGE_WELCOME, &w);
            }
            Message::Config(c) => pb::put_bytes(&mut b, AAP_MESSAGE_CONFIG, &c.encode()),
            Message::Adu(m) => pb::put_bytes(&mut b, AAP_MESSAGE_ADU, &m.encode()),
            Message::Keepalive => pb::put_bytes(&mut b, AAP_MESSAGE_KEEPALIVE, &[]),
            Message::Other(f) => pb::put_bytes(&mut b, *f, &[]),
        }
        b
    }

    pub fn decode(d: &[u8]) -> Result<Self, Aap2Error> {
        // A oneof: the last variant present wins, as in protobuf.
        let mut out = None;
        for (f, v) in pb::fields(d)? {
            let pb::Value::Bytes(inner) = v else {
                continue;
            };
            out = Some(match f {
                AAP_MESSAGE_WELCOME => {
                    let mut node_id = String::new();
                    for (g, w) in pb::fields(inner)? {
                        if let (WELCOME_NODE_ID, pb::Value::Bytes(s)) = (g, w) {
                            node_id = text(s)?;
                        }
                    }
                    Message::Welcome { node_id }
                }
                AAP_MESSAGE_CONFIG => Message::Config(Config::decode(inner)?),
                AAP_MESSAGE_ADU => Message::Adu(AduMeta::decode(inner)?),
                AAP_MESSAGE_KEEPALIVE => Message::Keepalive,
                other => Message::Other(other),
            });
        }
        out.ok_or(Aap2Error::Protocol("empty AAPMessage"))
    }
}

/// An `AAPResponse` carrying only a status.
pub fn encode_response(status: u64) -> Vec<u8> {
    let mut b = Vec::new();
    pb::put_uint(&mut b, AAP_RESPONSE_RESPONSE_STATUS, status);
    b
}

/// The status in an `AAPResponse` (0 if absent).
pub fn decode_response(d: &[u8]) -> Result<u64, Aap2Error> {
    let mut status = 0;
    for (f, v) in pb::fields(d)? {
        if let (AAP_RESPONSE_RESPONSE_STATUS, pb::Value::Varint(s)) = (f, v) {
            status = s;
        }
    }
    Ok(status)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// One AAP 2.0 connection. Configure it as a sender or as a subscriber.
pub struct Aap2Client<S: Read + Write> {
    stream: S,
    node_id: String,
    subscriber: bool,
}

#[cfg(unix)]
impl Aap2Client<std::os::unix::net::UnixStream> {
    /// Connect to uD3TN's AAP 2.0 Unix socket (`--aap2-socket`).
    pub fn connect_unix<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Aap2Error> {
        Self::handshake(std::os::unix::net::UnixStream::connect(path)?)
    }
}

impl Aap2Client<std::net::TcpStream> {
    /// Connect to uD3TN's AAP 2.0 TCP port.
    pub fn connect_tcp<A: std::net::ToSocketAddrs>(addr: A) -> Result<Self, Aap2Error> {
        Self::handshake(std::net::TcpStream::connect(addr)?)
    }
}

impl<S: Read + Write> Aap2Client<S> {
    /// Read the magic byte and the `Welcome` on an open stream.
    pub fn handshake(mut stream: S) -> Result<Self, Aap2Error> {
        let mut magic = [0u8; 1];
        stream.read_exact(&mut magic)?;
        if magic[0] != AAP2_MAGIC {
            return Err(Aap2Error::Protocol("not an AAP 2.0 agent (bad magic)"));
        }
        let node_id = match Message::decode(&read_delimited(&mut stream)?)? {
            Message::Welcome { node_id } => node_id,
            _ => return Err(Aap2Error::Protocol("expected Welcome")),
        };
        Ok(Aap2Client {
            stream,
            node_id,
            subscriber: false,
        })
    }

    /// The agent's node ID, from its `Welcome`.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The endpoint ID for an agent ID on this node: `dtn://node/agent` or
    /// `ipn:N.agent`.
    pub fn endpoint_for(&self, agent_id: &str) -> String {
        match self.node_id.strip_prefix("ipn:") {
            Some(rest) => {
                let node = rest.split('.').next().unwrap_or(rest);
                std::format!("ipn:{node}.{agent_id}")
            }
            None => {
                let base = self.node_id.trim_end_matches('/');
                std::format!("{base}/{agent_id}")
            }
        }
    }

    fn call(&mut self, msg: &Message, payload: Option<&[u8]>) -> Result<(), Aap2Error> {
        write_delimited(&mut self.stream, &msg.encode())?;
        if let Some(p) = payload {
            self.stream.write_all(p)?;
        }
        self.stream.flush()?;
        match decode_response(&read_delimited(&mut self.stream)?)? {
            RESPONSE_STATUS_SUCCESS => Ok(()),
            other => Err(Aap2Error::Status(other)),
        }
    }

    /// Register `endpoint_id`. A subscriber receives ADUs; otherwise this
    /// connection sends. The same `secret` must be used by every connection
    /// sharing an endpoint.
    pub fn configure(
        &mut self,
        endpoint_id: &str,
        subscriber: bool,
        secret: &str,
    ) -> Result<(), Aap2Error> {
        let cfg = Config {
            is_subscriber: subscriber,
            secret: secret.into(),
            endpoint_id: endpoint_id.into(),
            keepalive_seconds: 0,
        };
        self.call(&Message::Config(cfg), None)?;
        self.subscriber = subscriber;
        Ok(())
    }

    /// Send one ADU to `dst_eid`.
    pub fn send(&mut self, dst_eid: &str, payload: &[u8]) -> Result<(), Aap2Error> {
        if self.subscriber {
            return Err(Aap2Error::Protocol("subscriber connections cannot send"));
        }
        let meta = AduMeta {
            dst_eid: dst_eid.into(),
            payload_length: payload.len() as u64,
            ..AduMeta::default()
        };
        self.call(&Message::Adu(meta), Some(payload))
    }

    /// Block until the agent delivers an ADU; acknowledge it. Keepalives are
    /// answered on the way.
    pub fn receive(&mut self) -> Result<(AduMeta, Vec<u8>), Aap2Error> {
        if !self.subscriber {
            return Err(Aap2Error::Protocol("configure as subscriber to receive"));
        }
        loop {
            match Message::decode(&read_delimited(&mut self.stream)?)? {
                Message::Adu(meta) => {
                    if meta.payload_length > MAX_PAYLOAD {
                        return Err(Aap2Error::Protocol("payload too large"));
                    }
                    let mut payload = vec![0u8; meta.payload_length as usize];
                    self.stream.read_exact(&mut payload)?;
                    write_delimited(&mut self.stream, &encode_response(RESPONSE_STATUS_SUCCESS))?;
                    self.stream.flush()?;
                    return Ok((meta, payload));
                }
                Message::Keepalive => {
                    write_delimited(&mut self.stream, &encode_response(RESPONSE_STATUS_ACK))?;
                    self.stream.flush()?;
                }
                _ => return Err(Aap2Error::Protocol("unexpected message for a subscriber")),
            }
        }
    }

    /// The underlying stream (for timeouts and shutdown).
    pub fn stream(&self) -> &S {
        &self.stream
    }
}
