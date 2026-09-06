//! Meeting a serverless direct-punch peer through a **Hysteria Realms**
//! rendezvous (`docs/PROTOCOL.md` §7.1.5, "Meeting through a rendezvous
//! realm").
//!
//! A `direct_punch_to` line whose "where" is a `realm://` URI names no
//! address at all - it names a realm on a rendezvous host both peers can
//! reach (the public `realm.hy2.io`, or a self-hosted `hysteria-realm-server`).
//! Each slot then runs the Hysteria Realms procedure, speaking that
//! server's own protocol rather than one invented here:
//!
//! 1. **STUN.** Each peer asks a public STUN server what its NAT shows the
//!    world for the punch socket - the router-rewritten outer port that
//!    made a fixed, agreed port unreachable in the first place.
//! 2. **Rendezvous.** The peer whose nickname sorts lower *registers* the
//!    realm with those addresses and listens on its event stream; the
//!    other *looks it up*, posting its own addresses plus a fresh punch
//!    nonce and obfuscation key. The server pushes those to the registrant,
//!    who answers with freshly re-discovered addresses, and the lookup
//!    returns them to the other side.
//! 3. **Punch.** Both send small obfuscated `HYRLMv1` hello packets at
//!    every address they were given until a hello or an ack comes back.
//!    The address that answered is the one the NATs have opened.
//! 4. **The ordinary handshake.** That address is handed to the direct
//!    punch scheduler as if the settings file had named it, and the
//!    existing `DirectPing`/`DirectPong` exchange activates the link
//!    (`client::p2p::PeerLinkManager::on_realm_outcome`).
//!
//! The rendezvous only ever mediates the introduction - nothing of the
//! link goes through it - and its registration lasts one attempt window,
//! deregistered on every exit path (`Registration`'s drop). One UDP socket
//! carries all of it: STUN replies and punch packets are told apart from
//! aloo's own datagrams before any of aloo's decoding runs (`RawTaps`), the
//! way a QUIC transport demultiplexes such control packets off its own
//! socket.
//!
//! **What is wire-compatible, and what is not.** The parts that have to
//! talk to a real server are verified against `apernet/hysteria-realm-server`
//! (master): the HTTP API (routes `POST /v1/{id}`, `GET .../events`,
//! `POST .../connect`, `POST .../connects/{nonce}`, `DELETE /v1/{id}`),
//! `Authorization: Bearer` auth (the realm token for register/connect, the
//! returned `session_id` for the rest), the `addresses`/`nonce`/`obfs` JSON
//! and `punch`/`heartbeat_ack` SSE events, and the 16-byte nonce / 32-byte
//! obfs lengths the server validates. So two aloo peers meet through the
//! public `realm.hy2.io` (or any `hysteria-realm-server`) with no aloo
//! server anywhere. STUN is plain RFC 5389. The peer-to-peer **punch packet**
//! (`HYRLMv1`, salted and SHA-256-masked under the shared obfs key) is
//! aloo's *own* obfuscation, not reproduced from Hysteria's `punch.go`: it
//! only ever travels aloo<->aloo, so it needs both peers to agree, which
//! they do, and nothing more. An aloo peer therefore will not punch a
//! genuine Hysteria endpoint - which is not a goal here; the goal is aloo
//! peers reaching each other with no server of their own.
//! No heartbeat is sent: an attempt window (`DIRECT_PUNCH_WINDOW`, 30s) is
//! shorter than the server's session TTL (60s) and is deregistered at its
//! close, so the session never needs refreshing.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::server::ssl::BoxedStream;

/// The rendezvous the Hysteria project runs for everyone, with its public
/// token. Best-effort: it may rate-limit, change its rules or go away
/// without notice, which is why a self-hosted one is accepted in the same
/// URI shape.
pub const PUBLIC_RENDEZVOUS_HOST: &str = "realm.hy2.io";
pub const PUBLIC_RENDEZVOUS_TOKEN: &str = "public";

/// A fresh `realm://public@realm.hy2.io/<random>` URI to offer as a ready
/// default when someone adds a realm target: the realm name is the whole
/// of the rendezvous's privacy (the `public` token gates nothing), so it is
/// minted here at 128 bits rather than left to a person to invent something
/// guessable. Both peers must carry the *same* URI to meet - the name is a
/// shared secret, not a per-user handle.
pub fn suggested_realm_uri() -> String {
    let name = hex_encode(&crate::crypto::random_bytes(16));
    format!("realm://{PUBLIC_RENDEZVOUS_TOKEN}@{PUBLIC_RENDEZVOUS_HOST}/{name}")
}
/// A small built-in list of public STUN servers, asked in this order;
/// every one that answers contributes an address. Two of these are also on
/// Hysteria's own default list; the exact set does not need to match, since
/// STUN is standard and only discovers this client's own outer address.
/// Overridable per line with `?stun=`.
pub const DEFAULT_STUN_SERVERS: [&str; 3] = [
    "stun.nextcloud.com:3478",
    "stun.sip.us:3478",
    "global.stun.twilio.com:3478",
];
const DEFAULT_STUN_PORT: u16 = 3478;
/// How long one STUN discovery waits for the servers to answer.
pub const STUN_TIMEOUT: Duration = Duration::from_secs(4);
/// One punch round: hellos every `PUNCH_INTERVAL` for up to `PUNCH_TIMEOUT`,
/// Hysteria's own cadence.
pub const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
/// How long a lookup waits before asking the rendezvous again after it
/// failed - typically because the other side has not registered yet.
pub const RENDEZVOUS_RETRY_DELAY: Duration = Duration::from_secs(2);
/// A lookup blocks server-side for up to 10 seconds waiting for the
/// registrant's answer, so one HTTP exchange is allowed longer than that.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

pub const PUNCH_NONCE_LEN: usize = 16;
pub const PUNCH_OBFS_KEY_LEN: usize = 32;
/// A punch packet carries 0..=MAX_PUNCH_PADDING random trailing bytes so
/// its size says nothing.
pub const MAX_PUNCH_PADDING: usize = 1024;
const PUNCH_SALT_LEN: usize = 8;
const PUNCH_MAGIC: [u8; 8] = *b"HYRLMv1\0";
const PUNCH_HEADER_LEN: usize = PUNCH_MAGIC.len() + 1 + PUNCH_NONCE_LEN;
const PUNCH_MIN_WIRE_LEN: usize = PUNCH_SALT_LEN + PUNCH_HEADER_LEN;
const PUNCH_MAX_WIRE_LEN: usize = PUNCH_MIN_WIRE_LEN + MAX_PUNCH_PADDING;

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_HEADER_LEN: usize = 20;

/// Hysteria's symmetric-NAT guess: several observed ports within this gap
/// of each other are a NAT allocating predictably, so a few more past the
/// last one are worth trying too.
const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u16 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;

// ---------------------------------------------------------------------
// The realm URI
// ---------------------------------------------------------------------

/// One parsed `realm://<token>@<host>[:port]/<realm>[?stun=host:port...]`
/// - the same URI Hysteria's own `listen:`/`server:` take, so a realm
/// name agreed on with a Hysteria user needs no translation.
///
/// `realm://` speaks HTTPS to the rendezvous (default port 443);
/// `realm+http://` plain HTTP (default 80), for a rendezvous run on a
/// private network or under test. The `lport` parameter Hysteria accepts
/// is refused here: aloo's punch socket is `direct_punch_port`, and a
/// line silently asking for another would punch from a port the peer's
/// own line never learns of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmAddr {
    /// `true` for `realm://` (HTTPS), `false` for `realm+http://`.
    pub tls: bool,
    pub token: String,
    pub host: String,
    pub port: u16,
    pub realm_id: String,
    /// `?stun=` overrides, in order; empty means `DEFAULT_STUN_SERVERS`.
    pub stun_servers: Vec<String>,
    /// The URI exactly as written, so a settings round trip is lossless
    /// however the port or token were spelled.
    uri: String,
}

impl RealmAddr {
    /// Whether `value` is meant as a realm URI at all - the discriminator
    /// a `direct_punch_to` line's "where" field is read by.
    pub fn is_realm_uri(value: &str) -> bool {
        value.starts_with("realm://") || value.starts_with("realm+http://")
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        let (tls, rest, default_port) = if let Some(rest) = value.strip_prefix("realm://") {
            (true, rest, 443u16)
        } else if let Some(rest) = value.strip_prefix("realm+http://") {
            (false, rest, 80u16)
        } else {
            return Err(format!("not a realm URI (realm://... or realm+http://...): {value:?}"));
        };
        if rest.contains('#') {
            return Err("a realm URI cannot carry a fragment".to_string());
        }
        let (authority, path_and_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => return Err("a realm URI needs a realm name after the host".to_string()),
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let Some((userinfo, hostport)) = authority.rsplit_once('@') else {
            return Err("a realm URI needs a token before the @ (public@realm.hy2.io)".to_string());
        };
        let token = percent_decode(userinfo)?;
        if token.is_empty() {
            return Err("a realm URI needs a token before the @ (public@realm.hy2.io)".to_string());
        }
        let (host, port) = split_host_port(hostport, default_port)?;
        if host.is_empty() {
            return Err("a realm URI needs a rendezvous host".to_string());
        }
        if path.is_empty() || path.contains('/') {
            return Err(
                "a realm name must be exactly one path segment after the host".to_string(),
            );
        }
        let realm_id = percent_decode(path)?;
        if realm_id.is_empty() {
            return Err("a realm URI needs a realm name after the host".to_string());
        }
        let mut stun_servers = Vec::new();
        if let Some(query) = query {
            for pair in query.split('&').filter(|p| !p.is_empty()) {
                let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
                match key {
                    "stun" => {
                        let server = percent_decode(val)?;
                        split_stun_server(&server)?;
                        stun_servers.push(server);
                    }
                    "lport" => {
                        return Err(
                            "lport is not accepted here: the punch port is direct_punch_port"
                                .to_string(),
                        );
                    }
                    // Unknown parameters are ignored, as Hysteria ignores
                    // them, so a URI written for a newer version still reads.
                    _ => {}
                }
            }
        }
        Ok(Self {
            tls,
            token,
            host,
            port,
            realm_id,
            stun_servers,
            uri: value.to_string(),
        })
    }

    /// The URI as written.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The STUN servers this line discovers its outer address through.
    pub fn stun_servers(&self) -> Vec<String> {
        if self.stun_servers.is_empty() {
            DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect()
        } else {
            self.stun_servers.clone()
        }
    }

    /// `host:port` as an HTTP `Host:` header and a dial target spell it.
    fn host_port(&self) -> String {
        if self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_host_port(value: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return Err(format!("unterminated '[' in rendezvous host: {value:?}"));
        };
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if after.is_empty() => default_port,
            None => return Err(format!("not a valid rendezvous host: {value:?}")),
        };
        return Ok((inside.to_string(), port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((host.to_string(), parse_port(port)?)),
        _ => Ok((value.to_string(), default_port)),
    }
}

fn parse_port(s: &str) -> Result<u16, String> {
    match s.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("not a valid port: {s:?}")),
        Ok(p) => Ok(p),
    }
}

/// Minimal percent-decoding for the token and realm-name segments.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(|| format!("bad escape in {s:?}"))?;
            let hex = std::str::from_utf8(hex).map_err(|_| format!("bad escape in {s:?}"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| format!("bad escape in {s:?}"))?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("not UTF-8 after decoding: {s:?}"))
}

/// `host[:port]` for a STUN server, port 3478 when omitted.
fn split_stun_server(server: &str) -> Result<(String, u16), String> {
    if server.is_empty() {
        return Err("a stun= parameter names no server".to_string());
    }
    split_host_port(server, DEFAULT_STUN_PORT)
}

// ---------------------------------------------------------------------
// Punch metadata and packets (extras/realm/punch.go)
// ---------------------------------------------------------------------

/// The nonce and obfuscation key one lookup mints and the rendezvous
/// hands to the registrant: what makes a punch packet recognisable to
/// exactly the two peers this introduction is for, and noise to anyone
/// else on the path.
#[derive(Clone, PartialEq, Eq)]
pub struct PunchMeta {
    pub nonce: [u8; PUNCH_NONCE_LEN],
    pub obfs: [u8; PUNCH_OBFS_KEY_LEN],
}

impl std::fmt::Debug for PunchMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PunchMeta({})", self.nonce_hex())
    }
}

impl PunchMeta {
    pub fn random() -> Self {
        let nonce = crate::crypto::random_bytes(PUNCH_NONCE_LEN);
        let obfs = crate::crypto::random_bytes(PUNCH_OBFS_KEY_LEN);
        Self {
            nonce: nonce.try_into().unwrap_or([0; PUNCH_NONCE_LEN]),
            obfs: obfs.try_into().unwrap_or([0; PUNCH_OBFS_KEY_LEN]),
        }
    }

    pub fn from_hex(nonce: &str, obfs: &str) -> Result<Self, String> {
        let nonce = hex_decode(nonce)
            .filter(|b| b.len() == PUNCH_NONCE_LEN)
            .ok_or_else(|| "invalid punch nonce".to_string())?;
        let obfs = hex_decode(obfs)
            .filter(|b| b.len() == PUNCH_OBFS_KEY_LEN)
            .ok_or_else(|| "invalid punch obfs key".to_string())?;
        Ok(Self {
            nonce: nonce.try_into().unwrap_or([0; PUNCH_NONCE_LEN]),
            obfs: obfs.try_into().unwrap_or([0; PUNCH_OBFS_KEY_LEN]),
        })
    }

    pub fn nonce_hex(&self) -> String {
        hex_encode(&self.nonce)
    }

    pub fn obfs_hex(&self) -> String {
        hex_encode(&self.obfs)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchKind {
    Hello = 0x01,
    Ack = 0x02,
}

/// One punch packet: 8 random salt bytes, then `magic || type || nonce ||
/// padding` XOR-masked with `SHA-256(obfs || salt)` repeated.
pub fn encode_punch(kind: PunchKind, meta: &PunchMeta) -> Vec<u8> {
    let padding = usize::from(u16::from_le_bytes(
        crate::crypto::random_bytes(2).try_into().unwrap_or([0; 2]),
    )) % (MAX_PUNCH_PADDING + 1);
    let mut plain = Vec::with_capacity(PUNCH_HEADER_LEN + padding);
    plain.extend_from_slice(&PUNCH_MAGIC);
    plain.push(kind as u8);
    plain.extend_from_slice(&meta.nonce);
    plain.extend_from_slice(&crate::crypto::random_bytes(padding));
    let salt = crate::crypto::random_bytes(PUNCH_SALT_LEN);
    xor_mask(&mut plain, &meta.obfs, &salt);
    let mut packet = salt;
    packet.extend_from_slice(&plain);
    packet
}

/// The inverse of `encode_punch` under the same `meta`; `None` for
/// anything that is not a punch packet for exactly this introduction.
pub fn decode_punch(packet: &[u8], meta: &PunchMeta) -> Option<PunchKind> {
    if packet.len() < PUNCH_MIN_WIRE_LEN || packet.len() > PUNCH_MAX_WIRE_LEN {
        return None;
    }
    let (salt, masked) = packet.split_at(PUNCH_SALT_LEN);
    let mut plain = masked.to_vec();
    xor_mask(&mut plain, &meta.obfs, salt);
    if plain[..PUNCH_MAGIC.len()] != PUNCH_MAGIC {
        return None;
    }
    let kind = match plain[PUNCH_MAGIC.len()] {
        0x01 => PunchKind::Hello,
        0x02 => PunchKind::Ack,
        _ => return None,
    };
    if plain[PUNCH_MAGIC.len() + 1..PUNCH_HEADER_LEN] != meta.nonce {
        return None;
    }
    Some(kind)
}

fn xor_mask(data: &mut [u8], obfs: &[u8], salt: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(obfs);
    hasher.update(salt);
    let mask = hasher.finalize();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[i % mask.len()];
    }
}

// ---------------------------------------------------------------------
// STUN binding (RFC 5389, the subset extras/realm/stun.go uses)
// ---------------------------------------------------------------------

pub type StunTransactionId = [u8; 12];

/// A binding request and the transaction id its answer will carry.
pub fn stun_binding_request() -> (StunTransactionId, Vec<u8>) {
    let txid: StunTransactionId = crate::crypto::random_bytes(12).try_into().unwrap_or([0; 12]);
    let mut msg = Vec::with_capacity(STUN_HEADER_LEN);
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txid);
    (txid, msg)
}

/// Whether `packet` has the shape of a STUN message at all: the two
/// leading zero bits, the magic cookie, and a length that matches. Strict
/// enough that none of aloo's own datagrams can pass for one.
pub fn is_stun_message(packet: &[u8]) -> bool {
    packet.len() >= STUN_HEADER_LEN
        && packet[0] & 0xC0 == 0
        && packet[4..8] == STUN_MAGIC_COOKIE.to_be_bytes()
        && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len() - STUN_HEADER_LEN
}

/// The transaction id and mapped address of a binding success response,
/// preferring `XOR-MAPPED-ADDRESS` and falling back to `MAPPED-ADDRESS`.
pub fn parse_stun_binding_response(packet: &[u8]) -> Option<(StunTransactionId, SocketAddr)> {
    if !is_stun_message(packet) {
        return None;
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != STUN_BINDING_SUCCESS {
        return None;
    }
    let txid: StunTransactionId = packet[8..20].try_into().ok()?;
    let mut mapped = None;
    let mut rest = &packet[STUN_HEADER_LEN..];
    while rest.len() >= 4 {
        let attr_type = u16::from_be_bytes([rest[0], rest[1]]);
        let attr_len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let value = rest.get(4..4 + attr_len)?;
        match attr_type {
            STUN_ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_address_attr(value, true, &txid) {
                    return Some((txid, addr));
                }
            }
            STUN_ATTR_MAPPED_ADDRESS => {
                if mapped.is_none() {
                    mapped = parse_address_attr(value, false, &txid);
                }
            }
            _ => {}
        }
        let padded = (attr_len + 3) & !3;
        rest = rest.get(4 + padded..).unwrap_or(&[]);
    }
    mapped.map(|addr| (txid, addr))
}

fn parse_address_attr(value: &[u8], xor: bool, txid: &StunTransactionId) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
    }
    match value[1] {
        0x01 => {
            let mut ip: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            if xor {
                for (b, c) in ip.iter_mut().zip(cookie) {
                    *b ^= c;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x02 => {
            let mut ip: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            if xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie);
                key[4..].copy_from_slice(txid);
                for (b, k) in ip.iter_mut().zip(key) {
                    *b ^= k;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
    .filter(|a| a.port() != 0)
}

/// A binding success response naming `mapped`, for a STUN server stand-in
/// under test - the exact bytes a real server sends.
pub fn stun_binding_response(txid: &StunTransactionId, mapped: SocketAddr) -> Vec<u8> {
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let mut attr = Vec::new();
    attr.push(0);
    attr.push(if mapped.is_ipv4() { 0x01 } else { 0x02 });
    attr.extend_from_slice(&(mapped.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    match mapped.ip() {
        IpAddr::V4(ip) => {
            for (b, c) in ip.octets().iter().zip(cookie) {
                attr.push(b ^ c);
            }
        }
        IpAddr::V6(ip) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(txid);
            for (b, k) in ip.octets().iter().zip(key) {
                attr.push(b ^ k);
            }
        }
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&((4 + attr.len()) as u16).to_be_bytes());
    msg.extend_from_slice(&cookie);
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&attr);
    msg
}

// ---------------------------------------------------------------------
// Demultiplexing the one socket (extras/realm/punch_conn.go)
// ---------------------------------------------------------------------

/// One datagram a tap recognised as its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawDatagram {
    Stun {
        from: SocketAddr,
        txid: StunTransactionId,
        mapped: SocketAddr,
    },
    Punch {
        from: SocketAddr,
        kind: PunchKind,
    },
}

struct Tap {
    id: u64,
    meta: Option<PunchMeta>,
    tx: UnboundedSender<RawDatagram>,
}

#[derive(Default)]
struct TapsInner {
    next_id: u64,
    taps: Vec<Tap>,
}

/// The rendezvous attempts currently listening on a socket, consulted by
/// the receive loop **before** any of aloo's own decoding: a STUN reply or
/// a punch packet is bytes that would otherwise be dropped - or, worse,
/// be mistaken for a datagram of ours, since an obfuscated punch packet
/// is indistinguishable from noise by design. Both checks are exact (the
/// STUN cookie and length; the punch magic and nonce under the attempt's
/// own key), and cost nothing at all while no attempt is running.
#[derive(Clone, Default)]
pub struct RawTaps(Arc<Mutex<TapsInner>>);

/// A registered tap; dropping it unregisters.
pub struct TapHandle {
    taps: RawTaps,
    id: u64,
}

impl RawTaps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts listening. STUN replies arrive from the moment of
    /// registration; punch packets only once `set_meta` names the key
    /// they are masked under.
    pub fn register(&self) -> (TapHandle, UnboundedReceiver<RawDatagram>) {
        let (tx, rx) = unbounded_channel();
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.next_id += 1;
        let id = inner.next_id;
        inner.taps.push(Tap { id, meta: None, tx });
        (TapHandle { taps: self.clone(), id }, rx)
    }

    /// Whether any attempt is listening at all - the cheap check the
    /// receive loop makes before touching a datagram.
    pub fn is_empty(&self) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).taps.is_empty()
    }

    /// Offers one datagram to the taps. `true` if one of them took it,
    /// in which case it is not a datagram of aloo's own.
    pub fn demux(&self, from: SocketAddr, packet: &[u8]) -> bool {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if inner.taps.is_empty() {
            return false;
        }
        if let Some((txid, mapped)) = parse_stun_binding_response(packet) {
            for tap in &inner.taps {
                let _ = tap.tx.send(RawDatagram::Stun { from, txid, mapped });
            }
            return true;
        }
        for tap in &inner.taps {
            let Some(meta) = &tap.meta else {
                continue;
            };
            if let Some(kind) = decode_punch(packet, meta) {
                let _ = tap.tx.send(RawDatagram::Punch { from, kind });
                return true;
            }
        }
        false
    }

    fn set_meta(&self, id: u64, meta: Option<PunchMeta>) {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tap) = inner.taps.iter_mut().find(|t| t.id == id) {
            tap.meta = meta;
        }
    }

    fn remove(&self, id: u64) {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.taps.retain(|t| t.id != id);
    }
}

impl TapHandle {
    /// Names the punch key this attempt's packets are masked under; from
    /// here on packets under it are delivered to this tap.
    pub fn set_meta(&self, meta: Option<PunchMeta>) {
        self.taps.set_meta(self.id, meta);
    }
}

impl Drop for TapHandle {
    fn drop(&mut self) {
        self.taps.remove(self.id);
    }
}

// ---------------------------------------------------------------------
// The rendezvous HTTP API (extras/realm/client.go, hysteria-realm-server)
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct AddressesBody {
    addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    session_id: String,
    #[allow(dead_code)]
    #[serde(default)]
    ttl: u64,
}

#[derive(Debug, Serialize)]
struct ConnectRequest {
    addresses: Vec<String>,
    nonce: String,
    obfs: String,
}

/// What a lookup gets back, and what a registrant is pushed: the other
/// side's addresses and the punch key both will use.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Introduction {
    pub addresses: Vec<String>,
    pub nonce: String,
    pub obfs: String,
}

#[derive(Debug, Default, Deserialize)]
struct ErrorResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

/// The status and error of a non-2xx answer, in the words the server used.
fn describe_error(status: u16, body: &[u8]) -> String {
    let parsed: ErrorResponse = serde_json::from_slice(body).unwrap_or_default();
    if parsed.error.is_empty() && parsed.message.is_empty() {
        format!("rendezvous returned {status}")
    } else {
        format!("rendezvous returned {status}: {}: {}", parsed.error, parsed.message)
    }
}

async fn dial(addr: &RealmAddr) -> Result<BoxedStream, String> {
    let tcp = tokio::net::TcpStream::connect(addr.host_port())
        .await
        .map_err(|e| format!("could not reach {}: {e}", addr.host_port()))?;
    if addr.tls {
        let connector = crate::server::ssl::client_connector(None)?;
        crate::server::ssl::connect(Some(&connector), &addr.host, tcp)
            .await
            .map_err(|e| format!("TLS to {}: {e}", addr.host))
    } else {
        Ok(Box::new(tcp))
    }
}

fn request_head(addr: &RealmAddr, method: &str, sub_path: &str, bearer: &str, body_len: Option<usize>) -> String {
    let path = if sub_path.is_empty() {
        format!("/v1/{}", url_escape(&addr.realm_id))
    } else {
        format!("/v1/{}/{sub_path}", url_escape(&addr.realm_id))
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {bearer}\r\nUser-Agent: aloo-realm/1\r\nAccept: */*\r\nConnection: close\r\n",
        addr.host_port()
    );
    if let Some(len) = body_len {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {len}\r\n"));
    }
    head.push_str("\r\n");
    head
}

fn url_escape(segment: &str) -> String {
    let mut out = String::new();
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Reads one HTTP/1.1 response head: the status and the two headers the
/// body framing depends on.
async fn read_head(reader: &mut BufReader<BoxedStream>) -> Result<(u16, Option<usize>, bool), String> {
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| format!("reading the rendezvous response: {e}"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("rendezvous sent no HTTP status line ({status_line:?})"))?;
    let mut content_length = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("reading the rendezvous response: {e}"))?;
        if n == 0 {
            return Err("rendezvous closed the connection mid-headers".to_string());
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().ok();
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    Ok((status, content_length, chunked))
}

/// The body under the framing `read_head` found, to its end.
async fn read_body(
    reader: &mut BufReader<BoxedStream>,
    content_length: Option<usize>,
    chunked: bool,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    if chunked {
        let mut chunks = ChunkedReader::new();
        while !chunks.read_some(reader, &mut body).await? {}
    } else if let Some(len) = content_length {
        body.resize(len, 0);
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| format!("reading the rendezvous response body: {e}"))?;
    } else {
        reader
            .read_to_end(&mut body)
            .await
            .map_err(|e| format!("reading the rendezvous response body: {e}"))?;
    }
    Ok(body)
}

/// One request/response exchange, bounded by `HTTP_TIMEOUT`.
async fn exchange(
    addr: &RealmAddr,
    method: &str,
    sub_path: &str,
    bearer: &str,
    body: Option<String>,
) -> Result<HttpResponse, String> {
    let fut = async {
        let stream = dial(addr).await?;
        let mut reader = BufReader::new(stream);
        let head = request_head(addr, method, sub_path, bearer, body.as_ref().map(String::len));
        let mut out = head.into_bytes();
        if let Some(body) = body {
            out.extend_from_slice(body.as_bytes());
        }
        reader
            .get_mut()
            .write_all(&out)
            .await
            .map_err(|e| format!("sending to the rendezvous: {e}"))?;
        let (status, content_length, chunked) = read_head(&mut reader).await?;
        let body = read_body(&mut reader, content_length, chunked).await?;
        Ok(HttpResponse { status, body })
    };
    tokio::time::timeout(HTTP_TIMEOUT, fut)
        .await
        .map_err(|_| "the rendezvous did not answer in time".to_string())?
}

fn expect_status(resp: &HttpResponse, expected: u16) -> Result<(), String> {
    if resp.status == expected {
        Ok(())
    } else {
        Err(describe_error(resp.status, &resp.body))
    }
}

/// `POST /v1/{realm}` with the bearer token: this side is the registrant.
pub async fn register(addr: &RealmAddr, addresses: &[SocketAddr]) -> Result<String, String> {
    let body = serde_json::to_string(&AddressesBody {
        addresses: addresses.iter().map(ToString::to_string).collect(),
    })
    .map_err(|e| e.to_string())?;
    let resp = exchange(addr, "POST", "", &addr.token, Some(body)).await?;
    expect_status(&resp, 200)?;
    let parsed: RegisterResponse = serde_json::from_slice(&resp.body)
        .map_err(|e| format!("rendezvous sent an unreadable registration: {e}"))?;
    Ok(parsed.session_id)
}

/// `DELETE /v1/{realm}` with the session id.
pub async fn deregister(addr: &RealmAddr, session_id: &str) -> Result<(), String> {
    let resp = exchange(addr, "DELETE", "", session_id, None).await?;
    expect_status(&resp, 204)
}

/// `POST /v1/{realm}/connect` with the bearer token: this side looks the
/// registrant up, and blocks (server-side, up to ten seconds) until they
/// answer with fresh addresses.
pub async fn connect(addr: &RealmAddr, addresses: &[SocketAddr], meta: &PunchMeta) -> Result<Introduction, String> {
    let body = serde_json::to_string(&ConnectRequest {
        addresses: addresses.iter().map(ToString::to_string).collect(),
        nonce: meta.nonce_hex(),
        obfs: meta.obfs_hex(),
    })
    .map_err(|e| e.to_string())?;
    let resp = exchange(addr, "POST", "connect", &addr.token, Some(body)).await?;
    expect_status(&resp, 200)?;
    serde_json::from_slice(&resp.body).map_err(|e| format!("rendezvous sent an unreadable introduction: {e}"))
}

/// `POST /v1/{realm}/connects/{nonce}` with the session id: the
/// registrant's answer to one lookup.
pub async fn connect_response(
    addr: &RealmAddr,
    session_id: &str,
    nonce: &str,
    addresses: &[SocketAddr],
) -> Result<(), String> {
    let body = serde_json::to_string(&AddressesBody {
        addresses: addresses.iter().map(ToString::to_string).collect(),
    })
    .map_err(|e| e.to_string())?;
    let sub = format!("connects/{}", url_escape(nonce));
    let resp = exchange(addr, "POST", &sub, session_id, Some(body)).await?;
    expect_status(&resp, 204)
}

/// `GET /v1/{realm}/events`: the registrant's server-sent event stream,
/// open until dropped.
pub async fn open_events(addr: &RealmAddr, session_id: &str) -> Result<EventStream, String> {
    let fut = async {
        let stream = dial(addr).await?;
        let mut reader = BufReader::new(stream);
        let head = request_head(addr, "GET", "events", session_id, None);
        reader
            .get_mut()
            .write_all(head.as_bytes())
            .await
            .map_err(|e| format!("sending to the rendezvous: {e}"))?;
        let (status, content_length, chunked) = read_head(&mut reader).await?;
        if status != 200 {
            let body = read_body(&mut reader, content_length, chunked).await.unwrap_or_default();
            return Err(describe_error(status, &body));
        }
        Ok(EventStream {
            reader,
            chunks: chunked.then(ChunkedReader::new),
            buffer: Vec::new(),
        })
    };
    tokio::time::timeout(HTTP_TIMEOUT, fut)
        .await
        .map_err(|_| "the rendezvous did not open the event stream in time".to_string())?
}

/// An open `/events` stream. Only `punch` events are of interest; the
/// heartbeat acknowledgements and comments the server also sends are
/// skipped.
pub struct EventStream {
    reader: BufReader<BoxedStream>,
    chunks: Option<ChunkedReader>,
    buffer: Vec<u8>,
}

impl EventStream {
    /// The next `punch` event, or an error once the stream ends.
    pub async fn next_punch(&mut self) -> Result<Introduction, String> {
        loop {
            if let Some(event) = take_sse_event(&mut self.buffer) {
                if let Some(intro) = parse_sse_event(&event) {
                    return Ok(intro);
                }
                continue;
            }
            let before = self.buffer.len();
            let eof = match self.chunks.as_mut() {
                Some(chunks) => chunks.read_some(&mut self.reader, &mut self.buffer).await?,
                None => {
                    let mut tmp = [0u8; 4096];
                    let n = self
                        .reader
                        .read(&mut tmp)
                        .await
                        .map_err(|e| format!("reading the rendezvous event stream: {e}"))?;
                    self.buffer.extend_from_slice(&tmp[..n]);
                    n == 0
                }
            };
            if eof && self.buffer.len() == before {
                return Err("the rendezvous closed the event stream".to_string());
            }
        }
    }
}

/// Splits one complete server-sent event (terminated by a blank line) off
/// the front of `buffer`, if one is there.
fn take_sse_event(buffer: &mut Vec<u8>) -> Option<String> {
    let text = String::from_utf8_lossy(buffer);
    let (end, sep) = match (text.find("\n\n"), text.find("\r\n\r\n")) {
        (Some(a), Some(b)) if b < a => (b, 4),
        (Some(a), _) => (a, 2),
        (None, Some(b)) => (b, 4),
        (None, None) => return None,
    };
    let event = text[..end].to_string();
    buffer.drain(..end + sep);
    Some(event)
}

/// The `punch` event's payload, if `event` is one - any other event name,
/// and a comment line, is skipped exactly as Hysteria's reader skips them.
pub fn parse_sse_event(event: &str) -> Option<Introduction> {
    let mut name = String::new();
    let mut data = String::new();
    for line in event.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => name = value.to_string(),
            "data" => {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value);
            }
            _ => {}
        }
    }
    if name != "punch" {
        return None;
    }
    serde_json::from_str(&data).ok()
}

/// `Transfer-Encoding: chunked`, decoded incrementally so an event stream
/// can be read as it arrives rather than at its end.
struct ChunkedReader {
    remaining: usize,
    done: bool,
}

impl ChunkedReader {
    fn new() -> Self {
        Self { remaining: 0, done: false }
    }

    /// Appends whatever body bytes are readable now to `out`; `true` once
    /// the final chunk has been consumed.
    async fn read_some(&mut self, reader: &mut BufReader<BoxedStream>, out: &mut Vec<u8>) -> Result<bool, String> {
        if self.done {
            return Ok(true);
        }
        let err = |e: std::io::Error| format!("reading the rendezvous response body: {e}");
        if self.remaining == 0 {
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).await.map_err(err)? == 0 {
                    self.done = true;
                    return Ok(true);
                }
                if !line.trim().is_empty() {
                    break;
                }
            }
            let size = line.trim().split(';').next().unwrap_or("").trim();
            self.remaining = usize::from_str_radix(size, 16)
                .map_err(|_| format!("malformed chunk size {size:?} from the rendezvous"))?;
            if self.remaining == 0 {
                // Trailers, up to the blank line that ends the body.
                loop {
                    line.clear();
                    if reader.read_line(&mut line).await.map_err(err)? == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                self.done = true;
                return Ok(true);
            }
        }
        let mut tmp = vec![0u8; self.remaining.min(4096)];
        let n = reader.read(&mut tmp).await.map_err(err)?;
        if n == 0 {
            self.done = true;
            return Ok(true);
        }
        out.extend_from_slice(&tmp[..n]);
        self.remaining -= n;
        Ok(false)
    }
}

// ---------------------------------------------------------------------
// STUN discovery and punching on the one socket
// ---------------------------------------------------------------------

/// Asks every configured STUN server what this socket looks like from
/// outside, keeping punch packets that arrive meanwhile for the punch
/// phase rather than dropping them.
async fn discover(
    socket: &UdpSocket,
    servers: &[String],
    local_is_ipv6: bool,
    rx: &mut UnboundedReceiver<RawDatagram>,
    stashed: &mut Vec<RawDatagram>,
) -> Result<Vec<SocketAddr>, String> {
    let mut pending: HashSet<StunTransactionId> = HashSet::new();
    for server in servers {
        let Ok((host, port)) = split_stun_server(server) else {
            continue;
        };
        let Ok(resolved) = tokio::net::lookup_host((host.as_str(), port)).await else {
            crate::log_warn!("STUN server {server} does not resolve");
            continue;
        };
        for target in resolved.filter(|a| a.is_ipv6() == local_is_ipv6) {
            let (txid, request) = stun_binding_request();
            if socket.send_to(&request, target).await.is_ok() {
                pending.insert(txid);
            }
        }
    }
    if pending.is_empty() {
        return Err("no STUN server could be asked".to_string());
    }
    let mut found: Vec<SocketAddr> = Vec::new();
    let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
    while !pending.is_empty() {
        let Ok(next) = tokio::time::timeout_at(deadline, rx.recv()).await else {
            break;
        };
        match next {
            Some(RawDatagram::Stun { txid, mapped, .. }) => {
                if pending.remove(&txid) && !found.contains(&mapped) {
                    found.push(mapped);
                }
            }
            Some(punch @ RawDatagram::Punch { .. }) => stashed.push(punch),
            None => return Err("the socket is gone".to_string()),
        }
    }
    if found.is_empty() {
        return Err("no STUN server answered".to_string());
    }
    found.sort_by_key(ToString::to_string);
    Ok(found)
}

/// Which of the peer's addresses to punch at, in Hysteria's order: the
/// socket's own family only, deduplicated, with a predictable
/// symmetric-NAT port group widened by a few ports, sorted for a stable
/// probe order.
pub fn punch_candidates(peer_addrs: &[SocketAddr], local_is_ipv6: bool) -> Vec<SocketAddr> {
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in peer_addrs {
        let addr = match addr.ip() {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
                SocketAddr::new(IpAddr::V4(v6.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED)), addr.port())
            }
            _ => *addr,
        };
        if addr.port() == 0 || addr.is_ipv6() != local_is_ipv6 {
            continue;
        }
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    let mut by_ip: Vec<(IpAddr, Vec<u16>)> = Vec::new();
    for addr in &out {
        if !addr.is_ipv4() {
            continue;
        }
        match by_ip.iter_mut().find(|(ip, _)| *ip == addr.ip()) {
            Some((_, ports)) => ports.push(addr.port()),
            None => by_ip.push((addr.ip(), vec![addr.port()])),
        }
    }
    for (ip, mut ports) in by_ip {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2 || ports.windows(2).any(|w| w[1] - w[0] > SYMMETRIC_NAT_PORT_GAP) {
            continue;
        }
        let start = u32::from(ports[0]);
        let end = (u32::from(ports[ports.len() - 1]) + u32::from(SYMMETRIC_NAT_EXTRA_PORTS)).min(65535);
        let mut added = 0;
        for port in start..=end {
            if added >= SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
                break;
            }
            let addr = SocketAddr::new(ip, port as u16);
            if seen.insert(addr) {
                out.push(addr);
                added += 1;
            }
        }
    }
    out.sort_by_key(ToString::to_string);
    out
}

/// Hellos to every candidate every `PUNCH_INTERVAL` until one of them
/// answers with anything under this introduction's key, or the deadline.
async fn punch(
    socket: &UdpSocket,
    candidates: &[SocketAddr],
    meta: &PunchMeta,
    rx: &mut UnboundedReceiver<RawDatagram>,
    stashed: &mut Vec<RawDatagram>,
    deadline: tokio::time::Instant,
) -> Result<SocketAddr, String> {
    if candidates.is_empty() {
        return Err("the peer advertised no address this socket can reach".to_string());
    }
    let answered = |from: SocketAddr, kind: PunchKind| -> SocketAddr {
        if kind == PunchKind::Hello {
            let ack = encode_punch(PunchKind::Ack, meta);
            let _ = socket.try_send_to(&ack, from);
        }
        from
    };
    for early in stashed.drain(..) {
        if let RawDatagram::Punch { from, kind } = early {
            return Ok(answered(from, kind));
        }
    }
    let mut next_send = tokio::time::Instant::now();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err("nobody answered the punch".to_string());
        }
        if now >= next_send {
            let hello = encode_punch(PunchKind::Hello, meta);
            for addr in candidates {
                let _ = socket.send_to(&hello, addr).await;
            }
            next_send = now + PUNCH_INTERVAL;
        }
        let wait_until = next_send.min(deadline);
        match tokio::time::timeout_at(wait_until, rx.recv()).await {
            Ok(Some(RawDatagram::Punch { from, kind })) => return Ok(answered(from, kind)),
            Ok(Some(RawDatagram::Stun { .. })) => {}
            Ok(None) => return Err("the socket is gone".to_string()),
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------
// One attempt, end to end
// ---------------------------------------------------------------------

/// Which side of the rendezvous this client takes for one peer. The
/// rendezvous is asymmetric - one registers, the other looks up - and
/// two clients holding only each other's nickname settle it the one way
/// that needs no message: the nickname that sorts first registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealmRole {
    /// Registers the realm and waits to be looked up.
    Registrant,
    /// Looks the realm up.
    Lookup,
}

pub fn role_for(own_nick: &str, peer_nick: &str) -> RealmRole {
    if own_nick < peer_nick {
        RealmRole::Registrant
    } else {
        RealmRole::Lookup
    }
}

/// Everything one attempt needs, handed over by `client::p2p` when a
/// realm target's slot comes round.
pub struct AttemptConfig {
    pub realm: RealmAddr,
    pub role: RealmRole,
    pub socket: Arc<UdpSocket>,
    /// This machine's own interface addresses, advertised alongside the
    /// STUN-discovered ones so two peers on one LAN meet without leaving it.
    pub local_addrs: Vec<SocketAddr>,
    pub local_is_ipv6: bool,
    /// How long the whole attempt may run - the direct punch window.
    pub window: Duration,
    /// For the log line only.
    pub peer_label: String,
}

/// A registration that deregisters itself however the attempt ends -
/// including being aborted at the end of the window, when nothing after
/// the `.await` it was cancelled at would otherwise run.
struct Registration {
    realm: RealmAddr,
    session_id: String,
    released: bool,
}

impl Registration {
    async fn release(mut self) {
        self.released = true;
        if let Err(e) = deregister(&self.realm, &self.session_id).await {
            crate::log_warn!("could not deregister realm {}: {e}", self.realm.realm_id);
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let realm = self.realm.clone();
        let session_id = std::mem::take(&mut self.session_id);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = deregister(&realm, &session_id).await;
            });
        }
    }
}

/// Runs one whole attempt: STUN, the rendezvous in this side's role, and
/// the punch, retrying the rendezvous every `RENDEZVOUS_RETRY_DELAY`
/// until something answers or the window closes. `Ok` is the peer's
/// address the punch opened.
pub async fn run_attempt(cfg: AttemptConfig, taps: RawTaps) -> Result<SocketAddr, String> {
    let deadline = tokio::time::Instant::now() + cfg.window;
    let (tap, mut rx) = taps.register();
    loop {
        let result = match cfg.role {
            RealmRole::Registrant => registrant_round(&cfg, &tap, &mut rx, deadline).await,
            RealmRole::Lookup => lookup_round(&cfg, &tap, &mut rx, deadline).await,
        };
        tap.set_meta(None);
        let error = match result {
            Ok(addr) => return Ok(addr),
            Err(e) => e,
        };
        if tokio::time::Instant::now() + RENDEZVOUS_RETRY_DELAY >= deadline {
            return Err(error);
        }
        crate::log_warn!("realm rendezvous with {} failed ({error}); trying again", cfg.peer_label);
        tokio::time::sleep(RENDEZVOUS_RETRY_DELAY).await;
    }
}

fn advertised(discovered: &[SocketAddr], local: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = discovered.to_vec();
    for addr in local {
        if !out.contains(addr) {
            out.push(*addr);
        }
    }
    out
}

fn parse_addresses(intro: &Introduction) -> Vec<SocketAddr> {
    intro.addresses.iter().filter_map(|a| a.parse().ok()).collect()
}

async fn registrant_round(
    cfg: &AttemptConfig,
    tap: &TapHandle,
    rx: &mut UnboundedReceiver<RawDatagram>,
    deadline: tokio::time::Instant,
) -> Result<SocketAddr, String> {
    let servers = cfg.realm.stun_servers();
    let mut stashed = Vec::new();
    let discovered = discover(&cfg.socket, &servers, cfg.local_is_ipv6, rx, &mut stashed).await?;
    let session_id = register(&cfg.realm, &advertised(&discovered, &cfg.local_addrs)).await?;
    let registration = Registration {
        realm: cfg.realm.clone(),
        session_id: session_id.clone(),
        released: false,
    };
    let mut events = open_events(&cfg.realm, &session_id).await?;
    let outcome = loop {
        let intro = match tokio::time::timeout_at(deadline, events.next_punch()).await {
            Ok(Ok(intro)) => intro,
            Ok(Err(e)) => break Err(e),
            Err(_) => break Err("nobody looked the realm up during this window".to_string()),
        };
        let meta = match PunchMeta::from_hex(&intro.nonce, &intro.obfs) {
            Ok(meta) => meta,
            Err(e) => {
                crate::log_warn!("ignoring a realm introduction with {e}");
                continue;
            }
        };
        tap.set_meta(Some(meta.clone()));
        // Fresh mappings for the answer, as Hysteria does: the ones
        // registered earlier may already have aged out of the NAT. The
        // earlier answer stands in if nothing replies this time.
        let fresh = discover(&cfg.socket, &servers, cfg.local_is_ipv6, rx, &mut stashed)
            .await
            .unwrap_or_else(|_| discovered.clone());
        if let Err(e) = connect_response(
            &cfg.realm,
            &session_id,
            &intro.nonce,
            &advertised(&fresh, &cfg.local_addrs),
        )
        .await
        {
            break Err(e);
        }
        let candidates = punch_candidates(&parse_addresses(&intro), cfg.local_is_ipv6);
        let punch_deadline = (tokio::time::Instant::now() + PUNCH_TIMEOUT).min(deadline);
        match punch(&cfg.socket, &candidates, &meta, rx, &mut stashed, punch_deadline).await {
            Ok(addr) => break Ok(addr),
            Err(e) => {
                crate::log_warn!("punch toward {} failed ({e}); waiting for another lookup", cfg.peer_label);
                tap.set_meta(None);
                if tokio::time::Instant::now() >= deadline {
                    break Err(e);
                }
            }
        }
    };
    registration.release().await;
    outcome
}

async fn lookup_round(
    cfg: &AttemptConfig,
    tap: &TapHandle,
    rx: &mut UnboundedReceiver<RawDatagram>,
    deadline: tokio::time::Instant,
) -> Result<SocketAddr, String> {
    let servers = cfg.realm.stun_servers();
    let mut stashed = Vec::new();
    let discovered = discover(&cfg.socket, &servers, cfg.local_is_ipv6, rx, &mut stashed).await?;
    let meta = PunchMeta::random();
    // Listening from before the lookup is answered: the registrant may
    // start punching the moment it posts its answer, ahead of the
    // rendezvous returning that answer here.
    tap.set_meta(Some(meta.clone()));
    let intro = match tokio::time::timeout_at(deadline, connect(&cfg.realm, &advertised(&discovered, &cfg.local_addrs), &meta)).await {
        Ok(Ok(intro)) => intro,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("the window closed before the rendezvous answered".to_string()),
    };
    let candidates = punch_candidates(&parse_addresses(&intro), cfg.local_is_ipv6);
    let punch_deadline = (tokio::time::Instant::now() + PUNCH_TIMEOUT).min(deadline);
    punch(&cfg.socket, &candidates, &meta, rx, &mut stashed, punch_deadline).await
}
