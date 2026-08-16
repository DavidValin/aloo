# aloo wire protocol

This document specifies the client↔server protocol and the direct
client↔client transport (§7.1). It describes the *wire format and server
behaviour* precisely enough to implement an interoperable client or server
from scratch. Application-level behaviour - keybindings, rendering, how a
client chooses to chunk a recording - is documented in `SPEC.md`/
`README.md`, not here, except where noted as informative context.

This document describes the protocol, not its implementation: no Rust
appears in it, message shapes are given in neutral pseudocode, and no
function or file is named. `docs/SPEC.md` carries the mapping from every
term used here to the item that implements it, so a reader working on the
code can cross over and a reader writing a second implementation need not.

The server is a pure medium of connection *setup*, never of content: it
authenticates connections, tracks channel membership/presence, relays
`rsa_per_msg` key-rotation notices, and relays the candidate exchange that
lets two clients punch a direct UDP link to each other (§7.1). Every
actual message, voice stream, and file transfer travels over that direct
link once it's established - never through the server, not even as
ciphertext. The server holds no state beyond the current process's memory
(nothing survives a restart), and there is no relay-of-last-resort: if a
direct link can't be established, the send fails visibly rather than
falling back to a server relay (§7.1).

## Contents

- [Overview: the connections, and what travels on each](#overview-the-connections-and-what-travels-on-each)
  - [Every message, by connection](#every-message-by-connection)
- [1. Transport](#1-transport)
  - [1.1 Framing](#11-framing)
  - [1.2 Why length-prefixed framing](#12-why-length-prefixed-framing)
  - [1.3 The control channel is encrypted](#13-the-control-channel-is-encrypted)
- [2. Serialization](#2-serialization)
- [3. Domain types](#3-domain-types)
- [4. Connection lifecycle](#4-connection-lifecycle)
- [5. Authentication](#5-authentication)
  - [5.1 `AuthKind::None`](#51-authkindnone)
  - [5.2 `AuthKind::Password`](#52-authkindpassword)
  - [5.3 `AuthKind::Rsa`](#53-authkindrsa)
  - [5.4 Identify / nicknames](#54-identify-nicknames)
- [6. Channels](#6-channels)
  - [6.1 `JoinChannel { name, kind, password }`](#61-joinchannel-name-kind-password)
  - [6.2 `LeaveChannel { name }`](#62-leavechannel-name)
  - [6.3 `ChannelList(list<ChannelInfo>)` / `ChannelCreated { channel }`](#63-channellistlistchannelinfo-channelcreated-channel)
  - [6.4 `UserOffline { user_id }` - full disconnect](#64-useroffline-user_id---full-disconnect)
  - [6.5 Password-protected private channels](#65-password-protected-private-channels)
  - [6.6 Brute-force protection](#66-brute-force-protection)
- [7. Messaging](#7-messaging)
  - [7.1 Direct peer-to-peer transport](#71-direct-peer-to-peer-transport)
    - [7.1.1 Reliable delivery over the punched link](#711-reliable-delivery-over-the-punched-link)
    - [7.1.2 Trust boundary: responding only within a shared channel](#712-trust-boundary-responding-only-within-a-shared-channel)
    - [7.1.3 Tearing down a link once it no longer serves a purpose](#713-tearing-down-a-link-once-it-no-longer-serves-a-purpose)
    - [7.1.4 Showing which peers are actually reachable](#714-showing-which-peers-are-actually-reachable)
  - [7.2 Sending a channel or direct text message](#72-sending-a-channel-or-direct-text-message)
  - [7.3 Voice streaming](#73-voice-streaming)
  - [7.4 `Error { message: String }`](#74-error-message-string)
  - [7.5 `RotateKey` / `KeyRotated` - per-peer key rotation relay](#75-rotatekey-keyrotated---per-peer-key-rotation-relay)
  - [7.6 File transfer](#76-file-transfer)
- [8. Encryption model](#8-encryption-model)
  - [8.1 RSA-OAEP chunking](#81-rsa-oaep-chunking)
  - [8.2 Cost implication for voice](#82-cost-implication-for-voice)
  - [8.3 Password-derived keys](#83-password-derived-keys)
  - [8.4 RSA signatures](#84-rsa-signatures)
- [9. Versioning and compatibility](#9-versioning-and-compatibility)
- [10. What the server never sees](#10-what-the-server-never-sees)
- [11. Per-message key rotation (`rsa_per_msg`)](#11-per-message-key-rotation-rsa_per_msg)
  - [11.1 Granularity: per peer relationship, not global](#111-granularity-per-peer-relationship-not-global)
  - [11.2 Bootstrap (trust-on-first-use)](#112-bootstrap-trust-on-first-use)
  - [11.3 Rotation trigger and signing](#113-rotation-trigger-and-signing)
  - [11.4 Receiver-side verification and freshness](#114-receiver-side-verification-and-freshness)
  - [11.5 Queueing while waiting for a fresh key](#115-queueing-while-waiting-for-a-fresh-key)
  - [11.6 Voice streams count as one message](#116-voice-streams-count-as-one-message)
  - [11.7 Retained keys for late/batched decryption](#117-retained-keys-for-latebatched-decryption)
  - [11.8 What `rsa_per_msg` changes about the threat model](#118-what-rsa_per_msg-changes-about-the-threat-model)
  - [11.9 Key size: 4096 bits, not the app's usual 2048](#119-key-size-4096-bits-not-the-apps-usual-2048)
  - [11.10 Rotation keygen runs off the event-loop task (client implementation detail)](#1110-rotation-keygen-runs-off-the-event-loop-task-client-implementation-detail)
- [12. Client-side identity pinning (`id_store`)](#12-client-side-identity-pinning-id_store)
  - [12.1 The gap this closes](#121-the-gap-this-closes)
  - [12.2 What gets pinned, and what doesn't](#122-what-gets-pinned-and-what-doesnt)
  - [12.3 When the check happens](#123-when-the-check-happens)
  - [12.4 What happens on a mismatch](#124-what-happens-on-a-mismatch)
  - [12.5 Store format and location](#125-store-format-and-location)
  - [12.6 Extending identity pinning to `rsa_per_msg` (`own_next_keys`)](#126-extending-identity-pinning-to-rsa_per_msg-own_next_keys)
    - [12.6.1 What's persisted, on each side](#1261-whats-persisted-on-each-side)
    - [12.6.2 Sending: resuming on reconnect](#1262-sending-resuming-on-reconnect)
    - [12.6.3 Verifying: gate on sight, only a proof clears it](#1263-verifying-gate-on-sight-only-a-proof-clears-it)
    - [12.6.4 Why this is a different kind of "mismatch" than §12.2-§12.5](#1264-why-this-is-a-different-kind-of-mismatch-than-122-125)
    - [12.6.5 Store format and location (`own_next_keys`)](#1265-store-format-and-location-own_next_keys)
  - [12.7 Making a pin worth more than "these bytes differ"](#127-making-a-pin-worth-more-than-these-bytes-differ)
- [13. Post-quantum hybrid encryption (`pq_hybrid`)](#13-post-quantum-hybrid-encryption-pq_hybrid)
  - [13.1 Why a fifth method, and why it looks different](#131-why-a-fifth-method-and-why-it-looks-different)
  - [13.2 Key material: an identity that stays, keys that move](#132-key-material-an-identity-that-stays-keys-that-move)
  - [13.3 One layout for everything: a setup, then chunks](#133-one-layout-for-everything-a-setup-then-chunks)
  - [13.4 Opening a send: unwrap, verify, then check the binding](#134-opening-a-send-unwrap-verify-then-check-the-binding)
  - [13.5 Key size and parameter choices](#135-key-size-and-parameter-choices)
  - [13.6 Who can send to whom](#136-who-can-send-to-whom)
  - [13.7 Voice streaming (and file transfer chunks)](#137-voice-streaming-and-file-transfer-chunks)
  - [13.8 Identity pinning](#138-identity-pinning)
  - [13.9 Client convenience: auto-generated keys and the connect-popup cache](#139-client-convenience-auto-generated-keys-and-the-connect-popup-cache)
  - [13.10 Rotating encryption keys (forward secrecy)](#1310-rotating-encryption-keys-forward-secrecy)
- [14. The four encryption methods, side by side](#14-the-four-encryption-methods-side-by-side)
- [15. Sequences](#15-sequences)

## Overview: the connections, and what travels on each

A running client holds **one continuous connection to the server** and
**one direct connection per peer** it actually communicates with — so
between zero and N of them, N being the number of people it is talking to,
not the number of channels it has joined.

```
                        ┌────────────┐
                        │   server   │
                        └──────┬─────┘
                    one TCP connection,
                  continuous, encrypted (§1.3)
                               │
                        ┌──────┴─────┐
                        │  me        │
                        └──┬───┬───┬─┘
                           │   │   │      one direct UDP link per peer,
                           │   │   │      punched, carries everything (§7.1)
                      ┌────┘   │   └────┐
                   ┌──┴──┐  ┌──┴──┐  ┌──┴──┐
                   │alice│  │ bob │  │carol│
                   └─────┘  └─────┘  └─────┘
```

**The server connection** is opened once and held for the life of the
session. It sets things up and nothing more: authentication, nicknames,
channel membership and presence, relaying key rotations, and relaying the
address exchange that lets two clients find each other. **No message
content of any kind crosses it** — not text, not voice, not files, not
even as ciphertext (§7.1, §10).

**A peer connection** is one direct UDP link per *peer*, established by
hole punching (§7.1) the first time that peer is learned about. It is not
per channel and not per conversation: a single link to alice carries every
channel message she is a recipient of, every direct message, every voice
stream and every file transfer between the two of you. Two people who
share four channels still have exactly one link. If a link cannot be
established the send fails visibly — there is no relay of last resort.

A third, minor path exists: a **stateless UDP exchange with the server**
used only to learn one's own public address before punching (§7.1, step 1).
It carries no user data and keeps no state.

### Every message, by connection

**Server connection** — TCP, length-prefixed frames (§1.1), sealed after
the handshake (§1.3).

| Client → server | Purpose |
|---|---|
| `SecureChannel` | Turns the control channel on; must be first (§1.3) |
| `Auth` | Answers the server's challenge (§5) |
| `Identify` | Claims a nickname, announces a public key and method (§5.4) |
| `JoinChannel` | Joins or implicitly creates a channel (§6.1) |
| `LeaveChannel` | Leaves one channel (§6.2) |
| `RotateKey` | Offers a peer fresh key material (§7.5, §11, §13.10) |
| `RequestPeerLink` | Asks the server to pass candidates to a peer (§7.1) |

| Server → client | Purpose |
|---|---|
| `Hello` | Auth mode, challenge, control-channel offer (§1.3, §4) |
| `AuthResult` | Whether authentication succeeded (§5) |
| `IdentifyResult` | Whether the nickname was granted, and this client's `UserId` (§5.4) |
| `ChannelList` | The public channels, once, after identifying (§6.3) |
| `Joined` | Confirms a join, last in the join snapshot (§6.1) |
| `ChannelJoinFailed` | A join failed for a non-password reason (§6.1) |
| `ChannelJoinRejected` | A join needs a password, guessed wrong, or is banned (§6.5, §6.6) |
| `ChannelCreated` | A new public channel now exists (§6.3) |
| `UserJoined` | A peer is in a shared channel — carries their key (§6.1) |
| `UserLeft` | A peer left one channel (§6.2) |
| `UserOffline` | A peer's connection ended entirely (§6.4) |
| `KeyRotated` | A peer's relayed key rotation (§7.5, §11, §13.10) |
| `PeerCandidates` | A peer's relayed addresses, to punch against (§7.1) |
| `Error` | A soft, recoverable failure; the connection stays open (§7.4) |

**Peer connection** — UDP, punched. Two layers: the datagram itself, and
the payload carried inside a reliable or unreliable one.

| Punch datagram | Purpose |
|---|---|
| `Ping` / `Pong` | Opens and confirms the NAT mapping (§7.1) |
| `Keepalive` | Stops an idle mapping expiring (§7.1) |
| `Reliable` / `Ack` | The retransmitting layer text and files ride on (§7.1.1) |
| `Unreliable` | Voice chunks, which are not worth retransmitting (§7.3) |

| Peer payload | Carried | Purpose |
|---|---|---|
| `Envelope` | reliably | One text message, channel or direct (§7.2) |
| `FileOffer` | reliably | Offers a file; nothing is sent until accepted (§7.6) |
| `FileAccept` / `FileReject` | reliably | The recipient's decision (§7.6) |
| `FileChunk` / `FileEnd` | reliably | The file itself, once accepted (§7.6) |
| `StreamStart` / `StreamEnd` | reliably | Brackets one voice recording (§7.3) |
| `StreamKeySetup` | reliably | A `pq_hybrid` stream's key setup, sent once (§13.3) |
| *(voice chunks)* | unreliably | The audio, as `Unreliable` datagrams (§7.3) |

**Server UDP socket** — stateless, no user data.

| Message | Purpose |
|---|---|
| `BindingRequest` / `BindingResponse` | Learn this client's own public address (§7.1) |

§15 collects every one of these into end-to-end sequence diagrams —
connecting, meeting a peer, sending text, voice, file transfer, key
rotation, and replacing an identity.

## 1. Transport

- One TCP connection per client, held open for the life of the session.
- The protocol is symmetric in framing (both directions use the same
  frame format) but asymmetric in message types: a client only ever sends
  `ClientMessage` values and only ever receives `ServerMessage` values.
- There is no protocol version negotiation. Client and server are
  expected to be built from the same message definitions; there is no
  compatibility mechanism for mismatched versions (see §9 for what
  actually happens on a decode mismatch).

### 1.1 Framing

Every message, in either direction, is sent as one frame:

```
+----------------------------+----------------------------------+
| length: u32, big-endian    | payload: `length` bytes          |
+----------------------------+----------------------------------+
```

- `length` is the byte length of `payload` only (the 4-byte prefix itself
  is not counted).
- `payload` is the bincode encoding (§2) of exactly one `ClientMessage` or
  `ServerMessage` value.
- `length` must not exceed `MAX_FRAME_LEN = 64 * 1024 * 1024` (64 MiB). A
  length prefix over this limit is a hard protocol error - the reader
  aborts rather than allocating an attacker-controlled buffer.
- There is no inter-frame delimiter or padding; frames are simply
  concatenated back-to-back on the stream. A reader that has only part of
  a frame's bytes so far must wait for more.
- A clean TCP close (EOF) exactly at a frame boundary (i.e. before any
  byte of a new frame has arrived) is not an error - it's the normal way
  a connection ends. An EOF in the middle of a frame (after the length
  prefix or partway through the payload) is a hard I/O error.


### 1.2 Why length-prefixed framing

TCP is a byte stream with no message boundaries of its own. Framing is
required so a reader knows exactly how many bytes make up "the next
message" before attempting to decode it - without this, a reader would
have to speculatively try decoding an arbitrary prefix of the stream,
which bincode's schema-less format doesn't support safely.

### 1.3 The control channel is encrypted

Everything on this TCP connection is sealed, from the client's second
message onward. Only two frames ever travel in the clear - the server's
`Hello` and the client's `SecureChannel` - because they are what establish
the seal.

```
 client                                   server
   |<-- Hello { auth, challenge,            |   (in the clear)
   |            control: ControlOffer } ----|
   |                                        |
   |--- SecureChannel(ControlAccept) ------>|   (in the clear)
   |                                        |
   |=== everything after this is sealed ====|
```

```
ControlOffer  { encap: PqEncapKeys, signature: optional<bytes> }
ControlAccept { kem_ciphertext: bytes, wrapped_key: bytes[32],
                eph_x25519_pub: bytes[32] }
```

**Why.** Message content never touches the server at all (§7.1, §10), but
the conversation that sets a session up always travelled as plain TCP - and
it carries a `--password` credential in the clear (§5.2), nicknames,
which channels exist, who is in them, and the timing of every key rotation.
Sealing it changes nothing about what the *server* learns, since it still
has to route by these; it changes what anyone in between learns.

**How.** The construction is deliberately not new. The server's `encap` is
an ephemeral ML-KEM-1024 + X25519 pair, freshly generated per connection;
the client transports a random 32-byte secret to it through the identical
hybrid wrap a message send uses (§13.3), inheriting the same "a break of
either primitive alone is not enough" property. Both sides then derive two
keys from that secret:

```
c2s = HKDF-SHA256(secret, "aloo/control/v1/client-to-server")
s2c = HKDF-SHA256(secret, "aloo/control/v1/server-to-client")
```

A frame's *payload* is AES-256-GCM-sealed under the key for its direction,
with the direction's own message counter as the nonce; the length-prefixed
framing of §1.1 is untouched, and `length` simply counts the sealed bytes.
Separate keys per direction mean a captured frame cannot be reflected back
at its sender. A frame that fails its authentication tag is a hard error,
never a skipped message - on a sealed channel that means either tampering
or desynchronised counters, and both are fatal.

There is **no plaintext fallback**. A client whose first message is not
`SecureChannel` is not talked to at all; a fallback would be a downgrade
attack waiting to be used.

**Authenticating the server.** An ephemeral offer needs something
long-lived to vouch for it, or a man in the middle substitutes their own
and reads everything. When the deployment uses RSA auth (§5.3) the client
already holds the server's public key out of band, so the server signs its
offer with the matching private key:

```
signature = RSA-PSS over "aloo/control/v1/offer" ++ encode(encap)
```

and a client holding that key **requires** a valid one. An unsigned offer,
one signed by a different key, or one whose `encap` was swapped after
signing are all refused - each is exactly what an interceptor would
produce. This is the same shape as a TLS handshake signing an ephemeral key
exchange with a long-term identity.

Under `AuthKind::None` or `AuthKind::Password` there is no such key, and
the channel is then **encrypted but not authenticated**: it defeats a
passive observer, not an active man in the middle. That is a real limit of
those modes and is stated as one rather than implied away.

Because the offer is per connection and thrown away with it, recording a
session and later stealing the server's long-term key still does not
decrypt it - that key only ever signs, never encrypts.

## 2. Serialization

Payloads are encoded with [bincode](https://docs.rs/bincode) v2, using
its standard configuration:

- **Little-endian** integers.
- **Variable-length integer encoding** ("varint"): for an unsigned
  integer `u` (any width above `u8`, which is always exactly one byte):
  - `u < 251` → one byte, the value itself.
  - `251 <= u < 2^16` → byte `251`, then a little-endian `u16`.
  - `2^16 <= u < 2^32` → byte `252`, then a little-endian `u32`.
  - `2^32 <= u < 2^64` → byte `253`, then a little-endian `u64`.
  - (`2^64 <= u < 2^128` → byte `254`, then a `u128` - not used by this
    protocol, no field is `u128`.)
  - Signed integers are first zigzag-mapped to unsigned (`0,-1,1,-2,2,...`
    → `0,1,2,3,4,...`) and then varint-encoded the same way. This
    protocol has no signed integer fields either, but `stream_id: u64`
    and `seq: u32` (both unsigned) do use this varint form - in practice
    almost every real value (small channel counts, sequence numbers under
    251, `UserId`s from a server that's had fewer than 251 connections)
    encodes as a single byte.
- **Enum variants** are encoded as a leading `u32` variant index (0-based,
  in declaration order, varint-encoded per above - one byte for every
  enum in this protocol, since none has anywhere near 251 variants),
  followed by that variant's fields in declaration order. There is no
  variant name on the wire.
- **`optional<T>`**: one byte, `0` for absent or `1` for present, followed by
  the encoded `T` if `Some`.
- **`string`, `list<T>`, `bytes`**: a varint-encoded length (element/byte
  count, not byte-length-of-encoding), followed by the encoded elements
  (raw UTF-8 bytes for `String`/byte strings; each element's own encoding,
  concatenated, for `list<T>`).
- **Structs and tuples**: fields encoded in declaration order, back to
  back, with no field names, type tags, or padding on the wire.

This is a **schema-less** format: nothing on the wire identifies which
type or which struct/enum version produced it. A decoder must already
know the exact expected type (which is always statically known here -
e.g. the handshake always reads a `ClientMessage::Auth` first) and that
type's exact shape must match what the encoder used, field-for-field,
variant-index-for-variant-index. Reordering, adding, or removing a field
or enum variant changes the wire format and breaks compatibility with any
peer built from the old definitions - see §9.


## 3. Domain types

These are referenced throughout the message definitions below.

```
UserId = u64
```
Server-assigned on a successful `Identify` (§5.4), from a simple
per-server counter (`next_id`, starting at 1, incremented on every
successful registration). The counter only ever increases - a `UserId`
value is **never reused**, even after its holder disconnects, for as long
as that server process keeps running (the counter is in-memory only and
resets to 1 on a server restart). This is a different thing from the
*nickname* (`display_name`), which **is** freed for reuse as soon as its
holder disconnects (§5.4) - two different clients can be assigned the
same nickname over time, but never the same live `UserId`.

```
UserInfo {
    id:             UserId
    name:           string
    public_key_der: bytes     // see below
    key_mode:       KeyMode
}
```

`public_key_der` is a DER-encoded RSA SubjectPublicKeyInfo for every
`KeyMode` except `pq_hybrid`, whose identity is a keybundle rather than one
key - it carries its encoded key bundle in this same field (§13) rather
than growing the wire shape. Under `rsa_per_msg` this is only ever the
*bootstrap* key from that user's `Identify` (§5.4): the per-peer keys that
supersede it are never reflected here, only relayed via `KeyRotated`
(§7.5, §11). Under `pq_hybrid` likewise, the bundle carries only bootstrap
encryption keys (§13.10).

```
KeyMode = Rsa | Password | None | PerMessage | PqHybrid
```

The five values name how a client's own `my_key` was obtained, and whether
it changes:

| value | `my_key` type | key material | changes? |
|---|---|---|---|
| `Rsa` | `rsa` | one keypair loaded from a file | no |
| `Password` | `password` | one keypair derived from a password (§8.3) | no |
| `None` | `none` | one keypair generated at connect time | no |
| `PerMessage` | `rsa_per_msg` | a rotating keypair per peer (§11) | every message |
| `PqHybrid` | `pq_hybrid` | a keybundle loaded from a file (§13) | signing half no, encryption half every message (§13.10) |

`PerMessage` is what tells a peer to expect `KeyRotated` rather than
treating `public_key_der` as good for the session; `PqHybrid` sends
`KeyRotated` too, but for its encryption keys only (§13.10). §14 compares
the four *methods* these five values describe.

`Rsa`, `Password`, `None`, and `PqHybrid` are all "static" for protocol
purposes - exactly one keybundle for the whole session, no rotation - and
behave identically everywhere in this document except two things: which of
the five they are is broadcast (via `Identify` → `UserInfo`, unchanged wire
shape from before, only the enum grew variants) precisely so every peer can
render the right tag next to that user's name (sidebar, private-room
title - SPEC.md Functionality #3/#6); and `PqHybrid` alone changes what
`public_key_der` actually contains and how `Envelope.blocks` is produced -
see §13.

| `KeyMode`    | Tag           | Position (`KeyMode::format_with_name`) |
|--------------|---------------|------------------------------------------|
| `PerMessage` | `🔒 RSAPM`    | after the name: `name 🔒 RSAPM`          |
| `Rsa`        | `🔒 RSA`      | after the name: `name 🔒 RSA`            |
| `Password`   | `🚨 PWD`      | after the name: `name 🚨 PWD`            |
| `None`       | `🚨 PLAIN`    | after the name: `name 🚨 PLAIN`          |
| `PqHybrid`   | `🛡️ PQH`      | after the name: `name 🛡️ PQH`            |

(`KeyMode::label()` returns just the tag, unbracketed; `format_with_name`
composes it with a name, tag trailing, the same position for all five
variants.) Every tag trails the name as an annotation on it, not a
classification label sitting in front - `PerMessage` is the moving-target
case that always worked this way (a new key every message), and the other
four now read the same way for consistency. The icon is about identity
*durability*, not "unencrypted" - every `KeyMode` still encrypts every
message with real per-recipient encryption (RSA, or for `PqHybrid` the
hybrid scheme in §13); `🚨` just flags the two sourcings (`Password`,
`None`) that don't persist an identity across separate connections the way
a saved `rsa` keypair file does. `🛡️` is `PqHybrid`'s own icon rather than
reusing `🔒` - it is file-backed and durable like `Rsa`, but deliberately
given a distinct mark to read as the strongest tier (quantum-resistant
signing *and* key exchange, each additionally hedged with RSA-4096). Prior
to `PqHybrid`, only two states (`Static`/`PerMessage`) were
wire-visible and a peer's specific `rsa`/
`password`/`none` choice was locally forgotten immediately after resolving
the keypair (§8.3) - this is a genuine (if small) protocol change: every
peer must be rebuilt from the same `KeyMode` definition (§9), same as any
other change to this enum.

```
ChannelKind = Public | Private

ChannelInfo { name: string, kind: ChannelKind }
```
`Public` channels are advertised to every client via `ChannelList` (§6.3);
`Private` channels are never advertised - a client must already know the
exact name to join one.

```
AuthKind = None | Password | Rsa
```
What the server requires to authenticate a new connection - see §5.

```
AuthResponse =
    | None
    | Password(string)
    | Rsa { blocks: list<bytes> }   // the challenge nonce, RSA-OAEP
                                    // encrypted with the server's key (§8)
```

```
Envelope {
    content: Content        // Text | FileOffer
    blocks:  list<bytes>    // what these bytes are depends on the
                            // recipient's method: N RSA-OAEP blocks
                            // (§8.1) or one sealed send (§13.3)
}
```
`Envelope` is the unit of one complete, whole (non-streamed) encrypted
message body, addressed to exactly one recipient. Voice is never sent as a
whole `Envelope` (see §7.3); neither is a file's actual bytes, once
accepted - `FileOffer` is only the *offer* that precedes a file transfer
(§7.6), the one part of that exchange that fits this shape (a discrete,
one-shot decision, unlike the stream of chunks that follows it).

## 4. Connection lifecycle

```
 client                                   server
   |                                         |
   |--- TCP connect ------------------------>|
   |                                         |
   |<-- Hello { auth, challenge } -----------|
   |                                         |
   |--- Auth(response) --------------------->|
   |                                         |
   |<-- AuthResult { ok, reason } -----------|
   |        (ok == false => connection closed by server, see §5)
   |                                         |
   |--- Identify { display_name,             |
   |               public_key_der,           |
   |               key_mode } -------------->|
   |                                         |
   |<-- IdentifyResult { ok, you, reason } --|
   |        (ok == false => connection closed by server, see §5.4)
   |                                         |
   |<-- ChannelList(public_channels) --------|
   |                                         |
   |        ... connected: any ClientMessage /
   |            ServerMessage other than Auth/
   |            Identify may now flow either way ...
```

- The server always speaks first: it sends `Hello` immediately on
  accepting the TCP connection, before reading anything.
- The client's next message **must** be `Auth`; any other message (or a
  clean disconnect) at this point causes the server to send
  `AuthResult { ok: false, reason: Some("expected auth message") }` and
  close the connection.
- On successful auth, the client's next message **must** be `Identify`;
  otherwise the server sends
  `Error { message: "expected identify message" }` and closes the
  connection. (Note this is `ServerMessage::Error`, not `AuthResult` -
  an asymmetry in the reference implementation, not a meaningfully
  different failure mode from a client's perspective: either way, the
  next thing that happens is the connection closing.)
- `IdentifyResult` and `ChannelList` are queued by the server back-to-back,
  immediately after successful identification, into that connection's own
  outbound queue, ahead of anything else - a client can rely on receiving
  them consecutively, in that order, as the first two messages after a
  successful `Identify`.
- Once past `Identify`, the connection is "connected": `Auth` and
  `Identify` are no longer valid to send. Sending either again does *not*
  close the connection - the server responds with
  `Error { message: "unexpected message after handshake" }` and keeps
  the connection open, ready for the next message. This is a real
  asymmetry versus the pre-handshake failures above (which do close the
  connection) and any implementation should not assume sending a stray
  `Auth`/`Identify` post-handshake is fatal.
- There is no explicit logout/disconnect message. A client ends its
  session by closing the TCP connection; the server detects this (EOF or
  I/O error on read) and removes the client from every channel it was in,
  notifying every peer who shared any of those channels with it via
  `UserOffline { user_id }` (§6.4) - **not** `UserLeft`, which is reserved
  for an explicit single-channel `LeaveChannel` while the sender stays
  connected elsewhere - then forgets the client's `UserId`/nickname/public
  key entirely.


## 5. Authentication

The server is started with exactly one of three auth modes
(`aloo --server [--password <p> | --enc rsa <keyfile>]`); the client
discovers which one is in effect from `Hello.auth` and must respond with
the matching `AuthResponse` variant. Sending the wrong `AuthResponse`
variant for the advertised `AuthKind` is treated as authentication
failure (`AuthResult { ok: false }`), same as a genuinely wrong
credential.

### 5.1 `AuthKind::None`

`Hello.challenge` is `None`. The client must respond
`Auth(AuthResponse::None)`. Always succeeds.

### 5.2 `AuthKind::Password`

`Hello.challenge` is `None`. The client must respond
`Auth(AuthResponse::Password(plaintext_password))`. The password is
plaintext *inside the frame*, but the frame itself is sealed (§1.3) - this
message travels after `SecureChannel`, so it is not on the wire in the
clear. Note the limit that goes with it: a `--password` server has no
long-term key to sign its control offer with, so that channel is encrypted
but unauthenticated (§1.3). The server compares it against its configured `--password` value
using a constant-time comparison (a constant-time comparison) to avoid
leaking a timing side-channel about where the strings first differ.

### 5.3 `AuthKind::Rsa`

`Hello.challenge` is `Some(nonce)`, a fresh 32 random bytes generated per
connection (32 random bytes). The client must:

1. Encrypt `nonce` with the server's public key (which the client must
   already possess out-of-band, as its configured `server_key` file, see
   README.md's "Generating RSA keys") using RSA-OAEP/SHA-256, splitting
   into multiple blocks if needed (§8.1 - for a 32-byte nonce and any key
   ≥ 226 bits this is always exactly one block in practice).
2. Respond `Auth(AuthResponse::Rsa { blocks })`.

The server decrypts `blocks` with its own private key and compares the
result to the original `nonce` byte-for-byte (constant-time). This proves
the client holds the private key matching the `server_key` the server was
started with, without the private key ever crossing the wire.

### 5.4 Identify / nicknames

After a successful `Auth`, the client sends exactly one `Identify`:

```
Identify { display_name: string, public_key_der: bytes, key_mode: KeyMode }
```

`public_key_der` is the client's own DER-encoded RSA public key (its
`my_key` - see README.md; this is *independent* of whatever key material
was used for the `server_key` challenge in §5.3, if any) - or, for
`key_mode == PqHybrid`, a bincode-encoded `PqPublicBundle` instead (§13) -
other clients
use this to encrypt messages addressed to this user (§7.2, §8).

`key_mode` (§3) tells every peer, up front, whether `public_key_der` is
good for the whole session (`Rsa`/`Password`/`None`) or is only a
*bootstrap* key that individual peer relationships will supersede via
`KeyRotated` the first time a message is exchanged with them (`PerMessage`
- `rsa_per_msg`; see §11). The server itself does not branch on `key_mode`
beyond storing and relaying it as part of `UserInfo`, and using it to
validate `RotateKey` (§7.5) - it never gates ordinary messaging on it.

The server enforces that `display_name` is not currently in use by any
other connected client - matching is case-sensitive (`"dave"` and `"Dave"`
are different nicknames and may be held by two different clients at once)
- the check-and-register happens atomically under the server's single
registry lock, so two simultaneous `Identify`s for the same name cannot
both succeed. On success, the server assigns a fresh
`UserId` and responds `IdentifyResult { ok: true, you: Some(id), reason: None }`.
On a name collision, it responds
`IdentifyResult { ok: false, you: None, reason: Some(String) }` (the
reason names the taken nickname) and closes the connection immediately
after - the client must reconnect (a new TCP connection, restarting from
`Hello`) with a different `display_name` to retry. A nickname becomes
available again as soon as its holder's connection closes (see §4).


## 6. Channels

A channel is identified purely by its `name: String` (no separate numeric
ID) and is created implicitly by the first `JoinChannel` that references
it - there is no separate "create channel" message. The server always
seeds one channel, `DEFAULT_CHANNEL_NAME` (`"the-hall"`, `ChannelKind::
Public`), before any client connects - the one channel that survives being
emptied (§6.2).

A channel tab is shown prefixed with an emoji naming its kind at a glance,
followed by a space before the name: 🌍 for public, 🔒 for private
(the channel view).

### 6.1 `JoinChannel { name, kind, password }`

- `name` must pass the channel-name rule: non-empty, at most
  `CHANNEL_NAME_MAX_LEN` (21) characters, and every character an ASCII
  letter, digit, or `-`. This is enforced identically by the client (a
  per-keystroke guard in the Ctrl+J popup that simply refuses to type an
  invalid character or grow past the cap) and, independently, by the
  server (the join path, since the server never trusts the
  client) - both call the same `validation` module so the two can't
  silently disagree. A server-side rejection is `ChannelJoinFailed { name,
  reason }`, same as any other failure below.
- If `name` doesn't exist yet, it's created with the given `kind`, and
  `password` (if `Some` and non-empty) becomes that channel's password -
  see §6.5. A password given alongside `ChannelKind::Public` is silently
  ignored; public channels are never password-protected.
- If `name` already exists, the given `kind` is ignored - the channel
  keeps whatever kind it was created with. (There is no message to
  change a channel's kind or password after creation.) If it's a
  password-protected private channel, `password` is instead checked
  against the stored one - see §6.5.
- Joining a channel you're already a member of is a no-op: no messages
  are sent, not even a repeat `Joined`. (A password is not re-checked for
  an already-joined channel.)
- On a genuinely new join, the server sends (there is no ordering
  guarantee *between* different recipients' messages - each client's
  outbound queue is independent - but the ordering *within* each
  recipient's own stream, described below, is guaranteed):
  - **The new joiner** receives one `UserJoined { channel: name, user: <info> }`
    per existing member, iterated in ascending-`UserId` order (ascending
    `UserId`, not join order) - this is how the joiner learns every other
    current member's `public_key_der` (§3), needed to encrypt messages to
    them (§8) - followed, last, by exactly one
    `Joined { channel: ChannelInfo { name, kind } }`, the confirmation
    that the join itself succeeded. The joiner never receives a
    `UserJoined` about themselves. Since this snapshot arrives *before*
    `Joined`, and a client may not have a local notion of `name` yet at
    that point (a private channel is never pre-known via `ChannelList`; a
    public one typed directly into Ctrl+J may not be either), the client
    must create its local channel record on the first `UserJoined` for an
    unrecognized name, not wait for `Joined` - the client
    does this (TB-159); waiting would silently lose the whole snapshot.
  - **Each existing member** receives exactly one
    `UserJoined { channel: name, user: <the new member's UserInfo> }`,
    telling them about the joiner (and the joiner's `public_key_der`, so
    they can now encrypt to the joiner too).
- A `JoinChannel` for a `name` that fails for a reason unrelated to a
  channel password (currently: an invalid name, or `join_channel`'s
  user-not-found case, which in practice can't happen for an
  already-identified connection) results in `ChannelJoinFailed { name,
  reason }` sent to the requester only. The password-specific outcomes
  (§6.5/§6.6) instead use the typed `ChannelJoinRejected` variant.

### 6.2 `LeaveChannel { name }`

Removes the sender from `name`'s membership, if they were a member (a
no-op, no messages sent, if `name` doesn't exist or they weren't a
member). Every *remaining* member receives `UserLeft { channel: name,
user_id }` - the leaver themselves gets no acknowledgment at all. An
emptied channel is deleted outright - public or private alike - *unless*
`name` is `DEFAULT_CHANNEL_NAME` (`"the-hall"`), which survives being
empty forever (until server restart); any other channel's next
`JoinChannel` recreates it fresh, with no memory of previous membership.

Since there's no server acknowledgment to the leaver, the client applies
`/leave` optimistically: the moment it's submitted (`UiState::
leave_channel_locally`), before the `LeaveChannel` write even reaches the
server. A **private** channel's tab is removed from the client entirely -
it's never re-advertised, so a ghost tab has nothing to reconnect it to. A
**public** channel's tab instead stays, marked `left`: selecting it shows
a rejoin prompt instead of the normal view (SPEC.md Functionality), and
the dwell timer (§6's `[`/`]`) won't silently re-join it - only an
explicit rejoin does. See §7.1.3 for what leaving does to any P2P links
that were only justified by that channel's membership.

### 6.3 `ChannelList(list<ChannelInfo>)` / `ChannelCreated { channel }`

`ChannelList` is sent once, right after `IdentifyResult` (§4) - **public
channels only**, sorted by name. `ChannelCreated { channel: ChannelInfo }`
is the live follow-up: sent to every *other* currently-connected client
the instant a genuinely new public channel is created (`Registry::
join_channel`, `!existed_before && kind == Public`), so a channel created
after the initial snapshot doesn't stay invisible to everyone who didn't
create or join it. A **private** channel creation never triggers this -
it stays unadvertised exactly as `ChannelList` already keeps it. Joining
an *already-existing* channel (public or private) never re-triggers it
either - only genuine creation does. Like every other channel-membership
message, a client learns about a private channel only out-of-band (the
protocol has no "invite" message).

### 6.4 `UserOffline { user_id }` - full disconnect

Sent instead of `UserLeft` (§6.2) when a client's connection closes
entirely (§4), rather than it sending an explicit `LeaveChannel` for one
channel while staying connected elsewhere. Server-side (`Registry::
unregister`), on disconnect:

- `id` is removed from every channel it was a member of, exactly as
  `leave_channel` would do to each one individually (including deleting
  an emptied private channel) - the server keeps no server-side notion of
  "offline but still a member"; membership bookkeeping is unaffected by
  which message type gets sent.
- The set of peers to notify is the *union* of remaining members across
  every one of those channels, deduplicated - a peer who shared two
  channels with the disconnecting client still receives exactly one
  `UserOffline { user_id }`, not one per shared channel. This is the one
  place this protocol deliberately collapses a per-channel event into a
  single per-peer one; `UserJoined`/`UserLeft` never do this because they
  each name the one channel they're about.
- `UserOffline` carries no `channel` field, unlike `UserLeft` - by design,
  since it means "this identity is gone", not "left this one channel".
  Client-side, a recipient is expected to apply it to every channel where
  it currently has `user_id` listed, not just one.

This split exists purely for the client UI behavior in SPEC.md's
"Offline users" section: a client that has private-message history with
`user_id` keeps them listed (grayed out, not removed) in every channel
they were in, precisely because `UserOffline` (unlike `UserLeft`) doesn't
imply "no longer relevant to this channel" - it implies "no longer
reachable, but still someone you've talked to." A client with no such
history is free to (and, in the reference implementation, does) drop
`user_id` from its channel member lists exactly as it would for
`UserLeft`.

### 6.5 Password-protected private channels

A private channel may optionally be created with a password (Ctrl+J's
popup, Private selected, a non-empty password typed). The password is
fixed at creation, exactly like `kind` - there is no message to change or
remove it afterward, and it is stored on the server only, never persisted
to disk and never sent to anyone but the client that set it (the joiner
still needs to already know it, out of band, exactly as they need to
already know the channel's name).

**Format** (the channel-password rule, enforced identically
client- and server-side, same reasoning as §6.1's name validation): at
most `CHANNEL_PASSWORD_MAX_LEN` (50) characters, each an ASCII letter,
digit, or one of `! @ # $ % ^ & * - _ + = . ,`. This applies only when a
password is being *set* (channel creation) - a join-time guess is never
format-checked, since any string is a valid attempt, right or wrong, and
a constant-time comparison simply returns false for a malformed one; a
separate "malformed guess" error would be redundant with plain
`WrongPassword` below.

**Comparison** is constant-time (a constant-time comparison, the same
function and rationale as §5.2/TB-015's auth credential check), so a
private channel's password can't be brute-forced by timing.

**Outcomes**, on a `JoinChannel` against an existing password-protected
channel by a non-member, before the ordinary join logic ever runs:

```
ChannelJoinRejected { name: String, kind: ChannelJoinRejection }

enum ChannelJoinRejection {
    PasswordRequired,  // no password was supplied at all
    WrongPassword,      // a password was supplied but didn't match
    Banned,              // see §6.6 - refused without even comparing
}
```

sent to the requester only - like `ChannelJoinFailed`, nothing about a
private channel's existence, membership, or password state leaks to
anyone else through this. `PasswordRequired` does not count toward §6.6's
attempt limit (an honest first-timer who didn't know a password was
needed yet hasn't actually *guessed* wrong); only an actual mismatched
guess does. A successful join resets that channel's attempt counter for
the joining address to zero.

Client-side, receiving any `ChannelJoinRejected` opens a dedicated
password-entry popup (a password-entry popup) naming the channel and
showing a message for `WrongPassword`/`Banned` (blank for a fresh
`PasswordRequired`), distinct from the free-text `ChannelJoinFailed`
popup-less path - letting the user retype and resubmit the same
`JoinChannel` without re-typing the channel name.

### 6.6 Brute-force protection

More than `CHANNEL_MAX_PASSWORD_ATTEMPTS` (7) wrong-password attempts
against one **(source IP address, channel name)** pair bans further
attempts against that specific channel from that specific address for
`CHANNEL_PASSWORD_BAN_DURATION` (2 hours) - every attempt during the ban,
right password or wrong, is refused as `ChannelJoinRejected { kind:
Banned }` without even being compared.

Keyed by source IP, not `UserId`: a `UserId` is never reused (§3, TB-020)
- a client that disconnects and reconnects always gets a brand new one, so
a ban keyed by `UserId` alone would be trivially bypassed by simply
reconnecting. The IP is taken from the already-open TCP connection
(the connection's source address), not anything the client asserts.

Tracked in server memory only (the attempt counter), not
persisted to disk - a server restart clears every ban, the same scope
tradeoff `AuthConfig`'s in-memory-only session state already makes
elsewhere in this document.


## 7. Messaging

All message content - text and voice alike - is encrypted **per
recipient** (see §8 for why no shared/session key is used, and what that
costs) *and* delivered directly, client to client, over the punched UDP
link §7.1 establishes. The server is never in this data path at all - not
as a relay of ciphertext, not even briefly - it only ever helps two
clients find each other's address in the first place.

### 7.1 Direct peer-to-peer transport

Before any message/voice/file content can move between two clients, they
need a direct UDP path to each other. This section covers how that path
is found and used; §7.2-§7.6 cover what actually travels over it once
it exists.

**Trigger**: eager, the moment a client first learns a peer exists at all
(`ServerMessage::UserJoined` - covers both "they're already in a channel
you just joined" and "someone new joined a channel you're in", and
implicitly covers DMs too, since you can only open one with someone
you've already learned about this way). Revised from an earlier
lazy-on-first-send design once testing showed the gap it left: text and
file sends tolerate a not-yet-`Active` link by queuing (§7.2/§7.6), but
voice does not (§7.3) - a `Rsa`/`Password`/`None`/`PerMessage` recipient
whose link is still mid-punch at the exact moment someone starts a
recording is excluded from it outright, so a purely lazy trigger meant
the *first* voice message to any brand-new peer was reliably missing them
entirely, even though the punch itself typically finishes in well under a
second. Triggering the handshake as soon as the peer is known instead
gives it the whole gap between "you learn about them" and "you actually
press record" as a head start - on any reasonable network that's normally
far longer than the handshake needs. A peer who receives a candidate
proposal (below) - whether prompted by this eager trigger or an explicit
send - treats it as an implicit invitation and punches back if it hasn't
already started its own attempt, so being addressed first works either
way. A failed *eager* attempt (nobody ever actually tried to reach that
peer) fails silently - no visible error - since most co-channel members
are never actually addressed; §7.1's visible failure is reserved for
content that was genuinely waiting on a link. The attempt itself is
retried regardless (step 4), and the peer's sidebar colour tracks it
either way (§7.1.4).

**1. Candidate gathering** (once per session): each client binds one UDP
socket for the whole session and gathers two kinds of candidate address
for it - its own local interface addresses (`if-addrs`, pairing every
interface with the bound port), and a *server-reflexive* address learned
via a stateless STUN-Binding-style exchange with the server's own UDP
socket (bound on the same numeric port as its TCP listener):

```
// client -> server UDP socket and back; never touches the TCP connection
// or any server state
RendezvousMessage =
    | BindingRequest  { token: u64 }
    | BindingResponse { token: u64, observed: SocketAddr }
```

The server echoes back exactly the address the request arrived from -
this is the client's own public (NAT-mapped) address, which it has no way
to learn about itself. No auth, no state kept between requests: this
reveals nothing about a sender beyond what any UDP packet it sends
already reveals to whoever receives it, the same threat model as a public
STUN server. A client that gets no reply within a short timeout (old
server, outbound UDP blocked, ...) proceeds with host candidates alone.

**2. Signaling the peer, over the existing TCP connection**:

```
// client -> server
RequestPeerLink { peer: UserId, candidates: list<SocketAddr>, link_nonce: u64 }

// server -> client
PeerCandidates  { from: UserId, candidates: list<SocketAddr>, link_nonce: u64 }
```

The relay checks only that `peer` is currently connected - an unknown
recipient is an `Error`, and nothing else is validated or stored. Same
shape as §7.5's `RotateKey`/`KeyRotated`.

The initiator's own candidates are relayed to the peer; if the peer has
no link state yet for this sender, it replies in kind with its own
`RequestPeerLink` (same `link_nonce`, echoed) - one extra round trip gives
both sides the other's full candidate list.

**3. Punching**, entirely direct between the two clients (the server is
no longer involved at all from this point on):

```
PunchDatagram =
    | Ping       { link_nonce: u64 }
    | Pong       { link_nonce: u64 }
    | Keepalive  { link_nonce: u64 }
    | Ack        { seq: u32 }
    | Reliable   { seq: u32, payload: bytes }              // §7.1.1
    | Unreliable { stream_id: u64, seq: u32, blocks: list<bytes> }
```

`link_nonce` is one value shared by both sides of a link, not a
per-side token: the responder echoes the initiator's, and when both
initiate at once - the normal case, since both pre-warm on `UserJoined` -
both take the numerically smaller of the two. Against an already-`Active`
link a *differing* nonce means the peer gave up and started a fresh
attempt, and is followed rather than tie-broken. It is 64 random bits
that only ever travel over the authenticated TCP control connection, so
an off-path attacker cannot guess one; this is the role ICE's
ufrag/pwd plays.

Each side sends `Ping{link_nonce}` to every one of the other's
candidates in parallel, repeating every tick (~150ms) while unconfirmed.
A `Ping` or `Pong` is attributed to a link by its *source address* where
that is already known, and otherwise by its `link_nonce` against a link
currently being established - and in that second case the source address
is adopted as a **peer-reflexive candidate**, probed from then on like
any other, and usable for data frames. This is what makes a peer behind a
NAT that maps a different external port per destination (symmetric or
carrier-grade NAT) reachable at all: their probe arrives from an address
neither side could have advertised, and without learning it the link can
never open in that direction. Attribution by nonce is deliberately
limited to links being established - letting an unauthenticated datagram
move an already-`Active` link's address would be a hijack primitive,
whereas a peer that genuinely remaps mid-session is caught by the
liveness check in step 4 and re-punched from scratch. A probe whose nonce
matches no link being established is ignored rather than answered, so
this never becomes a reflector for anyone scanning the socket. Data
frames (`Ack`/`Reliable`/`Unreliable`) carry no nonce and are only ever
attributed by source address.

A side only trusts a `Pong` whose nonce matches its own current attempt;
the first one it receives locks in *the address it actually came from* -
frequently not any address that was advertised - as the link's active
address, and the link is now `Active`.

**4. Establishment is continuous, and there is still no fallback.**
A link that does not open (no candidate reply within `SIGNAL_TIMEOUT`, or
no confirmed `Ping`/`Pong` round trip within `PUNCH_TIMEOUT`, both 10
seconds) is not abandoned. It is re-signalled through the server
automatically, on a backoff doubling from `RETRY_BASE` (1s) and capped at
`RETRY_MAX` (30s), for as long as the peer is still known at all - only
losing every shared channel and DM with them (§7.1.3) stops it. A peer
being online means a direct path may become possible at any moment: their
NAT rebinding, a VPN dropping, a firewall rule changing. A user-initiated
send skips the remaining backoff, and a peer's own fresh invite re-arms a
lost link immediately.

Once `Active`, an idle link gets a `Keepalive` datagram after
`KEEPALIVE_INTERVAL` (15 seconds) of no other traffic, to keep the
NAT/firewall mapping from expiring. Those beats are also what make the
link's *liveness* observable: receiving nothing at all - keepalives
included, not just content - for `LINK_IDLE_TIMEOUT` (45 seconds, three
missed beats) means the link died without either side noticing, so it is
marked lost and re-punched like any other failed attempt.

Content addressed to a link that is not up is held, not dropped, and
flushed in order once it opens (§7.1.1). What surfaces to the user is
therefore not "the punch failed" - which is routine and usually
recovers - but "this content could not be delivered": once something has
been queued undeliverably for `PENDING_MAX_AGE` (60 seconds) it is
dropped and reported, naming why. There is deliberately no
relay-of-last-resort through the server - see the top of this document.

**5. Keeping our own address true.** The server-reflexive candidate is
re-learned every `REFLEXIVE_REFRESH_INTERVAL` (15 seconds) for the whole
session, not once at startup. This does two jobs: it keeps the NAT
mapping that address names from expiring while the client sits idle -
without it, a client that connects and waits advertises a mapping its NAT
dropped minutes ago - and it keeps the advertised address true. An
observed address that has changed replaces it and re-signals every link
that is not already up. Links that *are* up are left alone: on a
symmetric NAT the server-facing mapping is independent of the peer-facing
ones, so a change here says nothing about whether a working peer path
still works, and the liveness check above catches it if it does not.


#### 7.1.1 Reliable delivery over the punched link

UDP gives no ordering or delivery guarantee, so text and file content -
which must arrive complete and in order, unlike voice (§7.3) - get a
small hand-rolled reliable layer on top, carried
inside `PunchDatagram::Reliable { seq, payload }`:

- **Sender** (the sender): assigns an increasing `seq` to each outgoing
  payload, retransmits on a timeout with capped exponential backoff
  (400ms initial, doubling up to 3s), and after 10 retries with no ack
  treats the link as dead - which per §7.1 means re-punching it, not
  giving up on the content: anything still unacknowledged goes back onto
  the pending queue to be re-sent once the link reopens.
- **Receiver** (the receiver): acks every `Reliable` frame it sees
  immediately, even a duplicate or an out-of-order one; delivers frames to
  the application in order, buffering ones that arrive ahead of the
  expected sequence (bounded to 64 buffered frames - exceeding that fails
  the link rather than growing unbounded) and dropping duplicates.

The sequence space belongs to one punched link: both sides restart it
from zero when a link is re-punched, which they can do safely because
neither can transmit on the new link until both have entered the new
attempt.

This is deliberately minimal - no congestion control, no selective-repeat,
no cumulative acks - since it operates at chat-message/file-chunk
granularity, not bulk throughput.

**Datagram size.** A `Reliable`/`Unreliable` frame is one raw UDP datagram
- there's no length-prefixed framing to split an oversized payload across
multiple sends the way TCP's own segmentation would (§1.1's `MAX_FRAME_LEN`
governs the old TCP path, not this one). A datagram larger than a path's
MTU gets IP-fragmented, and plenty of real-world NATs/firewalls drop a
fragmented UDP datagram outright the moment any one fragment goes missing
- worse than just keeping every datagram small in the first place.
`SAFE_DATAGRAM_BYTES` (1200 bytes) is the target ceiling every
sender is expected to stay under; `FILE_CHUNK_BYTES` (§7.6)
and `CHUNK_INTERVAL` (§7.3) are both sized so an RSA-family
recipient's worst-case ciphertext clears it comfortably. `pq_hybrid` is the
one content type that can't: see §7.3/§7.6/§13.3 for why its fixed
per-chunk overhead makes this unavoidable regardless of chunk size.

`payload` (once reassembled) decodes to:

```
P2pPayload =
    | Envelope       { channel: optional<string>, envelope: Envelope }        // §7.2
    | FileOffer      { channel: optional<string>, stream_id: u64,
                       envelope: Envelope }                                  // §7.6
    | StreamStart    { channel: optional<string>, stream_id: u64 }           // §7.3
    | StreamKeySetup { stream_id: u64, setup: bytes }                        // §13.3
    | StreamEnd      { stream_id: u64, duration_ms: u32 }                    // §7.3
    | FileAccept     { stream_id: u64 }                                      // §7.6
    | FileReject     { stream_id: u64 }                                      // §7.6
    | FileChunk      { stream_id: u64, seq: u32, blocks: list<bytes> }       // §7.6
    | FileEnd        { stream_id: u64 }                                      // §7.6
```

`StreamKeySetup` carries a `pq_hybrid` stream's `SendSetup` (§13.3),
reliably and exactly once per recipient, immediately after `StreamStart`
(and, for a file transfer, immediately after the recipient's
`FileAccept`). Only `pq_hybrid` recipients ever receive it - an RSA-family
recipient's chunks need no setup at all.

None of these carry a `to`/`from` - the punched link's own address
already identifies which peer sent it. `channel: Some(name)` addresses a
channel send (kept purely for the receiver's own UI bucketing - there is
no server-side membership check to lean on anymore, so a client is
trusted to only address peers it actually intends to); `None` is a DM.

Voice chunks (`PunchDatagram::Unreliable`) bypass this layer entirely -
see §7.3.

#### 7.1.2 Trust boundary: responding only within a shared channel

`RequestPeerLink`/`PeerCandidates` (step 2 above) is an existence-check-only
relay (the relay) - the server checks that `peer`
is a currently-connected `UserId` and nothing more, so any registered
client can address a link request to any other registered `UserId`,
whether or not the two have ever shared a channel. Left unchecked, this
would let a stranger who merely learns someone's `UserId` get that
person's client to respond to punch traffic at all.

The receiving client closes this gap itself, since the server has no
membership list left to validate against (§7.2's note above): on an
incoming `PeerCandidates`, before doing anything else - not even creating
`PeerLink` state - it checks whether the sender is a member of any channel
it has actually joined right now (a shared-channel check).
A request from someone who isn't is dropped silently, leaving nothing
behind for a follow-up message to probe.

This check is **not** applied symmetrically to the *initiating* side
(the initiating side) - every call site that proactively opens a
link is already reachable only after legitimate prior contact: the eager
trigger above fires directly off a `UserJoined` for a shared channel; the
file-offer accept/reject and key-rotation-install paths only run for a
peer that already reached this client through an existing link or a
verified rotation. Gating those too would be pure redundancy, and would
actively break the supported case of still messaging someone in an open DM
after they've left every channel you shared (SPEC.md's "Offline users").

#### 7.1.3 Tearing down a link once it no longer serves a purpose

§7.1.2 gates *forming* a link; this is the mirror image - *tearing one
down* once a channel departure could have made it purposeless. A link is
kept only as long as there's still a reason to reach that peer at all:
the relevance check is true when either a currently-joined
channel is shared with them, or there's DM history with them (the same bar
`on_user_offline` already uses to decide whether to keep a departed user
listed - an *opened but still-empty* DM room does not count).

This is checked at every point a channel departure could tip the balance:

- **Locally, via `/leave`** (§6.2): the leave path runs the check
  against every former member of the left channel, right after applying
  the local state change, forgetting (forgetting the link) any of
  them who fail it.
- **A peer's `UserLeft`** (§6.2): the same check runs against that one
  peer once their membership is updated client-side.

`UserOffline` (§6.4) is unaffected by this and keeps its own,
unconditional `forget` - a full disconnect ends the link either way, no
relevance check needed. Neither path sends anything over the wire; this
is purely local bookkeeping; the peer's own client independently reaches
the same conclusion (or doesn't) about the link from its own side.

#### 7.1.4 Showing which peers are actually reachable

Being present on the server and being reachable are different things, and
only the second one decides whether anything sent arrives. Each link is
therefore surfaced to the UI in one of three states, and the sidebar
colours a peer's name by it (`docs/SPEC.md`'s "Connected UI"):

| State | Meaning | Sidebar |
| --- | --- | --- |
| `Connecting` | Being established or re-established; content is queued | Yellow |
| `Active` | Punched and confirmed live in both directions | Green |
| `Lost` | Never opened, or has gone quiet; a retry is scheduled | Red |

A peer with no link record at all reads as `Connecting`, never as
reachable: one is pre-warmed the moment they're learned about, so "no
record" means the handshake simply hasn't got anywhere yet. A trust-gated
peer (§12) stays red and an offline one (§6.4) stays grey regardless -
those states are about *who* the peer is and whether they're there at all,
which outranks how well the transport to them is doing.

This is purely local: nothing about link state is ever sent over the wire,
and each side reaches its own conclusion about its own half.

### 7.2 Sending a channel or direct text message

The sender addresses each intended recipient individually - a channel
send is one independently-encrypted `Envelope` per member, each delivered
over that member's own punched link, not one message broadcast by a
relay. There is no `ClientMessage`/`ServerMessage` variant for this
anymore: it's `P2pPayload::Envelope { channel, envelope }` (§7.1.1), sent
reliably, queued automatically if the link isn't `Active` yet and flushed
once it is (text is never dropped just because punching is still in
progress - contrast with voice, §7.3). `channel: Some(name)` is a channel
message; `None` is a DM. A sender is expected to address every other
current member of the channel itself - there is no server-side membership
list to expand or validate against anymore.

### 7.3 Voice streaming

Voice is never sent as a single whole `Envelope`/`Content` value. Instead
it's a **Start, then zero or more Chunks, then an End**, sharing one
`stream_id: u64` for the lifetime of that one recording, all traveling
directly over the punched link to each recipient (§7.1):

```
sender                                          recipient
  |                                                 |
  |-- P2pPayload::StreamStart (reliable) --------->|
  |   { channel, stream_id }                        |
  |                                                 |
  |-- PunchDatagram::Unreliable (repeats) --------->|
  |   { stream_id, seq, blocks }                    |
  |                                                 |
  |-- P2pPayload::StreamEnd (reliable) ------------>|
  |   { stream_id, duration_ms }                    |
```

For a channel stream, `StreamStart`/`StreamEnd` are sent reliably to
*every* recipient whose link is already `Active` at record-start time -
unlike text, **voice is never queued**: a recipient whose link is still
punching (or has failed) is simply left out of that particular stream,
exactly like a `rsa_per_msg` recipient without a fresh key (§11.6) - the
punch can take up to `PUNCH_TIMEOUT` seconds, too long to make a live
recording wait on. Each chunk is then sent unreliably
(`PunchDatagram::Unreliable`, no ack, no retransmit) to each of those same
recipients - a dropped or reordered chunk simply isn't retried, an
accepted RTP-style tradeoff (a stalled retransmit-and-wait would hurt live
playback more than an occasional dropped frame). This is safe because a
chunk's AEAD nonce is derived from `(stream_id, seq)` rather than arrival
order, so out-of-order or lost chunks still decrypt correctly on their
own; only live playback ordering is affected.

**Stream identity - critical, easy to get wrong**: `stream_id` is
generated by the sending client as a simple per-connection counter
(starting at 1, incrementing per recording) - it is **only unique per
sender**. Two different clients' independent counters *will*
legitimately collide (e.g. both send their first-ever stream as
`stream_id: 1`). Any correct implementation must treat the pair
`(from, stream_id)` as the identity of a stream, never `stream_id` alone
- indexing incoming chunks/state by `stream_id` by itself will
misattribute audio between two different senders' simultaneous streams.

**`seq: u32`** is load-bearing here in a way it wasn't under the old
server-relayed design: chunks travel unreliable/unordered UDP, so a
receiver may see them out of order or may not see all of them - `seq`
(combined with `stream_id`) is what lets the AEAD nonce derivation
recover each chunk's plaintext independent of arrival order. It is *not*
used to reorder chunks before mixing them into live playback; they're
simply mixed in arrival order.

**There is no cancellation message.** A stream that never gets an `*End`
(e.g. the sender's connection dies mid-recording) is - from the wire
protocol's perspective - simply a stream that stops receiving chunks
forever; nothing signals this explicitly. A robust receiver-side
implementation needs its own idle timeout to decide when to give up
waiting for more chunks of a given `(from, stream_id)` and finalize with
whatever partial data arrived (the reference client's is 5 seconds of
silence per stream - an implementation detail, not part of the wire
protocol).

**No content/rate/format field.** Unlike `Envelope`, chunk payloads carry
no `Content` tag and no sample-rate/channel-count metadata - the
plaintext recovered by decrypting `blocks` is understood, by convention
between this app's own client implementations, to be raw signed 16-bit
little-endian mono PCM at a fixed rate (`voice::SAMPLE_RATE_HZ = 16000`
in the reference client). The wire protocol itself does not encode or
enforce this; it is purely a convention two cooperating clients must
already agree on out of band. An implementation using a different
sample-format convention would not be interoperable with clients using
this one, and the protocol gives a receiver no way to detect that
mismatch from the bytes alone.

**Length cap, enforced on both ends independently.** The reference client
caps one recording at `MAX_RECORDING_SECS` (4 minutes,
`MAX_RECORDING_SAMPLES` at `SAMPLE_RATE_HZ`): the sending side stops
itself and sends `*End` automatically on reaching it, exactly as if the
user had released Space/the global shortcut right then
(the sending side). This is a client-side
courtesy, not a protocol-level limit - the wire format itself places no
cap on how many chunks a stream may have - so the receiving side enforces
the identical cap independently rather than trusting the sender to have
applied it: the moment an incoming stream's accumulated audio reaches
`MAX_RECORDING_SAMPLES`, the receiver force-finalizes it with whatever
arrived so far (exactly as if a real `*End` had arrived) and stops
processing any further chunks for that `(from, stream_id)`
(the receiving side, the length cap).
This is defense in depth: a modified or hostile peer that ignores its own
cap, or simply never sends `*End`, still can't make a receiver accept or
keep decrypting more than 4 minutes of one voice message.

### 7.4 `Error { message: String }`

Sent to the *originating* client only (never broadcast), whenever a
`ClientMessage` fails server-side validation (unknown channel, sender not
a member, unknown recipient, wrong message for the current handshake
phase, etc. - see the specific per-message rules above). The connection
is **not** closed - `Error` is a soft, recoverable response; the client
may continue sending further messages on the same connection. Contrast
with the handshake-phase failures in §4/§5, which do close the
connection.

### 7.5 `RotateKey` / `KeyRotated` - per-peer key rotation relay

Only meaningful between a sender whose own `key_mode == PerMessage`
(§3, §11) and one specific recipient; unrelated to channel membership.

```
// client -> server
RotateKey  { to: UserId,   new_public_key_der: bytes, signature: bytes }

// server -> client
KeyRotated { from: UserId, new_public_key_der: bytes, signature: bytes }
```

Server-side:

- Rejected (`Error` back to the sender) if `to` is not a currently-connected
  `UserId`, or if the sender's own registered `key_mode` is not
  `PerMessage` (a non-rotating `Rsa`/`Password`/`None` client has no
  business rotating).
- Otherwise relayed verbatim as `KeyRotated { from: <sender>,
  new_public_key_der, signature }` to `to` - one recipient, no
  channel/membership involved. Unlike §7.2-§7.3/§7.6, key rotation stays
  server-relayed rather than moving to the direct link (§7.1) - it's
  small, infrequent identity metadata, not the "content" the direct
  transport exists to keep off the server.
- The server does **not** verify `signature` - exactly like `Envelope`
  blocks, this is opaque payload as far as the server is concerned; §11
  covers how the *receiving client* validates it before trusting the new
  key.

There is no server-side bookkeeping of the rotated key itself: the
registry's own copy of the sender's `public_key_der` (used to bootstrap a
*new* peer who joins later, see §11) is never updated by `RotateKey` - it
stays as whatever `Identify` originally sent, for the lifetime of the
connection.

### 7.6 File transfer

A file transfer is **consent-gated and streamed**: the receiver must
explicitly `FileAccept` before a single byte of file data is sent, and once
accepted the file moves as a live Start/Chunk/End-shaped stream, exactly
like voice (§7.3) - except reliably (§7.1.1), since a dropped file chunk
is never an acceptable loss the way a dropped audio frame is. Unlike
voice, a transfer is always **point-to-point** and every frame in it is
sent reliably, including the chunks themselves. A channel file send is
simply the sending client fanning out N independent offers, one per
recipient, each with its own `stream_id` (drawn from the same
per-connection counter voice already uses) over that recipient's own
punched link - this is what lets one recipient accept while another
rejects without the two interfering.

```
sender                                          recipient
  |                                                 |
  |-- P2pPayload::FileOffer (reliable) ----------->|
  |   { channel, stream_id, envelope }              |
  |                                                 |
  |<-- P2pPayload::FileAccept (reliable) -----------|
  |    { stream_id }                                |
  |         (or FileReject, ending the exchange     |
  |          here)                                  |
  |                                                 |
  |-- P2pPayload::FileChunk (reliable, repeats) -->|
  |   { stream_id, seq, blocks }                    |
  |                                                 |
  |-- P2pPayload::FileEnd (reliable) -------------->|
  |   { stream_id }                                 |
```

All five (`FileOffer`/`FileAccept`/`FileReject`/`FileChunk`/`FileEnd`) are
`P2pPayload` variants (§7.1.1) - there is no `ClientMessage`/
`ServerMessage` counterpart anymore, and no server-side logic for this
family at all: a link can only exist to a peer the sender already knows
about (§7.1), so there's nothing left for an "unknown recipient" check to
do. `channel: optional<string>` on `FileOffer` is purely informational
routing metadata for the receiving *client* (which log to eventually show
the accepted transfer in).

**`FileOffer`'s plaintext**: like text, `envelope.content` is
`Content::FileOffer` and `envelope.blocks` decrypts (§8.1, identical
RSA-OAEP chunking) to a bincode encoding of:

```
FileOfferPayload { filename: string, size: u64 }
```

Bundling `filename`/`size` into the encrypted plaintext (rather than
cleartext fields on `P2pPayload::FileOffer`) keeps them as private as the
rest of the message - the server never sees any of it at all anymore
(§10), not even ciphertext size, since the offer travels the direct link
(§7.1), not the server. Once accepted, the actual file bytes are **never**
wrapped in a struct at all - each `FileChunk`'s `blocks` is the RSA-OAEP (or
PQ-hybrid, §13) encryption of a raw slice of the file, exactly like voice's
raw-PCM chunk convention (§7.3's "no content/rate/format field").

**No size bound.** Because a transfer is chunked exactly like voice rather
than sent as one whole-file `Envelope`, the old reasoning for a size cap
(fitting one server-relayed frame carrying every recipient's copy under
`MAX_FRAME_LEN`, §1.1) no longer applies - each `FileChunk` frame is small
and single-recipient regardless of total file size. The reference client
reads and encrypts `FILE_CHUNK_BYTES` (512 bytes) of
plaintext at a time, keeping both sender and receiver memory use bounded to
roughly one chunk no matter how large the file is; the sender never reads
any of the file into memory until the recipient's `FileAccept` arrives.
512 bytes is deliberately small for a *different* reason than the old
whole-file cap: each `FileChunk` is now one direct-link UDP datagram
(§7.1), so it's sized to keep worst-case RSA-OAEP ciphertext under
`SAFE_DATAGRAM_BYTES` (§7.1.1) rather than to bound memory use
alone - memory use would be just as bounded at a much larger chunk size.

**Filename length**: the reference client crops `FileOfferPayload.filename`
to `MAX_FILENAME_CHARS` (230 Unicode scalar values) both
before building the offer (sender) and again on whatever filename actually
arrives (receiver) - the receiver-side crop is not just defensive
redundancy, since nothing on the wire stops a modified/hostile peer from
sending a longer name than it claims to.

**`rsa_per_msg` readiness**: handled the same way as voice's recipient
readiness (§11.6), not text's queue (§11.5) - a recipient whose rotating
key isn't currently fresh is simply not offered the file at all, never
queued for a later offer once a fresh key arrives. Sending an offer still
triggers this client's own per-peer rotation for the recipient actually
reached (§11.3), same as text/voice.

**Where the bytes land**: an accepted file is written straight to
the download directory (`~/.aloo/downloads`) as chunks
arrive - `safe_filename` (unchanged: reduces a peer-supplied name to just
its final path component) still guards the on-disk path against a
maliciously-crafted filename, applied after the length crop above. There is
no separate save-location prompt; accepting *is* saving.

## 8. Encryption model

**There is no shared/session/hybrid key anywhere in this protocol for
`Rsa`/`Password`/`None`/`PerMessage`.** (§13 covers the one exception,
`PqHybrid`, which *does* use a per-message shared key - deliberately, for
reasons explained there; everything below this paragraph describes the
other four modes.) Every plaintext payload - a text message, or one voice
chunk - is
encrypted **separately for every individual recipient**, using that
recipient's own RSA public key. The server relays exactly as many
independently-encrypted copies as there are recipients; it never sees,
generates, or forwards a symmetric key, and could not decrypt a
multi-recipient message even if it colluded with one recipient (each
recipient's ciphertext is entirely independent).

This is a deliberate simplicity/auditability tradeoff over the usual
hybrid scheme (symmetric-encrypt the payload once, RSA-encrypt only a
short symmetric key per recipient) - it costs strictly more CPU and wire
bytes per additional recipient (§8.2), which is the direct reason voice
capture is kept to a low sample rate (§7.3) and streamed in small chunks
rather than one large blob. `PqHybrid` (§13) is a narrow, deliberate
exception to this whole design: its signing step needs *something* to
sign, its key-wrap step needs *something* to wrap, and a KEM produces a
shared secret by its very nature - a per-recipient-only scheme was never
on the table for it the way it is for RSA-OAEP.

A recipient's public key here is ordinarily good for the whole session
(`KeyMode::Rsa`/`Password`/`None`/`PqHybrid` - the last one loaded from a
file rather than autogenerated or password-derived, but equally static
for the whole session, see §13). §11 describes `KeyMode::PerMessage`
(`rsa_per_msg`), an opt-in per-client mode where that key is instead
rotated - per peer relationship, autogenerated in-process - on every
message sent or received with that peer.

### 8.1 RSA-OAEP chunking

Raw RSA (and OAEP padding) can only encrypt a payload smaller than the
key's modulus, so any payload larger than that limit is split into
multiple independently-encrypted blocks and reassembled by concatenating
their decryptions in order:

- Ciphertext block size is always exactly `key_size_bytes` (i.e. exactly
  the RSA modulus size - 256 bytes for a 2048-bit key, the size this
  app's own keygen produces by default, per `crypto::RSA_KEY_BITS = 2048`
  (512 bytes for `rsa_per_msg`'s 4096-bit keys, per
  `RSA_PER_MSG_KEY_BITS` - see §11.9); externally-supplied PEM
  keys, per README's "Generating RSA keys", may use a different size, and
  the protocol itself places no fixed size requirement on keys - two peers
  just need compatible RSA key sizes for whichever DER/PEM keys they
  actually exchange).
- Maximum plaintext bytes per block, for OAEP with SHA-256:
  `key_size_bytes - 2 * 32 - 2` (32 = SHA-256's output size; the `2*hLen + 2`
  term is OAEP's own padding overhead). For a 2048-bit key: `256 - 66 = 190`
  bytes of plaintext per block.
- An empty plaintext (`data.is_empty()`) still produces exactly one block
  (OAEP-encrypting zero bytes) rather than zero blocks - `blocks` is
  never empty for a validly-encrypted `Envelope`/chunk.
- `blocks: list<bytes>` on the wire is simply these blocks in order;
  decryption is: decrypt each block independently with the recipient's
  RSA private key, then concatenate the plaintexts in the same order.


### 8.2 Cost implication for voice

Total RSA work is proportional to bytes of plaintext, **independent of
how finely that plaintext is chunked** for streaming (§7.3): encrypting
one 480-byte chunk (`CHUNK_INTERVAL`'s 15ms at 16kHz mono 16-bit)
in 3 blocks costs the same total RSA-encrypt work as encrypting the same
480 bytes as one theoretical un-chunked blob would, modulo OAEP's fixed
per-block overhead (at most one block worth of padding "waste" per chunk
boundary - negligible in practice, since 190 bytes divides fairly evenly
into typical chunk sizes). What chunking
*does* affect is latency (finer chunks land sooner) and message-count
overhead (more frames, more per-message framing/relay cost) - not total
crypto cost. For a channel with `N` other members, a sender pays `N`× the
per-recipient RSA-encrypt cost for every chunk (once per recipient, since
each gets an independently-encrypted copy); each individual recipient
only ever pays 1× the RSA-decrypt cost for their own copy.

### 8.3 Password-derived keys

A client's `my_key` (§5.4's `public_key_der`) can be sourced from an RSA
keypair file, or deterministically derived from a password
(the password derivation: PBKDF2-HMAC-SHA256, 100,000 rounds,
fixed non-secret salt, seeding a ChaCha20 CSPRNG that generates the RSA
keypair) so the same password reproduces the same keypair on any machine.
This only affects how a client *obtains* the keypair whose public half it
announces in `Identify`; the actual key material the wire protocol sees -
the DER public key, RSA-encrypted ciphertext, everything in §7-§8 - is
identical regardless of sourcing, and no peer can distinguish a
password-derived key from a file-loaded one by its cryptographic
properties alone. `key_mode` (§3) does still announce *which* sourcing
was chosen (`Rsa` vs `Password` vs `None`), but purely as a display label
for peers to show next to that user's name - it has no bearing on how any
message is actually encrypted or decrypted.

### 8.4 RSA signatures

There is exactly one RSA signing primitive in this protocol, used in two
places: authenticating a freshly-rotated `rsa_per_msg` public key with the
key it replaces (§11.3), and the classical half of a `pq_hybrid` send
commitment (§13.3).

It is **RSA-PSS with SHA-256 and a random salt**. PSS rather than PKCS#1
v1.5 because it is the modern scheme with a security proof behind it; v1.5
survives elsewhere in the world only for backwards compatibility, which
this protocol explicitly does not want (§9).

Being randomised, signing the same bytes twice produces two different
signatures. That is not a problem here because nothing ever compares two
signatures for equality - a signature is only ever verified.

## 9. Versioning and compatibility

There is no version field anywhere in this protocol - no magic number, no
schema hash, nothing in `Hello` identifying a protocol revision. Framing
(§1) is stable and independent of the message schema, but the *payload*
inside a frame is decoded by assuming a specific, hardcoded Rust type
(`ClientMessage`/`ServerMessage` as currently defined) at
each point in the exchange. Consequences:

- Two peers must be built from *identical* `ClientMessage`/`ServerMessage`
  definitions (same fields, same order, same enum variant order) to
  interoperate at all. Bincode's schema-less encoding (§2) means a
  mismatch does not fail cleanly with a helpful "unknown field" error -
  at best it decodes into semantically wrong data (e.g. reading a `seq`
  field's bytes as part of a `Vec` length), at worst the length/variant
  values it reads are nonsensical and decoding errors out
  (a decode error) or a frame length wildly exceeds
  `MAX_FRAME_LEN` and the connection is simply dropped.
- Adding a *new* enum variant safely requires every peer to update
  together - there's no reserved/unknown-variant fallback.
- In practice, this protocol is versioned by "build from the same
  commit" rather than by anything self-describing on the wire.

Since §1.3, one common skew at least fails *early and consistently*: the
first message decoded on any connection is now `Hello`, and it carries a
field older servers do not send. A server predating the control channel
opens with `{ auth, challenge }`; a peer expecting
`{ auth, challenge, control }` reads both known fields, reaches for the
third, and finds the frame already spent - so the connection dies during the
opening exchange, before authentication, rather than at some later message.
It fails that way for every auth mode and every `my_key` type, which makes it
look unrelated to whatever was being configured at the time.

That is a symptom, not a mechanism: it is what one particular skew happens to
produce, not a check this protocol performs. Any other schema mismatch still
fails in one of the ways listed above, and one that decodes into
wrong-but-plausible data still fails silently. The remedy is unchanged -
build both sides from the same commit.

## 10. What the server never sees

To restate the core privacy property precisely: the server has visibility
into exactly the following, and nothing else. Note this is what the
*server* sees; since §1.3 everything below except the connection metadata
is sealed on the wire, so a passive observer between the two sees strictly
less than this list -

- Connection metadata: source address, connection lifetime.
- Auth material as sent (a `--password`-mode password reaches the server
  as plaintext inside a sealed frame, though not persisted beyond the
  comparison in §5.2; RSA-mode auth never exposes any private key, only a
  ciphertext of a nonce it already generated itself).
- Display names and DER-encoded public keys (both inherently
  non-secret - a public key is meant to be shared, and a nickname is
  chosen to be visible to other users).
- Channel names and membership (who is in which channel, when they
  joined/left) - channel *names* for private channels are known to the
  server (it has to route by them) even though they're never advertised
  to other clients via `ChannelList`.
- **That two specific clients are setting up a direct link** (§7.1): a
  `RequestPeerLink`/`PeerCandidates` exchange names both `UserId`s and
  each side's candidate IP:port addresses, and the timing of that
  exchange - so the server can tell *who is about to talk to whom*, and
  roughly when a conversation between two people starts.

Since §7.1, this is now strictly **less** than before: the server used to
also see the size (block count) and timing of *every individual*
message/chunk, because it had to route each one by `UserId`. That's gone
- once a link is `Active`, every message, voice chunk, and file chunk for
that pair travels entirely off the server's wire, so it learns nothing
further about how much was said, how often, or when, only that the
conversation exists at all.

It never sees: message plaintext (text or voice), voice audio content,
file names or contents, or any private key.

## 11. Per-message key rotation (`rsa_per_msg`)

`KeyMode::PerMessage` (§3) is an alternative to the non-rotating
`KeyMode::Rsa`/`Password`/`None` variants for a client's own `my_key`.
Everything in §7-§8 about
per-recipient RSA-OAEP encryption is unchanged - `rsa_per_msg` only
changes *which* public key is currently correct to encrypt to a given
user with, and how often that changes. It does not introduce a
shared/session key, and it does not change how a message body itself is
encrypted.

### 11.1 Granularity: per peer relationship, not global

A `PerMessage` user does not have one active key shared by everyone who
might message them. Instead they maintain an **independent rotating
keypair per peer** (`UserId`) they've exchanged anything with. Two
different peers of the same `PerMessage` user are given different current
public keys and rotate independently - Bob messaging Alice does not
consume or affect the key Alice has handed to Carol. This avoids
cross-peer contention: Bob and Carol can each message Alice without
waiting on each other.

### 11.2 Bootstrap (trust-on-first-use)

Every peer relationship starts from the *same* key: the `public_key_der`
a `PerMessage` user announced in its own `Identify` (§5.4), learned by
others the same way as a non-rotating user's key - via `UserInfo` in
`UserJoined`/the join snapshot (§6.1). Like a non-rotating user's key
today, this bootstrap key is **not signed by anything** - there is no prior key
to sign it with. It remains valid, for any peer who hasn't yet exchanged
a message with this user, for as long as that user's connection lasts;
it is only superseded, per peer, once that specific relationship's first
rotation happens (§11.3).

### 11.3 Rotation trigger and signing

A `PerMessage` user rotates their key **for one specific peer** exactly
once for every message sent to that peer, and once for every message
received from that peer (a live voice stream counts as a single message
for this purpose - see §11.6, not one rotation per chunk). Concretely,
after either:

- successfully sending a `P2pPayload::Envelope` (§7.1.1) addressed to
  peer `P`, or
- successfully decrypting an incoming `P2pPayload::Envelope` from peer
  `P`,

the user generates a brand-new RSA keypair - at `RSA_PER_MSG_KEY_BITS`
(4096 bits, larger than the `RSA_KEY_BITS` = 2048 used everywhere else in
this app - see §11.9), autogenerated in-process via the same OS-RNG path
as any other freshly-generated `my_key` (§8.3), never shelling out to an
external tool - and sends `RotateKey { to: P,
new_public_key_der, signature }` (§7.5). `signature` is computed over

```
to.0.to_be_bytes() ++ new_public_key_der
```

(`to`'s raw `u64` bytes, big-endian, concatenated with the new key's DER
bytes - not itself re-transmitted since `KeyRotated`'s implicit `to` is
just "whoever the server delivers it to"), SHA-256-hashed and signed with
RSA-PSS + SHA-256 (the signing primitive (§8.4), the one signing primitive this app has -
see §8.4) using **the private key this rotation is replacing** for peer `P` - i.e. the previous per-peer key if
one has already been established for `P`, or the bootstrap private key
(§11.2) if this is the first rotation for `P`. Binding `to` into the
signed bytes matters: without it, a rotation signed while the bootstrap
key was still shared by every not-yet-rotated peer could be replayed by
one peer as if it were a rotation addressed to them (they'd currently
trust the same bootstrap public key too).

### 11.4 Receiver-side verification and freshness

On receiving `KeyRotated { from, new_public_key_der, signature }`, a
client:

1. Reconstructs the signed payload using **its own** `UserId` (the
   implicit `to`) and `new_public_key_der`.
2. Verifies `signature` against whichever public key it currently trusts
   for `from` (the bootstrap key, or the last key `from` successfully
   rotated to for this relationship).
3. On success, replaces its stored key for `from` with
   `new_public_key_der` and marks it **fresh** (not yet used to encrypt
   anything). On failure (bad signature, or `from` unknown), the message
   is dropped - the previously-trusted key for `from` is left in place.

A client may only encrypt a message to a `PerMessage` peer using a key it
currently holds marked fresh; doing so immediately marks that key
**stale**. A stale key is never reused - see §11.5.

### 11.5 Queueing while waiting for a fresh key

If a client wants to send to a `PerMessage` peer for whom it does not
currently hold a fresh key (never received one yet, or already used the
one it has), the message is **not** sent - it is held in an in-memory,
per-peer FIFO queue instead. There is no wire message for "queued" state;
this is purely local client behavior.

When a `KeyRotated` for that peer is validated (§11.4), the **entire**
queue for that peer is flushed at once: every queued message is
encrypted under the one newly-fresh key and sent, in FIFO order, in the
same batch, and only then is that key marked stale again. This means one
rotation can legitimately cover several messages' worth of plaintext, not
strictly one - see §11.7 for why the receiver has to tolerate that.

### 11.6 Voice streams count as one message

Live voice (§7.3) is not compatible with per-chunk rotation - RSA key
generation at `rsa_per_msg`'s 4096-bit size (§11.9) is far too slow
(commonly a few hundred milliseconds, sometimes low seconds - notably
slower than the 2048-bit keys used everywhere else in this app) to repeat
every `CHUNK_INTERVAL` (15ms) without stalling capture.
Instead, an entire stream (`*Start` through `*End`) is treated as a
single message for every purpose in this section:

- Recipient readiness is decided once, at `*Start`: a `PerMessage`
  recipient without a fresh key at that moment is simply left out of the
  stream's recipient list entirely (silently, same as any other
  partial-delivery case in §7.2) rather than queued - queueing audio for
  indeterminate later delivery has no sensible playback semantics.
- Every chunk in the stream is encrypted with the one key snapshot taken
  at `*Start` for each included recipient - no rotation happens mid-stream.
- The sender's own per-peer rotation (§11.3) fires once per recipient, at
  `*End`, not at `*Start` and not per chunk. Symmetrically, a receiver's
  own rotation (§11.3's "received" trigger) fires once, when that
  stream's `*End` arrives (or the receiver's own idle timeout finalizes
  it), not per chunk.

### 11.7 Retained keys for late/batched decryption

Because §11.5 can flush more than one message under a single key, and a
`PerMessage` user rotates (and is entitled to discard the old private
key) as soon as it has decrypted *one* message under the current key,
naively discarding a superseded private key immediately would break
decryption of the second and later messages in a batch that arrives
right behind the first. There is no field anywhere in this protocol
telling a receiver how many messages a sender flushed under one key, so
a receiver cannot know exactly how long to keep an old key alive.

The reference implementation resolves this with a bounded retention
window per peer relationship (`KEY_RETENTION`, currently 8):
instead of discarding a private key the instant it rotates away from it,
it keeps the last `KEY_RETENTION` superseded keys for that peer and tries
them, most-recent-first, whenever the current key fails to decrypt an
incoming envelope. The shared bootstrap private key (§11.2) is retained
for the whole session regardless, since it may still be the active key
for other peers who haven't rotated yet. A batch larger than the
retention window will fail to decrypt its oldest members once enough
further rotations have superseded them - an accepted, documented
limitation rather than a solved problem, since ordinary interactive use
rarely queues more than a couple of messages before a round trip
completes.

### 11.8 What `rsa_per_msg` changes about the threat model

Compared to a non-rotating `Rsa`/`Password`/`None` key, a compromise of a `PerMessage` user's *current*
private key for a given peer at some point in time does not expose any
message already exchanged with that peer before the most recent
rotation - each such message was encrypted under a key that (outside the
bounded retention window of §11.7) no longer exists anywhere. It does
**not** protect a message still sitting in the sender's queue (§11.5) at
the moment of compromise, and it does not change anything about traffic
metadata visibility (§10) - key rotation messages are relayed exactly
like any other addressed message, so the server still sees the same
who/when/how-much it always did.

### 11.9 Key size: 4096 bits, not the app's usual 2048

Every RSA keypair `rsa_per_msg` ever generates - the bootstrap keypair
announced in `Identify` (§11.2) and every keypair `rotate_for_peer`
produces afterward (§11.3) - uses `crypto::RSA_PER_MSG_KEY_BITS = 4096`,
not the `crypto::RSA_KEY_BITS = 2048` used for a non-rotating
`Rsa`/`Password`/`None` `my_key` (§8.1). key generation
is the same OS-RNG keygen path either way; only the requested modulus size
differs. This is a deliberate asymmetry, not an oversight: a non-rotating
key lives for the whole session, while a `rsa_per_msg` key is often discarded after
protecting a single message (§11.8), so it errs toward a larger security
margin per key at the direct cost of slower keygen on every rotation
(§11.6) and larger OAEP ciphertext blocks (§8.1, §8.2) - 512 bytes per
block instead of 256, roughly doubling the per-recipient wire/CPU cost
this mode already pays.

### 11.10 Rotation keygen runs off the event-loop task (client implementation detail)

This is purely about how the reference client schedules work locally - it
has no wire-protocol effect and an interoperable implementation is free to
structure it differently, but it's worth documenting since getting it
wrong produces a real, user-visible defect.

§11.9's 4096-bit keygen is too slow (commonly 100ms to low seconds) to
run inline on `session.rs::run_connected_session`'s single the event loop
event-loop task, which
also owns terminal redraw and all other network processing - every
rotation (`request_rotation_if_per_message`) needs to happen once per
peer, per message sent or received (§11.3), so running keygen there
directly would stall the UI and delay every other in-flight
send/receive/redraw for however long that keygen takes, repeated once per
recipient for a channel message reaching several `rsa_per_msg` peers.

Instead, keygen runs on `session.rs::spawn_rotation_worker` - one dedicated
background thread, started once per session, fed a queue of "rotate for
this peer" requests over an unbounded channel and processing them
strictly one at a time:

1. Briefly lock `OwnKeys` (shared with the main task via shared state)
   just long enough to read the private key to sign against
   (`current_private_for`).
2. Generate the new keypair and sign it (`generate_and_sign_rotation`) -
   the slow part - with **no lock held**, so this never blocks the main
   task's own `OwnKeys` access (`decrypt_from` for incoming messages,
   `current_private_for` for starting an incoming voice stream's decrypt
   worker, §11.6).
3. Briefly lock `OwnKeys` again to install the result
   (`install_rotated_key`) and hand the resulting `ClientMessage::RotateKey`
   back to the main task (over a second channel) to actually write to the
   socket.

Processing requests one at a time on a single worker, rather than one
thread per request, is load-bearing, not just simplicity: two rotations
for the *same* peer racing each other would each read whatever "current"
key happened to be installed first and sign against it independently: if
both finish before either result reaches the peer, the peer can only
validate the one it still trusts (§11.4) - the loser's `RotateKey` looks
like a bad signature and is silently dropped, leaving that peer stuck
until the next legitimate rotation. A single serialized worker makes that
race structurally impossible, at the cost of rotations for different
peers queueing behind each other rather than running concurrently - an
acceptable trade, since rotation is background housekeeping, not
something a human is directly waiting on.

The main task tracks how many requests have been handed to the worker but
not yet finished with a plain a shared counter (a pending-rotation count,
incremented in `request_rotation_if_per_message` before the send, decremented
by the worker after it finishes processing one). Each UI tick reads this
counter to drive the top-right spinner described in `docs/SPEC.md`
Functionality #6 (the spinner) - purely a local read of a
count, not a channel round-trip, since the UI only ever needs the current
value at redraw time.

## 12. Client-side identity pinning (`id_store`)

**This entire section is client-local behavior with no wire-protocol
effect** - like §11.10, it's documented here because getting it wrong
produces a real, security-relevant defect, not because it changes anything
that crosses the network. No message, field, or enum variant described
anywhere above in this document is affected; a server, or a peer that
doesn't implement this section at all, is fully interoperable with one
that does.

### 12.1 The gap this closes

Nothing else in this protocol lets a client tell "the same person
reconnecting" apart from "someone else who happens to have taken a
familiar nickname." `UserId` (§3) is assigned fresh on every successful
`Identify` and never reused, and a `display_name` is freed the instant its
holder disconnects and immediately available to the next connection that
asks for it (§5.4) - there is no requirement, or even a mechanism, for a
name to keep being held by the same underlying identity across two
separate connections. Every peer's `public_key_der` is trust-on-first-use,
fresh, on every single connection (§11.2 describes this explicitly for
`PerMessage`'s bootstrap key, but it's equally true of a non-rotating
`Rsa`/`Password`/`None` key - nothing before this section gave any peer a
reason to remember a name's key from one session to the next). Concretely:
if "alice" disconnects and reconnects, or if a second, different client
connects using the nickname "alice" the moment the first one's connection
drops, every other client sees exactly the same thing either way - a
`UserJoined` (or the join-time snapshot, §6.1) carrying the name "alice"
and *some* public key - with nothing in the wire protocol to distinguish
the two cases.

`id_store` is a local, per-client record - never transmitted, never
visible to the server or any peer - that remembers which public key a
nickname was last seen with (the full DER bytes, not a fingerprint of them;
§12.2), so a reconnect under a *different* key can be flagged instead of
silently, indistinguishably trusted. The model is the same one SSH's
`known_hosts` and Signal's safety numbers use for pinning, but - unlike
either of those, and unlike this app's own earlier passive-banner
implementation - a mismatch here is a **blocking** decision, not merely a
displayed warning: messaging with the mismatched peer stays gated (§12.4)
until the user explicitly Accepts or Rejects the new key via an on-screen
popup (`docs/SPEC.md` #9's "Identity review popup"). This is still not a
*permanent* lockout, which matters precisely because a false positive is
possible (e.g. a peer legitimately regenerating their `my_key` file): a
`Reject` is reconsiderable at any time (selecting the peer again reopens
the same popup), and nothing about the decision is silent or automatic in
either direction - the human reviewing it decides, the app never guesses.

### 12.2 What gets pinned, and what doesn't

**Scope: this section is about byte-comparison pinning only** - the
the pin-and-compare path path the identity check drives, where the
alarm condition is "these bytes differ from last time". §12.6 adds a second,
signature-based mechanism over the same store for `PerMessage` peers, whose
key is *supposed* to differ every time; read both before concluding what is
and isn't protected.

Under byte comparison, only `KeyMode`s whose key is actually the *same* key
across two separate connections can be checked - not merely
"persistent-looking" ones:

| `KeyMode` | Checked? | Why |
|---|---|---|
| `Rsa` | yes | `resolve_my_keypair` loads the `public_key_der` from a file (`my_key`'s `file_pub`/`file_priv`) - the same file produces the same key on every connect, for as long as it exists |
| `Password` | yes | `resolve_my_keypair` re-derives the keypair from the password via the password derivation (§8.3: PBKDF2 into a deterministic CSPRNG seed) - same password in, same keypair out, every time |
| `PerMessage` | no — **but see §12.6** | `resolve_my_keypair` autogenerates `PerMessage`'s *bootstrap* keypair fresh, at `RSA_PER_MSG_KEY_BITS`, on every single connect - exactly like `None` below, not like `Rsa`/`Password` above. Nothing persists it between sessions, so the very same legitimate user reconnecting announces a genuinely different bootstrap key every time. Comparing it would flag a false "possible impersonation" on every single reconnect - worse than not checking at all, since a warning that fires constantly for no reason trains a user to dismiss it, including the one time it's real. (The keys `rotate_for_peer`, §11.3, produces *after* the bootstrap key are equally unsuited to comparison, for the same underlying reason - they're supposed to change.) |
| `None` | no | autogenerated fresh every connect by design (§3) - same reasoning as `PerMessage`'s bootstrap key above, and with no §12.6-style continuity mechanism to fall back on either |

In short: byte comparison only works for the two `my_key` types backed by a
secret the user actually holds onto between sessions (a key file, or a
password they remember). For a `my_key` type whose key material is, by
design, thrown away and regenerated at every connect, there is no stable
byte string to compare - which is a statement about *this* mechanism, not
about `id_store` as a whole. `PerMessage` gets its own answer in §12.6:
rather than comparing the key, it re-establishes the rotation chain across
the reconnect and verifies a *signature* against the previously pinned key,
using the same store as the anchor. `None` is the only `KeyMode` this
document leaves genuinely unprotected - it has neither a stable key to
compare nor a rotation chain to resume.

**The store pins the full `public_key_der` bytes, not a hash of them** -
the pin-and-compare path compares raw DER byte-for-byte, and saving the store
persists the complete key (§12.5). A SHA-256 fingerprint
(the fingerprint/`fingerprint_der`) is exactly as reliable for
*detecting* a change - two different real keys colliding to the same
fingerprint isn't a practical concern - but only the full key lets a user
actually verify a pinned identity against a `.pub` file handed to them
out-of-band, or inspect what was pinned after the fact; a fingerprint alone
would throw that away for no real storage saving (these are, at most, a
few hundred bytes of DER). A fingerprint is still computed on demand,
purely for compact on-screen display in the mismatch warning (§12.4) - it
is never what's compared or stored.

### 12.3 When the check happens

A client checks a peer's identity exactly once per connection - the first
time it ever learns that specific `UserId`, whether that's from the
join-time membership snapshot (`UserJoined` for a channel just joined,
§6.1) or a later arrival (`UserJoined` for a channel joined afterward, or
someone else joining a channel this client is already in). Because
`UserId` is assigned fresh and never reused (§3), "first time this
`UserId` is seen" is equivalent to "this specific connection's identity",
which is exactly what needs checking - there is no reason to re-check the
same live connection's key against the store a second time just because
it happens to be a member of more than one shared channel.

The reference implementation (the identity check) gates this on
whether `UserId` is already present in the client's record of connected peers at the
moment `UserJoined` arrives, which is populated by the very next thing
that happens to that message (the client) - so the check
runs before the peer is recorded as known, exactly once.

### 12.4 What happens on a mismatch

If the nickname was already pinned to a public key that doesn't
byte-for-byte match the one just announced, the client
(the identity check) does **not** re-pin or persist anything yet
- unlike §12.2-era behavior, a mismatch no longer writes to `id_store` on
its own; only an explicit `Accept` does (below). Concretely, `check_identity`
reads the pinned key with a read of the store (which never mutates) rather than
calling the pin-and-compare path (which always would), compares it by hand,
and on a byte difference:

1. Opens (or queues, if another peer's review is already showing - see
   below) an on-screen popup naming the peer, e.g. `Identity review: alice`,
   with the message `'alice' connected with a different key than last time
   (was <fp>, now <fp>) - possible impersonation. Accept their new key, or
   reject it.`, where each `<fp>` is a 16-hex-character prefix of
   the fingerprint computed on-the-fly from the old and new key
   bytes purely for compact display - the fingerprint itself is never
   what's stored or compared (§12.2). Two buttons, `Accept` and `Reject`,
   are shown; `Reject` is focused by default (the review buttons) so
   accepting always takes a deliberate move off the safer default rather
   than an accidental confirm. This is purely a local UI cue, exactly like
   the `rsa_per_msg` regeneration spinner (§11.10) - it has no
   wire-protocol meaning and isn't sent to or expected from peers.
2. Gates messaging with that peer until the popup is resolved (see below) -
   a real behavior change from the passive banner this replaced, which left
   §6-§11 completely unaffected. Specifically, while a peer's review is
   `Pending` or `Rejected` (the review status):
   - This client will not encrypt anything **to** them: excluded from a
     channel message/voice-stream recipient list (the message still
     reaches every other, verified member), and a direct room with them
     cannot be opened or typed into at all (Enter on their sidebar entry
     reopens the review popup instead of a private room).
   - A message/stream **from** them still decrypts normally (it's
     encrypted with *this client's* key, unrelated to their identity) but
     is held back from the visible log rather than shown - "hold and
     reveal": buffered in arrival order, and only spliced into the real
     channel/DM log if and when they're later `Accept`ed. A live voice
     stream from them is decrypted and accumulated the same way, but never
     forwarded to local playback while gated - nothing is heard live from
     someone not yet trusted.
   - Their sidebar entry renders red, taking priority over the usual
     green/offline-gray coloring.
3. On `Accept` (`session.rs::handle_ui_action`'s `AcceptIdentity` arm):
   pins the new key and **saves the store to disk immediately,
   synchronously** (saving the store, same as the old immediate-save
   policy) - the on-disk file reflects the new pinning the instant the
   decision is made, not batched or deferred. Every message held per
   point 2 is then revealed into the real log, in arrival order, and the
   peer is fully trusted again (sidebar color, sending, everything).
4. On `Reject`: no `id_store` write at all - the previous pin (if any)
   is left exactly as it was on disk and in memory. The peer's review
   stays recorded (not discarded) so selecting them again re-opens the
   same popup for reconsideration, rather than having nothing left to
   show - this is what makes `Reject` a *reconsiderable* decision, not a
   permanent one (§12.1).

Multiple peers can have unresolved reviews at once; only one popup is shown
at a time, front of a small FIFO queue - a peer's mismatch is queued the
instant it's detected and the popup for it opens automatically as soon as
whichever review is currently showing gets resolved (`Accept` or `Reject`
either).

A first-ever sighting of a nickname (nothing pinned for it yet) still saves
immediately and silently, exactly as before (so it's durably pinned for the
*next* reconnect, not just held in memory for the current session) - this
case never opens a review at all, since there's nothing to compare against.
A sighting that matches what's already pinned is likewise silent and writes
nothing (nothing changed, so there's nothing to persist). Only a genuine
byte difference reaches the review flow above.

### 12.5 Store format and location

The store is a small flat file, one line per pinned nickname:

```
<nickname><TAB><hex-encoded public_key_der>\n
```

e.g. `alice\t30820122300d06092a864886f70d01010105000382010f00...\n` - the
full DER bytes, lowercase-hex-encoded (lowercase hex, the same
encoding the fingerprint already uses, not base64 or raw bytes) so
the file stays plain text no matter what the key bytes are. Entries are written in sorted-by-nickname order on save so the
file diffs cleanly under version control or manual inspection.

A nickname containing a tab, `\n`, or `\r` is never pinned (silently
treated as if it were a first-ever sighting, with nothing written) - a
`display_name` is attacker-controlled input (any connected peer chooses
their own), and accepting one containing the file's own field delimiter
would let a remote peer inject spurious records into a purely local trust
file. The key half has no such restriction - hex digits can't collide with
either delimiter no matter what the underlying bytes are, so any
DER-encodable key is always storable. A line whose key half fails to
hex-decode (odd length, non-hex character - e.g. hand-editing damage) is
skipped on load, same as a line missing the `\t` separator entirely -
loading the store never fails the whole store over one bad line.

The path is set per-connection in the connect popup's `id_store` field
(`docs/SPEC.md`'s "Not connected UI"), prefilled with `idstore::
default_path()`'s result - always `~/.aloo/ids_store`
(`$HOME`/`%USERPROFILE%` joined with `.aloo/ids_store`, via
the app directory - `$HOME` preferred, `%USERPROFILE%` as the Windows
fallback, and a variable that's set but empty treated the same as unset),
created (including the `.aloo` directory, if missing) the first time
anything is actually pinned and saved - but freely editable before
connecting, so a user who deliberately wants a different location can
still type one in.
The app itself never reads or writes a loose file in the current working
directory of its own accord; the only way anything ends up outside
`~/.aloo` is the user explicitly typing a different path into this
field.

A store file that doesn't exist yet at connect time is not an error -
that's simply the first-ever run against that path, and every peer seen
in that session is a first sighting (§12.4). A store that exists but fails
to load for some other reason (e.g. a permissions error) also doesn't
block connecting: the client falls back to an empty, in-memory-only store
for that session (`connect.rs::load_id_store`) and prints a warning to
stderr - a broken local bookkeeping file is not treated as a reason to
refuse a connection outright, since that would make identity pinning less
safe overall (a user working around a startup failure by disabling the
feature entirely) rather than more.


### 12.6 Extending identity pinning to `rsa_per_msg` (`own_next_keys`)

§12.2 excludes `PerMessage` from byte-comparison pinning: its bootstrap key is freshly
autogenerated on every connect (`resolve_my_keypair`), so there is nothing
byte-stable to pin the way `rsa`/`password` allow. That leaves a real gap
`rsa_per_msg` users have no protection from at all - reconnecting is
wire-indistinguishable from a stranger taking a familiar nickname. This
section closes it, **without any wire-protocol change** - `RotateKey`/
`KeyRotated` (§7.5) already carry everything needed; this is entirely new
client-side persistence and decision logic layered on top of them.

**The core idea**: reuse the *existing* per-peer rotation chain (§11.3/
§11.4) as the verification mechanism, but give it something to survive a
reconnect on. `UserId` resets every connection, so the whole in-session
chain for a peer relationship - everything the sender's own rotating keys/`RemoteKeys`
track - dies with the connection today (§11.8's forward secrecy, by
design). §12.6 persists just enough to *resume* that chain from where it
left off, once, right after reconnecting - not to extend its lifetime
indefinitely, and not to weaken what it already protects.

#### 12.6.1 What's persisted, on each side

Two independent, symmetric pieces of state, each keyed by **nickname**
(never `UserId`, for the same reason §12.1 gives: `UserId` doesn't survive
a reconnect, nicknames are the only stable handle across one):

- **Sending**: this client's own *current* per-peer private key for each
  `rsa_per_msg` relationship it has established, in a new local store,
  the continuity store - the literal private key the sender's own rotating keys
  already holds in memory for that peer, mirrored to disk. Only relevant
  when this session's own `key_mode` is `PerMessage`.
- **Verifying**: the peer's last-verified rolling public key, pinned in
  the **same** the identity store that already handles `rsa`/`password`
  (§12.2-§12.5) - reused unchanged, just invoked from a different trigger
  point (§12.6.3) and with different handling of what a "mismatch" means
  (§12.6.4). Relevant regardless of this client's own `key_mode` - you can
  verify an `rsa_per_msg` peer's continuity even if your own `my_key` is
  something else entirely.

Only ever the single *current* key on either side - never a history. A
the sender's own rotating keys-style retention buffer (`KEY_RETENTION = 8`, §11.7) exists
for a completely different reason - tolerating a small in-flight backlog
of queued messages within one live connection - and has no bearing here:
once a connection ends, there is no backlog left to bridge, only a single
"whatever the key was when we last touched it" starting point for next
time.

**The accepted tradeoff**: this persists private key material that §11.8
has always described as memory-only, discarded on rotation and on
disconnect. A copy of `own_next_keys` stolen while its owner is offline
lets an attacker impersonate the *continuation* of specifically the peer
relationships recorded in it, on the owner's next reconnect - until the
real owner reconnects too and re-establishes trust, or the victim notices.
This is a materially smaller and more contained exposure than a single
long-lived signing-only identity key would be (rejected during this
feature's design in favor of this approach): a leak here compromises only
already-established relationships recorded in the file, one at a time,
never a client's entire identity toward everyone, past or future. Message
*content* stays exactly as protected as before either way - the keys that
actually decrypted past messages were superseded ones, and those are still
never written anywhere.

#### 12.6.2 Sending: resuming on reconnect

The moment a client (own `key_mode == PerMessage`) first learns of a peer
this connection - via `UserJoined`, the same first-sighting gate
`check_identity` already uses - it checks `own_next_keys` for an entry
matching that peer's nickname. If there is one:

1. Installs that persisted private key as the *current* key for the
   peer's brand-new `UserId` in the sender's own rotating keys (`install_rotated_key`'s
   existing "no prior state for this peer" branch, unchanged - seeding a
   fresh `UserId` this way is indistinguishable to it from a genuinely
   first-ever rotation).
2. Signs that same key's own public half with itself - a self-assertion,
   proof of possession bound to the peer's new `UserId` via the same
   `rotation_signing_payload` (§11.3) every ordinary rotation already
   uses. No new keypair is generated for this step (unlike an ordinary
   rotation) - there is nothing to rotate *to* yet, only a claim to
   re-assert; ordinary per-message rotation (§11.3) resumes from here,
   unmodified, on the next real message with that peer.
3. Sends it as a perfectly ordinary `ClientMessage::RotateKey { to, new_public_key_der, signature }`
   - wire-identical to any other rotation. No new message type, no new
   field.

This happens *before* any application message is exchanged with that
peer, unprompted - not gated on the peer actually talking first.

#### 12.6.3 Verifying: gate on sight, only a proof clears it

A receiver's existing `handle_key_rotated` only ever checked an incoming
`KeyRotated` against whatever key is currently live-registered for the
sender's `UserId` (§11.4). For a genuine resume, that check necessarily
fails - a reconnecting peer has a brand-new `UserId` with no live rotation
state at all yet. the two-anchor check is the fix: it tries the
live in-session key first, and only if that fails, tries the sender's
nickname against `id_store`'s pinned continuity key. Returns which anchor
(if either) verified it - `Live`, `Resumed`, or `Failed`
(the resume outcome) - pure decision logic, no I/O, fully
unit-testable independent of the async orchestration around it
(covered by the resume tests).

**`Live` alone is not proof of cross-session identity, and must never be
treated as if it were.** It only says a rotation is self-consistent with
whatever this same connection already announced - true of *any* rotation
from *anyone*, honest or not, the first time a fresh `UserId` rotates,
since nothing else has claimed that live slot yet. Trusting it
unconditionally would mean a nickname's whole history in `id_store` counts
for nothing the moment someone (attacker or a legitimate user who lost
`own_next_keys`) reconnects under it without even attempting to claim
continuity: their first ordinary, self-signed rotation would verify as
`Live` and silently overwrite the real pin - exactly the gap this
mechanism exists to close, just reopened at one remove. So a nickname's
identity is gated the moment it's seen again, **before** any rotation is
attempted, and only a genuine proof - never mere self-consistency - clears
that gate:

- the identity check runs this check itself now, not only
  `handle_key_rotated`: the instant a `PerMessage` peer's `UserJoined`
  arrives (§12.3's usual "first time this `UserId` is seen" gate), if
  `id_store` already has a continuity key pinned for their nickname, it
  opens a review immediately - `push_identity_review` (§12.4's mechanism,
  reused verbatim), worded `'bob' is using rsa_per_msg under a nickname
  previously linked to a different session's key, and hasn't proven
  continuity with it - possible impersonation. Accept their new key, or
  reject it.` A nickname with nothing pinned yet is untouched here, same as
  always - first contact, still trust-on-first-use.
- From then on, `handle_key_rotated` decides what (if anything) an
  incoming `KeyRotated` does to that gate:
  - `Resumed` - an actual signature verified against the pinned
    continuity key - installs the new key via `install_trusted_rotation`
    (the client, refreshes and saves the `id_store`
    pin, flushes any messages queued for this peer's key - §11.5) and, if
    `check_identity` had a review open for them, silently resolves it
    exactly as an `Accept` would (held messages included) - genuinely
    proven, so there is nothing left to ask a person.
  - `Live` while **not** gated (nothing was ever pinned for this
    nickname, or it's already fully trusted this session) gets the same
    `install_trusted_rotation` treatment - there was nothing to prove in
    the first place, so this is just an ordinary rotation.
  - `Live` while **gated** installs nothing and does not clear the
    review - self-consistency isn't proof - but does refresh it to point
    at this newest key, so that an `Accept`, if a person gives one, still
    installs something the peer can actually decrypt with rather than a
    stale bootstrap key they may have already rotated away from.
  - `Failed` installs nothing either way; if `id_store` had a continuity
    key pinned for that nickname (whether or not `check_identity` had
    already gated them for it), it opens or refreshes a review worded for
    an outright failed proof rather than "hasn't tried yet": `'bob'
    reconnected but couldn't prove continuity with a previous session
    (invalid resume signature) - possible impersonation. Accept their new
    key, or reject it.` There's no old-vs-new fingerprint pair to show
    here the way a static mismatch has, since a rolling key is *supposed*
    to change on every rotation.

A first-ever `rsa_per_msg` contact has nothing pinned to gate against and
is never treated as suspicious just for that - same as before. A peer
whose own client doesn't implement resume at all is a genuinely different
case from before this fix: if nothing was ever pinned for their nickname,
they're still just an ordinary first contact; but if something *was*
pinned, `check_identity`'s gate now catches them regardless of whether
they ever attempt (or fail) a resume, since the gate no longer depends on
an attempt happening at all. Accepting an open review, from any of the
above, runs the identical `install_trusted_rotation` sequence a `Resumed`
anchor's silent success gets, just triggered by a person instead; rejecting
it installs nothing, same as `Live`-while-gated or `Failed` already leave
in place on their own. Because a silent `Resumed` resolution can land on a
peer whose review isn't the one currently shown in the popup (a second
peer's continuity can verify while a first peer's review is still open -
§12.4's queue), resolving a review removes that specific peer from the
queue wherever they are, not only when they're at the front
(accepting a review/`remove_from_identity_review_queue`).

#### 12.6.4 Why this is a different kind of "mismatch" than §12.2-§12.5

For `rsa`/`password`, any byte change at all is the alarm signal - the key
is supposed to never change, full stop. Reusing `id_store` here works
*because* `rsa_per_msg` peers are checked differently: every legitimate
rotation - whether an ordinary in-session one or a resume - genuinely
changes the pinned bytes, on purpose, constantly. The byte comparison
the pin-and-compare path performs is therefore never itself the alarm
condition for `PerMessage` peers; it's just bookkeeping, called only once a
key is already trusted (by an anchor, or by a person via `Accept`) - never
*before*, the way a bare byte comparison would be. The alarm condition here
is two-sided, both halves keyed off the same fact ("a nickname we did have
something pinned for"): `check_identity` raises it the instant such a
nickname is seen again at all (§12.6.3), and separately,
`handle_key_rotated` raises or refreshes it for "a signature that verifies
against neither anchor" (`Failed`) or "only proves self-consistency, not
continuity" (`Live` while already gated) - neither is something
`id_store`'s own `IdCheck` return value has any way to express on its own,
which is why `handle_key_rotated` branches on `ResumeVerification` first
and only *afterward* (on a `Resumed` success) touches `id_store` -
structurally the same discipline §12.4's `rsa`/`password` path now follows
too (compare via a read of the store first, only `check_and_pin` on a trusted
outcome), even though the two paths reach that outcome differently: §12.4
needs a human's `Accept`, §12.6.3 can also reach it automatically, but only
via a genuinely verified `Resumed` - `Live` no longer suffices once a
nickname has real history to live up to.

One consequence worth naming: `id_store.save()` (and, on the sending side,
`own_next_keys.save()`) now happens on essentially every rotation for an
active `rsa_per_msg` relationship - i.e. on every message exchanged with
one, not just once per reconnect the way §12.4's `New`/`Mismatch`-gated
saves do for `rsa`/`password`. This is a deliberate simplicity/robustness
tradeoff over debouncing the writes: persisting on every rotation means a
crash between rotations degrades gracefully (the next reconnect's resume
attempt just fails to verify, falling back to an ordinary unverified
first-sighting-shaped case - never a false alarm), at the cost of more
frequent, small, local file writes than §12.4's mechanism needs.

#### 12.6.5 Store format and location (`own_next_keys`)

Same shape as `id_store` (§12.5), storing private keys instead of public
ones:

```
<nickname><TAB><hex-encoded PKCS8 DER private key>\n
```

Resolved the same way, via the connect popup's `own_next_keys` field
(shown only when `my_key` is `rsa_per_msg`, `docs/SPEC.md`'s "Not
connected UI"): always `~/.aloo/own_next_keys`, same rule (and same
"never a loose cwd file of its own accord") as `id_store` above - freely
editable, never auto-preferred from the current directory. A missing or
otherwise-unreadable file behaves exactly as §12.5 describes for
`id_store` - never blocks connecting, falls back to an empty, in-memory-
only store for that session instead (`connect.rs::load_own_next_keys`).


### 12.7 Making a pin worth more than "these bytes differ"

Everything above can only say that a key changed. It cannot say *why*, and
the two reasons are not remotely alike: a friend who regenerated their
keybundle, and a stranger who took their nickname, produce exactly the same
signal. Asking the user about both is what teaches people to dismiss the
question - so three mechanisms narrow it. All are client-local; only the
continuity certificate is wire-visible, and only as an extra field inside a
`pq_hybrid` bundle.

**Safety phrases.** A 32-byte identity fingerprint renders as eight words
drawn from a fixed 256-word list. Two people read it to each other over any
channel they already trust and confirm they see the same thing. Eight words
is 64 bits - not the full fingerprint, deliberately, because it is what
someone will actually read aloud; forging a match still means finding a
second identity colliding in those 64 bits.

The fingerprint covers the identity's *keys* - ML-DSA verifying key, RSA
signing key, bootstrap encryption keys - and **not** the continuity
certificate below. Otherwise a certificate would have to sign the
fingerprint of a bundle that already contained it, and attaching one would
pointlessly change the phrase every contact had already checked.

**Verified pins.** A pin records how much it is worth:

| | meaning | a mismatch means |
|---|---|---|
| `tofu` | believed because it turned up first; nobody checked it | "this differs from whatever arrived first" |
| `verified` | a human confirmed it out of band | "this differs from what a person checked" |

The store's line format gains a third column (§12.5):
`nickname<TAB>hex<TAB>tofu|verified`. A store written before the column
existed loads as `tofu` rather than being discarded - throwing away a
user's pins would cost real security, not just convenience. Re-pinning
never silently demotes a `verified` entry.

**Continuity certificates.** A `pq_hybrid` identity generated by
`aloo --rekey-pq-hybrid <old> <new>` carries, inside its bundle:

```
ContinuitySig { previous_fp: bytes[32], mldsa_sig: bytes, rsa_sig: bytes }

signed over: "aloo/pq-hybrid/v2/continuity" ++ previous_fp ++ new_fp
```

signed by the identity being **retired**. A contact who has the old
identity pinned verifies it and moves the pin across silently, noting it on
the status line; no review is opened. Producing one requires the old
private keys, so knowing a fingerprint - which anyone who has met that
person does - buys nothing. A certificate that names a different
predecessor, is signed by other keys, or has been lifted onto a different
successor all fail, and a failure leaves the pin exactly as it was and
opens the ordinary review. The RSA modes cannot do this at all: they have
no signing identity separable from the key being replaced.

**Identity cards.** `aloo --export-identity-card <prefix> <nickname>`
writes a small self-signed file pairing a nickname with an identity:

```
IdentityCard { nickname: string, bundle: PqPublicBundle, mldsa_sig, rsa_sig }

signed over: "aloo/pq-hybrid/v2/card" ++ len(nickname) ++ nickname ++ fingerprint
```

Importing one pins that nickname as `verified` **before first contact** -
the one thing pinning alone can never do, since a first sighting has
nothing to compare against and is believed by default. The nickname is
length-prefixed in the commitment so it cannot be shifted into the
fingerprint.

A card is self-signed, which is precisely what it claims: whoever holds
these keys asked to be known by this name. What makes it worth trusting is
the channel it arrived over, not the signature - the signature only ensures
that what arrived is what was sent.

**What remains open.** None of this authenticates a first contact that
arrives with no card and no prior pin; that is still trust-on-first-use,
and the protocol has no way around it without an anchor outside itself.

## 13. Post-quantum hybrid encryption (`pq_hybrid`)

`KeyMode::PqHybrid` is a fifth `my_key` method: ML-DSA-87+RSA-4096 signing,
ML-KEM-1024+RSA-4096 key-wrap, AES-256-GCM bulk encryption. Unlike every
other method in this document, it is not built on RSA-OAEP-per-recipient at
all (§8) - it needs a shared symmetric key by construction, so it is
documented here as its own, self-contained model rather than a variation on
§7-§8's. Like §11/§12, this section has real wire-visible pieces (a new
`KeyMode` variant, and what `public_key_der`/`Envelope.blocks` actually
contain for it) but otherwise reuses existing message types unchanged - no
new `ClientMessage`/`ServerMessage` variant, no change to `Envelope`'s or
`UserInfo`'s shape.

### 13.1 Why a fifth method, and why it looks different

The other four methods share one property: RSA-OAEP encryption needs
nothing from the *sender* except the recipient's public key - no identity,
no private key, no signature. That is what lets any client encrypt to any
recipient regardless of the sender's own `my_key` choice, and it is exactly
what makes real post-quantum *authentication* impossible to bolt on without
a shared-key step: producing an ML-DSA-87 signature needs an ML-DSA-87
signing key, which only a `pq_hybrid` sender has. This is why §13.6 below is
a hard requirement, not an incidental detail: **a `PqHybrid` recipient can
only be addressed by a `PqHybrid` sender.**

The user-facing design brief this section implements:

```
[ YOUR ORIGINAL DATA / FILE ]
             |
             v
1. SIGN THE DATA (Authentication)       -- ML-DSA-87 + RSA-4096
             |
             v
2. ENCRYPT THE DATA (Privacy)           -- AES-256-GCM
             |
             v
3. ENCRYPT THE AES KEY (Key Exchange)   -- ML-KEM-1024 + RSA-4096
```

RSA-4096 is paired with *both* PQ primitives deliberately: if ML-DSA-87 or
ML-KEM-1024 ever turns out to have an implementation or cryptanalytic flaw,
messages are still only as broken as plain RSA-4096 already would be -
never fully unauthenticated or fully readable from a single primitive's
failure alone.

### 13.2 Key material: an identity that stays, keys that move

One `pq_hybrid` identity is generated by `aloo --keygen-pq-hybrid <prefix>`
(there is no `openssl`-equivalent for ML-DSA/ML-KEM, unlike `rsa`'s keys -
see README.md "Generating PQ-hybrid keys"). It has two halves, and the
distinction between them is the whole of §13.10:

**The signing half - durable, on disk, pinned by contacts:**

- An ML-DSA-87 signing keypair.
- A signing-only RSA-4096 keypair, paired with it. **Never** the same
  keypair as anything used for encryption: reusing one RSA key for both
  signing and encryption is a known cross-protocol anti-pattern.

This half never changes. It is what proves a message came from you, what
`id_store` pins (§13.8), and what signs every key rotation (§13.10).

**The encryption half - rotating, in memory:**

- An ML-KEM-1024 encapsulation/decapsulation keypair.
- An X25519 keypair, paired with it.

Two primitives again, so a break of either alone is not enough. X25519
rather than RSA-4096 here because this half is regenerated per peer, per
message, and X25519 keygen is microseconds where RSA-4096's is hundreds of
milliseconds - the same reason `rsa_per_msg` (§11.9) needs a background
worker and a carve-out for voice, and this does not. The pairing is the
same shape as the IETF's X-Wing construction, at a higher ML-KEM parameter
set.

The keybundle file holds exactly one encryption keypair: the **bootstrap**
pair, used only until a relationship rotates for the first time. Every key
after that lives in memory and is destroyed when superseded.

```
PqPublicBundle  { mldsa_verifying, rsa_sign_public_der, bootstrap_encap }
PqPrivateBundle { mldsa_signing,   rsa_sign_private_der, bootstrap_decap }

PqEncapKeys { mlkem_encaps, x25519_pub }    // what a peer encrypts to
PqDecapKeys { mlkem_decaps, x25519_priv }   // the private half
```

Bundled into exactly two files, mirroring `rsa`'s `file_pub`/`file_priv`
shape so the connect popup needs no new UI beyond a new `my_key` type
selection (`docs/SPEC.md`'s "Not connected UI"). Both are plain
bincode-encoded, written as raw bytes - there is no PEM convention for
ML-DSA/ML-KEM keys the way there is for RSA. The private bundle file is
written with `0o600` permissions on unix - the one `my_key` file this app
itself ever writes to disk.

`public_key_der` in `Identify`/`UserInfo` carries the encoded
`PqPublicBundle` for this `KeyMode` - reusing the existing field opaquely,
the same trick already used for `rsa_per_msg`'s resume mechanism (§12.6)
and file transfer's `FileOfferPayload` convention (§7.6). No wire schema
change to `Identify` or `UserInfo` at all.

### 13.3 One layout for everything: a setup, then chunks

Every `pq_hybrid` send uses the **same** shape, whatever it carries: a
per-recipient **setup** that names who the content is for and hands over
the key, followed by one or more **chunks** encrypted under that key. A
text message is simply a send whose stream is one chunk long; a voice
recording is the identical construction with more of them.

```
SendBinding {
    recipient_fp: bytes[32],       // SHA-256 of the recipient's public bundle
    channel:      optional<string>, // Some(name) = channel send, None = DM
    send_id:      u64,              // sender's per-connection send counter
}

SendSetup {
    binding:         SendBinding,
    kem_ciphertext:  bytes,       // ML-KEM-1024 encapsulation to the recipient
    wrapped_key:     bytes[32],   // k_data XOR K_wrap
    eph_x25519_pub:  bytes[32],   // sender's throwaway X25519 key, the classical hedge
    mldsa_sig:       bytes,       // ML-DSA-87 over the commitment below
    rsa_sig:         bytes,       // RSA-4096-PSS over the same commitment
}

HybridSend { setup: SendSetup, ciphertext: bytes }   // a one-chunk send
```

**Sealing a send**, per recipient:

1. Generate a fresh random 32-byte `k_data`.
2. Build the `SendBinding` for this recipient.
3. Wrap `k_data`: ML-KEM-1024-encapsulate to the recipient's `mlkem_encaps`
   key, and separately do an X25519 exchange between a **throwaway
   keypair generated for this send** and their X25519 key; combine both
   into a one-time
   `K_wrap = HKDF-SHA256(kem_shared ++ x25519_shared, "aloo/pq-hybrid/v2/key-wrap")`;
   ship `k_data XOR K_wrap` alongside the throwaway public key. Recovering
   `k_data` needs **both** halves - a break of ML-KEM-1024 alone, or
   X25519 alone, is not enough. The sender keeps no part of the throwaway
   keypair, so it contributes forward secrecy of its own on top of the
   recipient's rotation (§13.10).
4. Sign the **commitment**
   `"aloo/pq-hybrid/v2/send" ++ encode(binding) ++ k_data`
   with both the ML-DSA-87 and RSA-4096-PSS signing keys. Encoding the
   binding with length-prefixed fields is what keeps two different
   bindings from ever producing the same commitment bytes.
5. Encrypt each chunk with AES-256-GCM under `k_data`, nonce
   `send_id (8 bytes, big-endian) ++ seq (4 bytes, big-endian)`. The nonce
   needs no randomness because `k_data` is fresh per send, so `(send_id,
   seq)` never repeats under one key.

**What the binding buys.** The signature covers who the send is for, not
just what it says. Three attacks that the content signature alone did not
stop:

- **Re-wrap for a third party.** A legitimate recipient knows `k_data`, so
  they could once re-wrap a sender's content for somebody else and pass it
  off as a message that sender addressed to *them*. Now the commitment
  names `recipient_fp`, so it only verifies for the recipient it was
  sealed for. Everyone else fails closed.
- **Moving a message between rooms.** `channel` binds a send to the room
  it belongs to, so a private message cannot be replayed into a channel,
  or the reverse.
- **Replay onto the same link.** `send_id` must strictly exceed everything
  already accepted from that peer (§13.4).

`recipient_fp` is an *identity* fingerprint, not a connection one - stable
across reconnects, unlike a `UserId`. Gaps in `send_id` are ordinary and
accepted: the counter is per connection rather than per recipient, so a
channel message addressed to five people consumes one value for all of
them and a message to somebody else consumes a value this peer never sees.

**How the two shapes travel.**

- **Text and file offers** put the whole `HybridSend` - setup and its
  single chunk - as the one element of `Envelope.blocks`. `Envelope`'s own
  shape is unchanged; only the *meaning* of `blocks` differs by `KeyMode`.
- **Voice streams and file transfers** send the `SendSetup` on its own,
  once, as `P2pPayload::StreamKeySetup` (§7.1.1, reliable), and every
  chunk after it carries ciphertext only.

That split is why a `pq_hybrid` chunk now fits `SAFE_DATAGRAM_BYTES`
(§7.1.1). Previously the setup was repeated verbatim in *every* chunk -
several kilobytes of ML-KEM ciphertext, RSA ciphertext and two signatures,
re-sent every 15ms - which both wasted bandwidth and guaranteed IP
fragmentation no chunk size could fix. Sent once, the problem disappears.

Since voice chunks travel unreliably (§7.3) they can outrun the reliable
setup they depend on. A receiver therefore **holds** chunks that arrive
early - bounded, mirroring §7.1.1's own buffering rule - and replays them
in arrival order the moment the setup verifies. Beyond that bound further
chunks are dropped rather than buffered without limit. A stream whose
setup never arrives, or never verifies, decrypts nothing at all: there is
no key to try.

**Per-recipient cost.** Each recipient of one send gets an independent
`k_data`, because a setup is bound to one recipient and sharing a key
across them would mean sharing a binding too. A channel send to N members
therefore does N seals rather than encrypting once and wrapping N times.
That is a deliberate trade: it costs one AES pass per recipient (cheap,
symmetric) to buy the binding property above, and it is still far cheaper
than the RSA modes, which re-encrypt the *entire plaintext* per recipient
with public-key crypto (§8).

### 13.4 Opening a send: unwrap, verify, then check the binding

Given the recipient's own private bundle and the *sender's* public bundle:

1. X25519-exchange the recipient's own private key with the sender's
   `eph_x25519_pub`, recovering `x25519_shared`.
2. ML-KEM-1024-decapsulate `kem_ciphertext` with their `mlkem_decaps`
   private key, recovering `kem_shared`.
3. Recompute `K_wrap` (same HKDF as §13.3) and `k_data = wrapped_key XOR K_wrap`.
4. Recompute the commitment from the binding and `k_data`, and verify
   **both** `mldsa_sig` against the sender's ML-DSA-87 key **and**
   `rsa_sig` against their RSA-4096 signing key. Both must pass - a break
   of one primitive alone must not be enough to forge a send.
5. Check `binding.recipient_fp` is *our own* fingerprint. This is the step
   that refuses a send re-wrapped for somebody else.
6. Decrypt each chunk with AES-256-GCM under `k_data` and its
   `(send_id, seq)` nonce.

Two further checks belong to the receiving client rather than the crypto
layer, because only it knows the context:

- **Channel**: `binding.channel` must equal the channel the payload
  actually arrived on (`None` for a DM).
- **Replay**: `binding.send_id` must strictly exceed the highest already
  accepted from that peer. State is kept per live `UserId` and only for the
  life of the session - deliberately, since a peer who reconnects gets a
  fresh `UserId` and restarts their counter, and keying this by identity
  instead would reject everything they sent after reconnecting.

Any failure at any step - bad AEAD tag, either signature, a binding naming
someone else or the wrong room, a replayed `send_id`, malformed bytes -
drops the message. Fail-closed throughout, mirroring every other
`KeyMode`'s decrypt failure path: never a partial accept, never a panic.

**Which scheme a client uses for an incoming send is decided by that
client's *own* `key_mode`, never the sender's** - a message addressed to
you was necessarily encrypted against whichever public key material *you*
announced, regardless of what `my_key` the sender runs. The sender's
`key_mode` only matters for knowing the shape of their signing public key
when verifying.


### 13.5 Key size and parameter choices

The RSA signing key is 4096 bits - the same size `rsa_per_msg` uses
(§11.9), chosen for the same reason: extra security margin, at the cost of
slower keygen, paid once at `aloo --keygen-pq-hybrid` time rather than per
message. It is the only RSA key a `pq_hybrid` identity has; the encryption
side's classical hedge is X25519 (§13.2), because that half rotates and
RSA keygen is far too slow to repeat per message.

ML-DSA-87 and ML-KEM-1024 are each the highest security-category parameter
set NIST standardized (FIPS 204/203) - the whole point of this method is
the strongest tier available, not the fastest.

### 13.6 Who can send to whom

Because step 1 needs the *sender's* ML-DSA-87/RSA-sign identity, and only a
`pq_hybrid` client has one:

- **A `pq_hybrid` recipient can only be addressed by a `pq_hybrid`
  sender.** A sender whose own `my_key` is `rsa`/`password`/`none`/
  `rsa_per_msg` has no way to produce a valid `SendSetup` signature - such a
  recipient is silently excluded from that sender's channel/DM/file/voice
  send, the same partial-delivery pattern as any other unreachable
  recipient in this app (an offline member, a not-yet-fresh `rsa_per_msg`
  key, §11.5/§11.6). the addressing rule is the reference
  implementation of this check.
- **A `pq_hybrid` sender can still address any non-`pq_hybrid` recipient
  normally** - RSA-OAEP (§8) needs no sender identity at all, so a
  `pq_hybrid` client falls straight through to the ordinary `encrypt_for_one`
  path for an `rsa`/`password`/`none`/`rsa_per_msg` recipient, exactly like
  any other sender would.

A mixed channel - some members `pq_hybrid`, some not - therefore behaves
asymmetrically per sender: a `pq_hybrid` member's message reaches everyone;
a non-`pq_hybrid` member's message reaches everyone *except* the `pq_hybrid`
members.

### 13.7 Voice streaming (and file transfer chunks)

`pq_hybrid` voice is not just "supported" but a *better* fit than every RSA
method: the expensive asymmetric work (ML-DSA-87 sign, ML-KEM-1024
encapsulate, RSA-4096 operations) happens once per stream, not once per
15ms chunk - unlike `rsa_per_msg`, which has to exempt voice from its own
per-message rotation entirely because 4096-bit RSA keygen is far too slow
to repeat every chunk (§11.6).

A stream is sealed by exactly the construction §13.3 describes, so there is
little left to say here that isn't already said there:

- **Once, at record-start** (mirroring the RSA path's "recipients' public
  keys parsed once at record-start"): one `SendSetup` per `pq_hybrid`
  recipient, sent as `P2pPayload::StreamKeySetup` (§7.1.1) right after
  `StreamStart`. For a file transfer the same setup goes out on
  `FileAccept`, before the first `FileChunk`.
- **Every chunk** carries ciphertext only - `pcm` (or a raw slice of the
  file) under AES-256-GCM with the `(send_id, seq)` nonce, where `send_id`
  is that stream's `stream_id`. Nothing else. §7.3's "`stream_id` is only
  unique per sender" caveat still applies: a receiver keys everything by
  `(from, stream_id)`, never `stream_id` alone.
- **Receiver side**: verify and unwrap the setup once, cache `k_data`, and
  pay only cheap AES-256-GCM per chunk thereafter. Chunks that arrive
  before the setup are held (bounded) and replayed in arrival order once it
  verifies; a stream whose setup never verifies decrypts nothing.

Because the setup no longer rides on every chunk, a `pq_hybrid` voice or
file chunk now fits comfortably under `SAFE_DATAGRAM_BYTES` (§7.1.1) with
only AES-GCM's own overhead on top of the plaintext - the guaranteed IP
fragmentation this section used to warn about is gone.

Everything here is written in terms of voice, but a `pq_hybrid` recipient's
accepted file transfer (§7.6) reuses the identical mechanism for its
`FileChunk` stream, unmodified - the chunk payload is just whatever bytes
that chunk carries. Only `FileOffer` itself (a discrete, one-shot decision,
not a stream) travels as a one-chunk send instead.

### 13.8 Identity pinning

A `pq_hybrid` *identity* is static and file-loaded - stable across
reconnects by construction, exactly like `rsa` (a key file) and `password`
(a deterministic re-derivation). Rotation (§13.10) does not change that:
what rotates is the encryption half, which is not what gets pinned.

So the bundle participates in `id_store`'s ordinary byte-comparison pinning
unchanged (§12.2's table gains a `PqHybrid: yes` row) -
the pinning predicate is the single predicate
`check_identity` consults, covering exactly `Rsa`/`Password`/`PqHybrid`.

It has **no** need for `rsa_per_msg`'s resume mechanism (§12.6,
`own_next_keys`) - that machinery exists purely to bridge a bootstrap key
that changes every reconnect. A `pq_hybrid` bundle does not change between
reconnects, so a plain byte comparison is already definitive, and every
rotation is separately verifiable against that same pinned bundle.

### 13.9 Client convenience: auto-generated keys and the connect-popup cache

Like §11.10/§12, this is purely client-local behavior with no wire-protocol
effect - a server, or a peer whose client doesn't implement this section at
all, is fully interoperable with one that does. It exists because `13.2`'s
file-loaded keybundle would otherwise be the one `my_key` type that can't
be used the moment you open the app for the first time - every other type
either needs nothing prepared (`none`, `rsa_per_msg`'s bootstrap) or fails
with an actionable, immediate error naming exactly which field is empty. A
blank `file_pub`/`file_priv` for `pq_hybrid` would technically fail the
same validation, but with no in-app way to fix it short of quitting,
running `aloo --keygen-pq-hybrid` externally, and reopening the form -
real friction for what's this app's default `my_key` type. Two pieces close
that gap:

**Auto-generation at connect time** (the auto-generation step, called
from `connect.rs::resolve_my_keypair`'s `PqHybrid` arm): if either
`file_pub` or `file_priv` doesn't exist on disk, a fresh keybundle is
generated and written to those *exact* paths before loading - whether
that's a location the popup assigned automatically (below) or one the user
typed by hand. Deliberately treats "either file missing" as "neither is
usable" and regenerates both together rather than salvaging a lone
surviving half (e.g. after one file was deleted by hand) - loading a public
bundle that doesn't actually pair with the private one would silently
produce an identity that can't decrypt its own incoming messages, a worse
outcome than just regenerating.

**A fresh, not-yet-generated default location** the moment the connect
popup opens for the very first time (`connect.rs::fresh_pq_hybrid_paths_in`):
a random 4-character lowercase-alphanumeric prefix (`random_prefix`,
~1.68M combinations) under `~/.aloo/`, retried (bounded) if a prefix's
files already exist, so this never silently reuses a stray identity left
over from something else. Nothing is written to disk at this point - only
a location is chosen; the auto-generation above is what actually creates
the key material, the first time that location is used to connect.

**The connect-popup cache** (`connect.rs::ConnectCache`, `~/.aloo/.cache`)
remembers, per `(host, port)`, the `pq_hybrid` `file_pub`/`file_priv` last
used to connect there - a flat `host<TAB>port<TAB>file_pub<TAB>file_priv`-
per-line file, oldest-used first, tolerant of a missing file (first run) or
a malformed line, the same conventions the identity store/
the continuity store already use. Every submitted `pq_hybrid`
connect attempt records/updates its `(host, port)` entry (moving it to
"most recently used") *before* the connection attempt itself, regardless of
whether that attempt succeeds - this remembers "the last values used in the
popup", not "the last successful connection", so a wrong password or an
unreachable host doesn't erase a perfectly good remembered identity.

The moment the popup opens, `connect.rs::prefill_connect_defaults` decides
between the two mechanisms above: if the cache has a most-recently-used
entry, its host, port, and `pq_hybrid` file paths are restored verbatim
(so reconnecting to a server you've used before needs no retyping at all,
and each server keeps its own remembered identity rather than sharing one
global default); otherwise (first run, empty cache) a fresh location is
assigned per the previous paragraph. Both paths are one-shot, evaluated
once before the popup is ever shown - not reactively as the user edits
host/port afterward, the same convention `id_store`/`own_next_keys`/the
nickname field already use for their own prefills.


### 13.10 Rotating encryption keys (forward secrecy)

A `pq_hybrid` identity's signing half never changes; its **encryption half
rotates per peer relationship**, once for every message sent to that peer
and once for every message received from them. Each superseded key is
destroyed. That is the whole mechanism, and what it buys is this: someone
who later steals the keybundle file gets your identity, not your history.

The shape is deliberately the one §11 already established for
`rsa_per_msg` - rotate per message, keep a bounded window of superseded
keys, count a whole voice stream as one message - so there is one model to
learn rather than two. What differs:

| | `rsa_per_msg` (§11) | `pq_hybrid` (here) |
|---|---|---|
| What rotates | the identity key itself | the encryption keys only |
| What signs a rotation | the key being replaced | the durable identity |
| Verifying across a reconnect | needs the §12.6 resume mechanism | nothing special - the verifying key never changed |
| Keygen cost | RSA-4096: 100ms to seconds | ML-KEM + X25519: microseconds |
| Scheduling | background worker (§11.10) | inline; no worker, no spinner |
| Voice | exempt from per-message rotation (§11.6) | not exempt; rotation is cheap |

**Bootstrap.** Before a relationship has rotated even once, a peer
encrypts to the bootstrap keys from the `PqPublicBundle` they announced.
Unlike §11.2's bootstrap this one is *signed material from a pinned
identity*, not trust-on-first-use in its own right - but it is the one
encryption key the keybundle file holds, so **a first message exchanged
before either side rotates is not forward-secret**. This is stated plainly
rather than glossed: forward secrecy begins at the first rotation, which
is triggered by that very first message.

**Rotating and offering.** A rotation is carried by the existing
`RotateKey`/`KeyRotated` relay (§7.5), whose opaque fields carry:

```
PqRotation { encap: PqEncapKeys, generation: u64 }

signature = sign_both(
    "aloo/pq-hybrid/v2/rotate" ++ to ++ recipient_fp ++ encode(rotation)
)
```

signed with the sender's ML-DSA-87 and RSA-4096-PSS keys - the durable
identity, not the key being replaced. Binding both `to` (the live
connection) and `recipient_fp` (the durable identity) is what stops one
peer replaying a rotation as though it had been addressed to them.

The server's only change is which senders it will relay for: both rotating
modes may, the static ones may not. It still verifies nothing.

**Receiving one.** Verify both signatures against the identity already
pinned for that peer, check the rotation names us, and refuse any
`generation` not newer than the last accepted - which stops a captured
rotation being re-injected to drag a peer back onto a key an attacker has
since obtained. A rotation that fails any of these is dropped and the
previously trusted keys are left exactly as they were, so a forged
rotation can neither strand a relationship nor downgrade it. A successful
install makes that peer *fresh* again, releasing anything queued for them
(§11.5's queueing, reused unchanged).

**Retention.** Superseded decryption keys are kept, newest first, up to
`PQ_KEY_RETENTION` (8) per peer - long enough that a burst flushed under
one key, or a message already in flight when we rotate, still opens.
Beyond that they are dropped, and **the bound is the guarantee**: a key
that falls out of the window is gone, so nothing that survives can reopen
what it protected. The same reasoning and the same value as §11.7.

When a peer's connection ends, everything remembered for them - their
current keys, ours for them, their replay counter - is discarded. A later
connection is a different `UserId` starting over.

**What this does and does not give.** Forward secrecy: yes, bounded by the
retention window and starting from the first rotation. Post-compromise
security: only partial. An attacker who steals the *signing* half can sign
rotations and impersonate the identity indefinitely; recovering from that
needs a new keybundle and re-pinning, not a ratchet. That gap is real and
is the one place MLS-style group ratcheting remains stronger.

## 14. The four encryption methods, side by side

Everything above describes mechanisms; this is the summary of what a user
actually picks between. There are four methods. `KeyMode` (§3) has five
values because `rsa` has a rotating variant, but `rsa` and `rsa_per_msg`
are the same method with one property changed - same primitive, same
per-recipient encryption, same everything except how long a key lives.

| | **plain** (`none`) | **password** | **rsa** (and `rsa_per_msg`) | **pq-hybrid** |
|---|---|---|---|---|
| Tag shown | `🚨 PLAIN` | `🚨 PWD` | `🔒 RSA` / `🔒 RSAPM` | `🛡️ PQH` |
| Where the key comes from | generated at connect | derived from a password (§8.3) | loaded from a file | loaded from a keybundle file |
| Message encryption | RSA-OAEP per recipient (§8) | same | same | ML-KEM-1024 + X25519 wrap, AES-256-GCM content (§13.3) |
| Signed by the sender? | no | no | no | yes - ML-DSA-87 **and** RSA-4096-PSS, both must verify |
| Post-quantum? | no | no | no | yes, key exchange and signatures both |
| Identity survives a reconnect? | no | yes | yes | yes |
| Byte-comparison pinning (§12)? | no | yes | `rsa` yes, `rsa_per_msg` no (§12.6) | yes |
| Forward secrecy? | no | no | `rsa_per_msg` only (§11) | yes (§13.10) |
| Recipient/room binding, replay protection? | no | no | no | yes (§13.3) |
| Who can address it? | anyone | anyone | anyone | only another `pq_hybrid` sender (§13.6) |

Reading the table honestly:

- **plain** exists for trying the app out. It encrypts every message for
  real, but the identity behind it is thrown away at disconnect, so
  nothing distinguishes a returning contact from a stranger.
- **password** buys a reproducible identity with nothing to carry around,
  at the cost that anyone who learns the password *is* you.
- **rsa** is the conventional choice: a durable key file, pinned by
  contacts. `rsa_per_msg` adds forward secrecy by rotating the identity
  key itself, which is why it cannot be pinned by comparison and needs
  §12.6's resume machinery.
- **pq-hybrid** is the default and the only one that is post-quantum,
  signed, bound to its recipient and room, replay-protected, and forward
  secret at once. Its cost is that it only talks to its own kind (§13.6).

The three RSA-family methods share §8's model entirely; only their key
*sourcing* and lifetime differ. `pq_hybrid` is a different construction
throughout, which is why §13 is self-contained rather than a variation on
§8.

## 15. Sequences

Every flow in one place, for a reader implementing this from scratch.
Details are in the sections referenced.

**Connecting** (§1.3, §4, §5)

```
 client                                        server
   |--- TCP connect --------------------------->|
   |<-- Hello { auth, challenge, control } -----|   in the clear
   |--- SecureChannel(accept) ----------------->|   in the clear
   |=========== everything below is sealed =====|
   |--- Auth(response) ------------------------>|
   |<-- AuthResult { ok } ----------------------|
   |--- Identify { name, key, key_mode } ------>|
   |<-- IdentifyResult { ok, you } -------------|
   |<-- ChannelList(public channels) -----------|
```

**Meeting a peer and opening a direct link** (§7.1)

```
 alice                    server                     bob
   |<-- UserJoined(bob) -----|                        |
   |--- RequestPeerLink ---->|--- PeerCandidates ---->|
   |<-- PeerCandidates ------|<-- RequestPeerLink ----|
   |............ Ping / Pong, directly ...............|
   |=============== link Active ======================|
```

**Sending text** (§7.2) - one sealed copy per recipient, over each link

```
 alice                                              bob
   |--- Envelope { channel, envelope } (reliable) --->|
```

**Voice** (§7.3, §13.3) - setup once, then unreliable chunks

```
 alice                                              bob
   |--- StreamStart { channel, stream_id } ---------->|  reliable
   |--- StreamKeySetup { stream_id, setup } --------->|  reliable, pq only
   |--- (chunks) { stream_id, seq, blocks } --------->|  unreliable, repeats
   |--- StreamEnd { stream_id, duration_ms } -------->|  reliable
```

**File transfer** (§7.6) - consent first, then the same stream shape

```
 alice                                              bob
   |--- FileOffer { channel, stream_id, envelope } -->|
   |<-- FileAccept { stream_id } ---------------------|   (or FileReject)
   |--- StreamKeySetup { stream_id, setup } --------->|   pq only
   |--- FileChunk { stream_id, seq, blocks } -------->|   reliable, repeats
   |--- FileEnd { stream_id } ----------------------->|
```

**Rotating a key** (§7.5, §11, §13.10) - relayed, never verified by the server

```
 alice                    server                     bob
   |--- RotateKey { to } --->|--- KeyRotated { from } ->|
```

**Replacing an identity** (§12.7) - no protocol exchange at all

```
  aloo --rekey-pq-hybrid old new     # signs the new identity with the old
       |
       v
  bob sees a different key, finds a valid certificate from the identity he
  pinned, moves the pin across, and is not asked anything
```
