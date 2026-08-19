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
`pq_hybrid` key-rotation notices, and relays the candidate exchange that
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
  - [4.1 Liveness: `Heartbeat`](#41-liveness-heartbeat)
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
  - [7.7 Live voice calls](#77-live-voice-calls)
- [8. Encryption model](#8-encryption-model)
  - [8.1 RSA-OAEP chunking](#81-rsa-oaep-chunking)
  - [8.2 Cost implication for voice](#82-cost-implication-for-voice)
  - [8.3 Password-derived keys](#83-password-derived-keys)
  - [8.4 RSA signatures](#84-rsa-signatures)
- [9. Versioning and compatibility](#9-versioning-and-compatibility)
- [10. What the server never sees](#10-what-the-server-never-sees)
- [11. Rotating a peer's key during a session](#11-rotating-a-peers-key-during-a-session)
  - [11.1 Queueing while waiting for a fresh key](#111-queueing-while-waiting-for-a-fresh-key)
  - [11.2 Voice streams count as one message](#112-voice-streams-count-as-one-message)
- [12. Client-side identity pinning (`id_store`)](#12-client-side-identity-pinning-id_store)
  - [12.1 The gap this closes](#121-the-gap-this-closes)
  - [12.2 What gets pinned, and what doesn't](#122-what-gets-pinned-and-what-doesnt)
  - [12.3 When the check happens](#123-when-the-check-happens)
  - [12.4 What happens on a mismatch](#124-what-happens-on-a-mismatch)
  - [12.5 Store format and location](#125-store-format-and-location)
  - [12.6 Making a pin worth more than "these bytes differ"](#126-making-a-pin-worth-more-than-these-bytes-differ)
  - [12.7 Device id and last-seen address](#127-device-id-and-last-seen-address)
- [13. Post-quantum hybrid encryption (`pq_hybrid`)](#13-post-quantum-hybrid-encryption-pq_hybrid)
  - [13.1 Why this method, and why it looks different](#131-why-this-method-and-why-it-looks-different)
  - [13.2 Key material: an identity that stays, keys that move](#132-key-material-an-identity-that-stays-keys-that-move)
  - [13.3 One layout for everything: a setup, then chunks](#133-one-layout-for-everything-a-setup-then-chunks)
  - [13.4 Opening a send: unwrap, verify, then check the binding](#134-opening-a-send-unwrap-verify-then-check-the-binding)
  - [13.5 Key size and parameter choices](#135-key-size-and-parameter-choices)
  - [13.6 Who can send to whom](#136-who-can-send-to-whom)
  - [13.7 Voice streaming (and file transfer chunks)](#137-voice-streaming-and-file-transfer-chunks)
  - [13.8 Identity pinning](#138-identity-pinning)
  - [13.9 Client convenience: auto-generated keys and the connect-popup cache](#139-client-convenience-auto-generated-keys-and-the-connect-popup-cache)
  - [13.10 Rotating encryption keys (forward secrecy)](#1310-rotating-encryption-keys-forward-secrecy)
- [14. The three encryption methods, side by side](#14-the-three-encryption-methods-side-by-side)
- [15. Sequences](#15-sequences)
- [16. One-time-pad layer over `pq_hybrid`](#16-one-time-pad-layer-over-pq_hybrid)
  - [16.1 Turning it on, only once both sides explicitly agree](#161-turning-it-on-only-once-both-sides-explicitly-agree)
  - [16.2 Sending under the pad](#162-sending-under-the-pad)
  - [16.3 Session visibility in the DM log](#163-session-visibility-in-the-dm-log)
  - [16.4 Recovering a send whose ciphertext already left](#164-recovering-a-send-whose-ciphertext-already-left)
  - [16.5 Live key-metadata header](#165-live-key-metadata-header)
- [17. OTP mail: asynchronous, server-stored delivery](#17-otp-mail-asynchronous-server-stored-delivery)
  - [17.1 Composing: what a mail is, and who can be written to](#171-composing-what-a-mail-is-and-who-can-be-written-to)
  - [17.2 Uploading: the mail's pad spend, and the storage acknowledgement](#172-uploading-the-mails-pad-spend-and-the-storage-acknowledgement)
  - [17.3 Delivery: fetch, decrypt, acknowledge, notify](#173-delivery-fetch-decrypt-acknowledge-notify)
  - [17.4 One pad, two transports: ordering across mail and live sends](#174-one-pad-two-transports-ordering-across-mail-and-live-sends)

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
address exchange that lets two clients find each other. **No live message
content of any kind crosses it** — not text, not voice, not files, not
even as ciphertext (§7.1, §10). The single, deliberate exception is OTP
mail (§17): a user may hand the server one *one-time-pad-sealed* blob to
hold for an offline recipient — ciphertext the server has no key material
for, stored only until the recipient collects it.

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
| `Heartbeat` | Proves the connection is still alive (§4.1) |
| `OtpMailSend` | Uploads one pad-sealed mail for an offline recipient (§17.2) |
| `OtpMailFetch` | Asks for pending mail and delivery receipts (§17.3) |
| `OtpMailAck` | Recipient confirms a delivered mail was decrypted and stored (§17.3) |
| `OtpMailDeliveredAck` | Sender confirms a delivery receipt was seen (§17.3) |

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
| `OtpMailResult` | Whether an uploaded mail is durably stored (§17.2) |
| `OtpMailDeliver` | One stored mail, handed to its recipient (§17.3) |
| `OtpMailDelivered` | A sent mail was genuinely decrypted by its recipient (§17.3) |

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
| `OtpEnvelope` / `OtpFileOffer` | reliably | A `pq_hybrid` send additionally wrapped by the one-time-pad layer (§16) |
| `OtpFileContentSeq` | reliably | Names an accepted file's content-phase pad slot, independent of the offer's own (§16.2) |
| `OtpVoiceOffer` | reliably | Offers a fully-recorded voice message under the pad layer - auto-accepted, no popup (§16.2) |
| `OtpDeliveryAck` | reliably | Confirms an `OtpEnvelope`/`OtpFileOffer`/`OtpVoiceOffer` decoded, unblocking the next one (§16) |
| `DeviceIdAnnounce` | reliably | This side's device id, sealed like any other content - sent automatically once `Active` (§12.7) |
| `CallInvite` | reliably | Proposes a live voice call (§7.7) |
| `CallAccept` | reliably | Joins a call, or replies to a newly-discovered participant - the mesh's only signal (§7.7) |
| `CallReject` | reliably | Declines an invite, sent only to whoever sent it (§7.7) |
| `CallEnd` | reliably | Leaves a call still in progress (§7.7) |

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
than growing the wire shape. Under `pq_hybrid`, the bundle carries only
bootstrap encryption keys - the keys that supersede them as the
relationship rotates are never reflected here, only relayed via
`KeyRotated` (§7.5, §13.10).

```
KeyMode = Password | None | PqHybrid
```

The three values name how a client's own `my_key` was obtained, and whether
it changes:

| value | `my_key` type | key material | changes? |
|---|---|---|---|
| `Password` | `password` | one keypair derived from a password (§8.3) | no |
| `None` | `none` | one keypair generated at connect time | no |
| `PqHybrid` | `pq_hybrid` | a keybundle loaded from a file (§13) | signing half no, encryption half every message (§13.10) |

`PqHybrid` is what tells a peer to expect `KeyRotated`, for its encryption
keys only (§13.10) - `public_key_der`/the identity itself stays good for
the whole session regardless of `KeyMode`. §14 compares the three
*methods* these values describe.

All three are "static" for protocol purposes - exactly one keybundle for
the whole session, the identity itself never rotates - and behave
identically everywhere in this document except two things: which of the
three they are is broadcast (via `Identify` → `UserInfo`) precisely so
every peer can render the right tag next to that user's name (sidebar,
private-room title - SPEC.md Functionality #3); and `PqHybrid` alone
changes what `public_key_der` actually contains and how `Envelope.blocks`
is produced - see §13.

| `KeyMode`    | Tag           | Position (`KeyMode::format_with_name`) |
|--------------|---------------|------------------------------------------|
| `Password`   | `🚨 PWD`      | after the name: `name 🚨 PWD`            |
| `None`       | `🚨 PLAIN`    | after the name: `name 🚨 PLAIN`          |
| `PqHybrid`   | `🛡️ PQH`      | after the name: `name 🛡️ PQH`            |

(`KeyMode::label()` returns just the tag, unbracketed; `format_with_name`
composes it with a name, tag trailing, the same position for all three
variants.) Every tag trails the name as an annotation on it, not a
classification label sitting in front. The icon is about identity
*durability*, not "unencrypted" - every `KeyMode` still encrypts every
message with real per-recipient encryption (RSA, or for `PqHybrid` the
hybrid scheme in §13); `🚨` just flags the two sourcings (`Password`,
`None`) that don't persist an identity across separate connections the way
`PqHybrid`'s saved keybundle file does. `🛡️` is `PqHybrid`'s own icon,
read as the strongest tier (quantum-resistant signing *and* key exchange,
each additionally hedged with RSA-4096).

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
  key entirely. A connection that never closes cleanly at all - see §4.1 -
  is torn down the same way, via the same cleanup.

### 4.1 Liveness: `Heartbeat`

A closed TCP connection is not the only way a client goes away. A machine
that loses power, a laptop that sleeps mid-session, a network that drops
without sending a FIN, or a client that stops driving its socket without
actually closing it, all leave the connection sitting open from the
server's point of view - nothing to read, but nothing telling it the
client is gone either. Left alone, that means the disconnect in §4 never
fires: the nickname stays held (§5.4) and peers never see `UserOffline`,
for as long as the half-dead TCP connection happens to survive.

`Heartbeat` closes that gap:

```
Heartbeat
```

- The client sends one every `HEARTBEAT_INTERVAL` (10s) for as long as the
  connection is open, unconditionally - not only when otherwise idle.
  Actual message content never touches the server at all (§7.1, §10), so a
  session that is busily chatting is, from the server's perspective,
  exactly as silent as one that has gone completely quiet; without this,
  neither could be told apart from a dead connection.
- The server does not reply. Receiving *any* message on a connection -
  `Heartbeat` or otherwise - resets that connection's liveness clock.
- If `HEARTBEAT_TIMEOUT` (30s - three missed heartbeats, tolerating a
  couple of lost beats to ordinary network jitter) passes with nothing at
  all received, the server treats the connection exactly as if it had
  closed: same cleanup, same `UserOffline` broadcast (§6.4), same freeing
  of the nickname (§5.4).
- This is a server-side timeout only. The client neither expects nor waits
  for an acknowledgement, and a `Heartbeat` arriving from a client the
  server has no other reason to distrust is never itself an error.


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
good for the whole session (`Password`/`None`) or is a *bootstrap*
encryption key that individual peer relationships will supersede via
`KeyRotated` the first time a message is exchanged with them (`PqHybrid`;
see §13.10). The server itself does not branch on `key_mode`
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
available again as soon as its holder's connection closes - cleanly (§4)
or because the server's heartbeat check decided it was dead (§4.1).


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
voice does not (§7.3) - a recipient of any `KeyMode`
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
A `Ping` or `Pong` is attributed to a link by its
*source address* where
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
exactly like a rotating-key recipient without a fresh key (§11.2) - the
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

Only meaningful between a sender whose own `key_mode == PqHybrid`
(§3, §13.10) and one specific recipient; unrelated to channel membership.

```
// client -> server
RotateKey  { to: UserId,   new_public_key_der: bytes, signature: bytes }

// server -> client
KeyRotated { from: UserId, new_public_key_der: bytes, signature: bytes }
```

Server-side:

- Rejected (`Error` back to the sender) if `to` is not a currently-connected
  `UserId`, or if the sender's own registered `key_mode` is not
  `PqHybrid` (a non-rotating `Password`/`None` client has no business
  rotating).
- Otherwise relayed verbatim as `KeyRotated { from: <sender>,
  new_public_key_der, signature }` to `to` - one recipient, no
  channel/membership involved. Unlike §7.2-§7.3/§7.6, key rotation stays
  server-relayed rather than moving to the direct link (§7.1) - it's
  small, infrequent identity metadata, not the "content" the direct
  transport exists to keep off the server.
- The server does **not** verify `signature` - exactly like `Envelope`
  blocks, this is opaque payload as far as the server is concerned;
  §13.10 covers how the *receiving client* validates it before trusting
  the new key.

There is no server-side bookkeeping of the rotated key itself: the
registry's own copy of the sender's `public_key_der` (used to bootstrap a
*new* peer who joins later, see §13.10) is never updated by `RotateKey` -
it stays as whatever `Identify` originally sent, for the lifetime of the
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

**Rotating-key readiness**: handled the same way as voice's recipient
readiness (§11.2), not text's queue (§11.1) - a recipient whose rotating
key isn't currently fresh is simply not offered the file at all, never
queued for a later offer once a fresh key arrives. Sending an offer still
triggers this client's own rotation for the recipient actually reached
(§13.10), same as text/voice.

**Where the bytes land**: an accepted file is written straight to
the download directory (`~/.aloo/downloads`) as chunks
arrive - `safe_filename` (unchanged: reduces a peer-supplied name to just
its final path component) still guards the on-disk path against a
maliciously-crafted filename, applied after the length crop above. There is
no separate save-location prompt; accepting *is* saving.

### 7.7 Live voice calls

A **call** is a continuous, multi-user voice conversation - distinct from a
voice message (§7.3) in every way that matters: it is not push-to-talk (the
microphone stays open once joined, not just while a key is held), it has no
`MAX_RECORDING_SECS` cap, and joining it takes an explicit Accept rather
than arriving unsolicited. Like everything else in §7, there is **no
server involvement at all** - signaling and audio both travel exclusively
over punched links (§7.1), and there is no server-side call state of any
kind.

`CallInvite`/`CallAccept`/`CallReject`/`CallEnd` are four more
`P2pPayload` variants (§7.1.1), all sent reliably:

```
CallInvite { call_id: u64, channel: optional<string> }
CallAccept { call_id: u64 }
CallReject { call_id: u64 }
CallEnd    { call_id: u64 }
```

`call_id` is a fresh random token (unguessable off-path, like a link's
`link_nonce`, §7.1) chosen by whoever runs `/call`, naming the call for its
whole lifetime. `channel: some(name)` on `CallInvite` addresses a channel
call, `none` a call to one DM peer - carried in the clear (unlike a file
offer's filename, §7.6, there's nothing about a call's existence worth
hiding from a peer it's already addressed to).

**Starting a call.** The initiator becomes a participant immediately, then
sends `CallInvite` to every member of `channel` (or the one DM peer) whose
link is reachable and who isn't currently under an OTP session with them
(see this section's OTP note below) - the same recipient-computation an
ordinary channel send already does, not a list carried on the wire. Each
recipient shows an Accept/Reject popup naming the caller. Rejecting sends
`CallReject` back to whoever the invite came from and nothing else -
purely informational, since the rejecter was never added as a participant
anywhere.

**No coordinator: how a full mesh converges.** Once more than two people
are on a call, something has to tell a third participant who the other two
already are - there is no server, and no single participant (not even the
initiator) is treated as a directory the others depend on staying
reachable. Two rules, both riding the same `CallAccept` message, are
sufficient:

1. On accepting, a client broadcasts `CallAccept { call_id }` to every
   other member of the call's channel/DM it can currently address - not
   just the inviter.
2. On receiving a `CallAccept` for a call it is itself active on, from
   someone not yet in its own roster, a client adds that peer as a
   participant *and* replies with its own `CallAccept { call_id }` sent
   directly back to them alone.

A `CallAccept` for a call the receiver isn't active on (not yet decided,
already declined, or a stale message from a call already left) is simply
ignored - rule 1's broadcast reaches people who aren't ready for it as a
matter of course, and that's fine, since rule 2 is what actually
guarantees convergence. Worked example, alice having invited bob and
carol to a channel call:

```
bob accepts  -> CallAccept(bob)   broadcast to {alice, carol}
   alice (active): adds bob, replies CallAccept(alice) -> bob
   carol (not active yet): ignores it
carol accepts later -> CallAccept(carol) broadcast to {alice, bob}
   alice (active): adds carol, replies CallAccept(alice) -> carol (already
     has alice - a harmless no-op on carol's end)
   bob (active): adds carol, replies CallAccept(bob) -> carol
carol receives bob's reply: adds bob (already reached alice above)
```

Every pairwise link ends up established regardless of join order or which
messages happen to race - a participant who is discovered late is always
covered by rule 2 firing on whichever side heard about them second.

**Audio reuses the voice-streaming wire format (§7.3), addressed
differently.** Once two participants have exchanged `CallAccept`s, each
sends the other a continuous run of `PunchDatagram::Unreliable { stream_id,
seq, blocks }` chunks (and, for a `pq_hybrid` recipient, one
`P2pPayload::StreamKeySetup`, §13.7) exactly as a voice message would -
with the call's own `call_id` standing in for `stream_id`. Two differences
from an ordinary voice message:

- **No `StreamStart`/`StreamEnd` is ever sent for call audio.** A
  `CallAccept` (either direction) is what starts a participant's audio
  toward its recipient; a `CallEnd` (below) is what stops it. This also
  keeps a call's audio out of the receiving client's voice-message log -
  it was never announced as one.
- **No `MAX_RECORDING_SECS` cap applies.** A call chunk stream runs for as
  long as both sides remain participants, which is expected to be far
  longer than any one voice message.

Since a chunk/setup's only identity on the wire is `(from, stream_id)`
(§7.3's stream-identity rule, unchanged here), an implementation must
distinguish a call's `call_id` from an ordinary voice message's
`stream_id` some other way if it needs to route them differently (the
reference client tracks which `(from, id)` pairs belong to its current
call's roster) - the two numbers are drawn from disjoint generators (a
call's is fully random; a voice message's is a small per-connection
counter) and so cannot collide in practice, but nothing on the wire tags a
chunk with which kind of stream it belongs to.

**Muting is purely local - there is no wire message for it.** A muted
participant simply stops sending chunks to everyone for as long as it's
muted; every recipient's mixer hears silence from that source in the
meantime because nothing is pushed to it, the same as a moment of natural
silence during an ordinary recording. No participant is ever told another
one is muted.

**Leaving.** `CallEnd { call_id }` is sent to every other participant a
leaving client currently knows about, and each one, on receiving it, tears
down that one pairwise audio stream and drops the leaver from its roster.
The call itself has no separate "end" beyond that - it is, at any moment,
simply whichever participants haven't yet sent (or received) a `CallEnd`
for it. A client that never receives `CallEnd` from a peer who is
genuinely gone (their connection died outright) is not automatically
corrected by this section - see §7.1.3/§7.1.4 for how a lost link is
detected and surfaced independently of call state.

**Busy handling.** A client already active on one call answers *any*
`CallInvite` it receives - for a different call - with an immediate
`CallReject`, without ever showing a popup: the reference client supports
only one active call at a time, the same simplification an ordinary phone
line makes.

**Not available under OTP.** The one-time-pad layer (§16) has no
live-streaming concept at all - even voice under OTP is recorded whole and
sent once, never continuously (§16.2) - so a call can never reach a peer
it applies to. A DM call to a peer under an active OTP session is refused
outright, with nothing sent; a channel call simply excludes any member
under one from the invite (and, symmetrically, from the `CallAccept`
broadcast above), the same partial-delivery treatment an ordinary channel
send already gives a rotating-key recipient without a fresh key (§11.2).

## 8. Encryption model

**There is no shared/session/hybrid key anywhere in this protocol for
`Password`/`None`.** (§13 covers the one exception, `PqHybrid`, which
*does* use a per-message shared key - deliberately, for reasons explained
there; everything below this paragraph describes the other two modes.)
Every plaintext payload - a text message, or one voice
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
(`KeyMode::Password`/`None`/`PqHybrid` - the last one loaded from a
file rather than autogenerated or password-derived, but equally static
for the whole session, see §13). `PqHybrid` additionally rotates its
*encryption* keys - not the identity itself - per peer relationship, on
every message sent or received with that peer; see §13.10.

### 8.1 RSA-OAEP chunking

Raw RSA (and OAEP padding) can only encrypt a payload smaller than the
key's modulus, so any payload larger than that limit is split into
multiple independently-encrypted blocks and reassembled by concatenating
their decryptions in order:

- Ciphertext block size is always exactly `key_size_bytes` (i.e. exactly
  the RSA modulus size - 256 bytes for a 2048-bit key, the size this
  app's own keygen produces by default, per `crypto::RSA_KEY_BITS = 2048`;
  externally-supplied PEM keys may use a different size, and the protocol
  itself places no fixed size requirement on keys - two peers just need
  compatible RSA key sizes for whichever DER/PEM keys they actually
  exchange).
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

There is exactly one RSA signing primitive in this protocol, used as the
classical half of every `pq_hybrid` signature: a send commitment (§13.3)
and an encryption-key rotation (§13.10) alike.

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

One addition since §17: a client using OTP mail hands the server a
one-time-pad-sealed blob to hold until its recipient collects it. The
server then additionally sees (and stores, on disk, until delivery) that
blob's **size and routing metadata** - sender and recipient nickname, the
pairwise pad contact name, a sequence number, a client-claimed timestamp -
but never its content: the blob is sealed under a pad the server holds no
byte of, and its integrity is anchored to the sender's pinned identity
signature *inside* the sealed payload (§17.2), so the server can neither
read nor undetectably alter a mail it stores.

## 11. Rotating a peer's key during a session

Only `KeyMode::PqHybrid` (§3) rotates its encryption keys during a
session - the trigger, signing, and receiver-side verification are all
specific to that scheme and are covered in full in §13.10. This section
covers the two pieces of client behavior around a rotating peer that
apply generically, independent of which scheme is doing the rotating:
what happens on the sending side while a recipient's key is momentarily
stale, and why a live voice stream doesn't rotate mid-stream. A
non-rotating (`Password`/`None`) peer never enters either of these paths
- it is always considered ready.

### 11.1 Queueing while waiting for a fresh key

If a client wants to send to a peer whose key rotates (currently:
`pq_hybrid`) and for whom it does not currently hold a fresh key (never
received one yet, or already used the one it has), the message is
**not** sent - it is held in an in-memory, per-peer FIFO queue instead.
There is no wire message for "queued" state; this is purely local client
behavior. A peer whose key never rotates is always considered ready and
never queued.

When a `KeyRotated` for that peer is validated (§13.10), the **entire**
queue for that peer is flushed at once: every queued message is
encrypted under the one newly-fresh key and sent, in FIFO order, in the
same batch, and only then is that key marked stale again. This means one
rotation can legitimately cover several messages' worth of plaintext, not
strictly one - see §13.10's retention discussion for why the receiver has
to tolerate that.

### 11.2 Voice streams count as one message

Live voice (§7.3) does not rotate per chunk - an entire stream (`*Start`
through `*End`) is treated as a single message for every purpose in this
section:

- Recipient readiness is decided once, at `*Start`: a rotating-key
  recipient without a fresh key at that moment is simply left out of the
  stream's recipient list entirely (silently, same as any other
  partial-delivery case in §7.2) rather than queued - queueing audio for
  indeterminate later delivery has no sensible playback semantics.
- Every chunk in the stream is encrypted with the one key snapshot taken
  at `*Start` for each included recipient - no rotation happens mid-stream.
- The sender's own rotation fires once per recipient, at `*End`, not at
  `*Start` and not per chunk. Symmetrically, a receiver's own rotation
  fires once, when that stream's `*End` arrives (or the receiver's own
  idle timeout finalizes it), not per chunk.

## 12. Client-side identity pinning (`id_store`)

**This entire section is client-local behavior with no wire-protocol
effect** - it's documented here because getting it wrong
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
separate connections. Every peer's `public_key_der` is trust-on-first-use
on every single connection - nothing before this section gave any peer a
reason to remember a name's key from one session to the next, regardless
of whether the underlying key material itself is stable (`Password`,
`PqHybrid`) or freshly generated (`None`). Concretely:
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
alarm condition is "these bytes differ from last time". It is the only
pinning mechanism this app has: every `KeyMode` either participates in it
or is left unprotected, covered below.

Under byte comparison, only `KeyMode`s whose key is actually the *same* key
across two separate connections can be checked - not merely
"persistent-looking" ones:

| `KeyMode` | Checked? | Why |
|---|---|---|
| `Password` | yes | `resolve_my_keypair` re-derives the keypair from the password via the password derivation (§8.3: PBKDF2 into a deterministic CSPRNG seed) - same password in, same keypair out, every time |
| `PqHybrid` | yes | the identity keybundle is loaded from a file (§13.2) - the same file produces the same bundle on every connect, for as long as it exists. Rotation (§13.10) only ever changes the encryption half, never the identity that gets pinned here |
| `None` | no | autogenerated fresh every connect by design (§3) - nothing persists it between sessions, so the very same legitimate user reconnecting announces a genuinely different key every time. Comparing it would flag a false "possible impersonation" on every single reconnect - worse than not checking at all, since a warning that fires constantly for no reason trains a user to dismiss it, including the one time it's real |

In short: byte comparison only works for the two `my_key` types backed by a
secret the user actually holds onto between sessions (a key file, or a
password they remember). For a `my_key` type whose key material is, by
design, thrown away and regenerated at every connect, there is no stable
byte string to compare - which is a statement about *this* mechanism, not
about `id_store` as a whole. `None` is the one `KeyMode` this document
leaves genuinely unprotected - it has no stable key to compare.

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

1. Starts a review (`session::check_identity` calling
   `UiState::begin_identity_review`) that immediately gates messaging (point
   2) but shows nothing yet - the popup itself is withheld until this
   specific connection's P2P address and device id are known, since showing
   it any earlier would give the user only two fingerprints to judge a key
   change by instead of the fuller picture §12.7 adds. Once punching
   resolves - `Active` (usually within a second or two) or `Lost` (after
   `PUNCH_TIMEOUT`/`SIGNAL_TIMEOUT`, §7.1, if it never punches through at
   all) - `session::reveal_pending_identity_review` finishes the review and
   opens (or queues, if another peer's review is already showing - see
   below) an on-screen popup naming the peer, e.g. `Identity review: alice`,
   with a message of the form `'alice' connected with a different key than
   last time (was <fp>, now <fp>) - possible impersonation.` followed by
   the last-known and new address/device id (§12.7's exact wording), where
   each `<fp>` is a 16-hex-character prefix of the fingerprint computed
   on-the-fly from the old and new key bytes purely for compact display -
   the fingerprint itself is never what's stored or compared (§12.2). Two
   buttons, `Accept` and `Reject`, are shown; `Reject` is focused by default
   (the review buttons) so accepting always takes a deliberate move off the
   safer default rather than an accidental confirm. This is purely a local
   UI cue - it has no wire-protocol meaning and isn't sent to or expected
   from peers.
2. Gates messaging with that peer from the moment the mismatch is detected
   (not from whenever the popup happens to become visible) until it is
   resolved (see below) -
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
   pins the new key, records the address/device id this connection was
   actually reviewed under as its last-seen values (§12.7), and **saves
   the store to disk immediately, synchronously** (saving the store, same
   as the old immediate-save policy) - the on-disk file reflects the new
   pinning the instant the decision is made, not batched or deferred.
   Every message held per point 2 is then revealed into the real log, in
   arrival order, and the peer is fully trusted again (sidebar color,
   sending, everything).
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
<nickname><TAB><hex-encoded public_key_der><TAB><trust><TAB><last addr><TAB><last device id>\n
```

e.g. `alice\t30820122300d06092a864886f70d01010105000382010f00...\ttofu\t203.0.113.7:51820\t3f9a...\n` -
the full DER bytes, lowercase-hex-encoded (lowercase hex, the same
encoding the fingerprint already uses, not base64 or raw bytes) so
the file stays plain text no matter what the key bytes are; `trust` is
`tofu` or `verified` (§12.6); `last addr`/`last device id` are §12.7's
last-seen values, either or both left empty until they have something to
record. Entries are written in sorted-by-nickname order on save so the
file diffs cleanly under version control or manual inspection.

A nickname containing a tab, `\n`, or `\r` is never pinned (silently
treated as if it were a first-ever sighting, with nothing written) - a
`display_name` is attacker-controlled input (any connected peer chooses
their own), and accepting one containing the file's own field delimiter
would let a remote peer inject spurious records into a purely local trust
file. `device_id` is announced by a peer the same way a nickname is, so
it gets the same treatment: an unstorable one is silently dropped rather
than written (§12.7). The key half has no such restriction - hex digits
can't collide with either delimiter no matter what the underlying bytes
are, so any DER-encodable key is always storable. A line whose key half
fails to hex-decode (odd length, non-hex character - e.g. hand-editing
damage) is skipped on load, same as a line missing the name or key
column entirely; the trust/address/device-id columns are all
independently optional on the way in (a store written before one of them
existed, or with an empty field, still loads correctly) - loading the
store never fails the whole store over one bad line or an older format.

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


### 12.6 Making a pin worth more than "these bytes differ"

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

### 12.7 Device id and last-seen address

Two more client-local, informational-only signals, purely to give a human
more to go on when a mismatch review (§12.4) actually asks them to decide -
neither one is trusted or checked by anything; they're just displayed. An
address is never something that can be kept confidential in transit (it's
the packet's own source, inherent to any IP communication - see §12.1's
"what remains open" reasoning extended to this), but a device id is real
payload, and it always travels sealed exactly like ordinary content -
never in the clear, and never inside the punch handshake itself.

**Device id.** Each installation generates a random 50-character
lowercase-hex id the first time one is needed and reuses it for that
machine's whole lifetime: `crypto::random_bytes(25)` hex-encoded, written
to `~/.aloo/d_id` (`client::device_id::load_or_create`) and read back
as-is on every later run rather than regenerated. Like a nickname, it is
entirely self-reported by whoever holds it - nothing stops a modified
client from lying about theirs - so it carries no security weight on its
own; it exists only to give a human something else to eyeball.

**`DeviceIdAnnounce`: sent encrypted, once a link is `Active`.** A new
`Content::DeviceIdAnnounce` tag and `P2pPayload::DeviceIdAnnounce {
envelope: Envelope }` (§7.1's `PunchDatagram::Reliable`, exactly like a
text message or file offer) carry it - `envelope`'s plaintext is just the
device id's raw UTF-8 bytes, sealed per-recipient with whichever scheme
the recipient's `KeyMode` uses (RSA-OAEP, or the `pq_hybrid` one-chunk
send, §13), the same `envelope::encrypt_envelope_for` dispatch every
other content type goes through. The punch handshake itself
(`Ping`/`Pong`) carries no device id at all - deliberately kept out of
that layer, which has no notion of recipient keys - so a device id is
only ever sent once the link reaches `Active` and the peer's key is
already known (from `Identify`/`UserJoined`, over the TCP control
channel). Sent automatically, unprompted, every time a link reaches
`Active` (`session::send_device_id_announce`) - idempotent, and cheap
enough that a link flap simply resends it. Silently skipped if this
client cannot currently address the recipient (`keymode_policy::can_address`
- the same partial-delivery rule every other content type follows) or
encryption fails for any other reason; there is nothing to retry beyond
the automatic resend the next `Active` transition already gives it.

On arrival, `session::on_device_id_announce` decrypts it (independent of
any trust gate on the sender - this is exactly the data an impersonation
review needs to resolve, not visible chat content subject to §12.4's
hold-and-reveal) and caches the plaintext. Processed unconditionally on
both sides regardless of who initiated the mismatch review, if any.

**Last-seen address/device id.** Once *both* a peer's direct link is
`Active` (the address) and their `DeviceIdAnnounce` has decrypted (the
device id) - the two arrive independently and may race either way, so
whichever happens second is what actually acts
(`session::maybe_resolve_p2p_identity_data`) - they are recorded against
their *currently pinned* key in `id_store`
(§12.5's trailing two columns), refreshed on every later `Active`
transition for that same pin, not just the first. This deliberately does
**not** happen while a mismatch review for that peer is still outstanding
(`AwaitingPeerInfo`/`Pending`): the review needs to compare against
whatever was recorded *before* this connection, so nothing overwrites it
until the user actually `Accept`s (at which point the newly-reviewed
connection's address/device id become the new last-seen values, per
§12.4 point 3).

**How this shows up in a mismatch review.** §12.4's mismatch popup message
gets two more lines, one for each side of the comparison:

```
Last known from <addr> (device <id>).
Now connecting from <addr> (device <id>).
```

The "last known" half is read straight from `id_store` - whatever was
recorded the last time this nickname's *previous* key went `Active`,
`unknown` if that never happened (e.g. the pin was set by an
`--export-identity-card` import, §12.6, rather than a live connection).
The "new" half is this specific connection's own values, which is why the
review itself is held open a moment before it's shown at all:
`check_identity` detecting the mismatch only starts the review
(`UiState::begin_identity_review`) and gates messaging with the peer
immediately, exactly as before - the popup itself waits for
`session::reveal_pending_identity_review`, called from
`maybe_resolve_p2p_identity_data` once both pieces are known, or from the
link going `Lost` (punching gave up before ever reaching `Active`, per
`PUNCH_TIMEOUT`/`SIGNAL_TIMEOUT`, §7.1 - both new fields show `unknown`
rather than leaving the review open forever). Every path reveals the
review exactly once; a link that later flaps and re-punches does not
re-reveal or re-chime.

## 13. Post-quantum hybrid encryption (`pq_hybrid`)

`KeyMode::PqHybrid` is the third `my_key` method: ML-DSA-87+RSA-4096 signing,
ML-KEM-1024+RSA-4096 key-wrap, AES-256-GCM bulk encryption. Unlike the
other methods in this document, it is not built on RSA-OAEP-per-recipient at
all (§8) - it needs a shared symmetric key by construction, so it is
documented here as its own, self-contained model rather than a variation on
§7-§8's. Like §11/§12, this section has real wire-visible pieces (a new
`KeyMode` variant, and what `public_key_der`/`Envelope.blocks` actually
contain for it) but otherwise reuses existing message types unchanged - no
new `ClientMessage`/`ServerMessage` variant, no change to `Envelope`'s or
`UserInfo`'s shape.

### 13.1 Why this method, and why it looks different

The other two methods share one property: RSA-OAEP encryption needs
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
milliseconds - cheap enough to run inline on the event-loop task, with no
background worker and no carve-out for voice needed. The pairing is the
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
the same trick file transfer's `FileOfferPayload` convention (§7.6)
already uses. No wire schema change to `Identify` or `UserInfo` at all.

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

The RSA signing key is 4096 bits, larger than the 2048-bit keys this app
uses elsewhere, for extra security margin - at the cost of slower keygen,
paid once at `aloo --keygen-pq-hybrid` time rather than per message. It
is the only RSA key a `pq_hybrid` identity has; the encryption
side's classical hedge is X25519 (§13.2), because that half rotates and
RSA keygen is far too slow to repeat per message.

ML-DSA-87 and ML-KEM-1024 are each the highest security-category parameter
set NIST standardized (FIPS 204/203) - the whole point of this method is
the strongest tier available, not the fastest.

### 13.6 Who can send to whom

Because step 1 needs the *sender's* ML-DSA-87/RSA-sign identity, and only a
`pq_hybrid` client has one:

- **A `pq_hybrid` recipient can only be addressed by a `pq_hybrid`
  sender.** A sender whose own `my_key` is `password`/`none` has no way to
  produce a valid `SendSetup` signature - such a recipient is silently
  excluded from that sender's channel/DM/file/voice send, the same
  partial-delivery pattern as any other unreachable recipient in this app
  (an offline member, a not-yet-fresh rotating-key recipient, §11.1/§11.2).
  the addressing rule is the reference implementation of this check.
- **A `pq_hybrid` sender can still address any non-`pq_hybrid` recipient
  normally** - RSA-OAEP (§8) needs no sender identity at all, so a
  `pq_hybrid` client falls straight through to the ordinary `encrypt_for_one`
  path for a `password`/`none` recipient, exactly like any other sender
  would.

A mixed channel - some members `pq_hybrid`, some not - therefore behaves
asymmetrically per sender: a `pq_hybrid` member's message reaches everyone;
a non-`pq_hybrid` member's message reaches everyone *except* the `pq_hybrid`
members.

### 13.7 Voice streaming (and file transfer chunks)

`pq_hybrid` voice is a good fit for the same reason its rotation is cheap
in general (§13.2): the expensive asymmetric work (ML-DSA-87 sign,
ML-KEM-1024 encapsulate, RSA-4096 operations) happens once per stream, not
once per 15ms chunk - it still respects the "voice counts as one message"
rule (§11.2) rather than rotating mid-stream, even though its own keygen
would be cheap enough to afford it.

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
reconnects by construction, exactly like `password` (a deterministic
re-derivation). Rotation (§13.10) does not change that: what rotates is
the encryption half, which is not what gets pinned.

So the bundle participates in `id_store`'s ordinary byte-comparison
pinning unchanged (§12.2's table) - the pinning predicate is the single
predicate `check_identity` consults, covering exactly `Password`/
`PqHybrid`.

### 13.9 Client convenience: auto-generated keys and the connect-popup cache

Like §12, this is purely client-local behavior with no wire-protocol
effect - a server, or a peer whose client doesn't implement this section at
all, is fully interoperable with one that does. It exists because `13.2`'s
file-loaded keybundle would otherwise be the one `my_key` type that can't
be used the moment you open the app for the first time - `none` needs
nothing prepared, and every other type fails
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
a malformed line, the same conventions the identity store already uses.
Every submitted `pq_hybrid`
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
host/port afterward, the same convention `id_store`/the nickname field
already use for their own prefills.


### 13.10 Rotating encryption keys (forward secrecy)

A `pq_hybrid` identity's signing half never changes; its **encryption half
rotates per peer relationship**, once for every message sent to that peer
and once for every message received from them (a live voice stream
counts as a single message for this purpose - §11.2, not one rotation
per chunk). Each superseded key is destroyed. That is the whole
mechanism, and what it buys is this: someone who later steals the
keybundle file gets your identity, not your history.

Rotation is cheap here - ML-KEM + X25519 keygen is microseconds, against
the hundreds of milliseconds an RSA-4096 keygen would cost - so it runs
inline on the client's event-loop task with no background worker needed.

**Bootstrap.** Before a relationship has rotated even once, a peer
encrypts to the bootstrap keys from the `PqPublicBundle` they announced.
This is *signed material from a pinned identity*, not trust-on-first-use
in its own right - but it is the one encryption key the keybundle file
holds, so **a first message exchanged before either side rotates is not
forward-secret**. This is stated plainly rather than glossed: forward
secrecy begins at the first rotation, which is triggered by that very
first message.

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
Verifying across a reconnect needs nothing special, since the verifying
key (the durable identity) never changes.

The server's only change is which senders it will relay for: only
`pq_hybrid` senders may, the static modes may not. It still verifies
nothing about the payload itself.

**Receiving one.** Verify both signatures against the identity already
pinned for that peer, check the rotation names us, and refuse any
`generation` not newer than the last accepted - which stops a captured
rotation being re-injected to drag a peer back onto a key an attacker has
since obtained. A rotation that fails any of these is dropped and the
previously trusted keys are left exactly as they were, so a forged
rotation can neither strand a relationship nor downgrade it. A successful
install makes that peer *fresh* again, releasing anything queued for them
(§11.1's queueing, reused unchanged).

**Retention.** Superseded decryption keys are kept, newest first, up to
`PQ_KEY_RETENTION` (8) per peer - long enough that a burst flushed under
one key, or a message already in flight when we rotate, still opens.
Beyond that they are dropped, and **the bound is the guarantee**: a key
that falls out of the window is gone, so nothing that survives can reopen
what it protected.

When a peer's connection ends, everything remembered for them - their
current keys, ours for them, their replay counter - is discarded. A later
connection is a different `UserId` starting over.

**What this does and does not give.** Forward secrecy: yes, bounded by the
retention window and starting from the first rotation. Post-compromise
security: only partial. An attacker who steals the *signing* half can sign
rotations and impersonate the identity indefinitely; recovering from that
needs a new keybundle and re-pinning, not a ratchet. That gap is real and
is the one place MLS-style group ratcheting remains stronger.

## 14. The three encryption methods, side by side

Everything above describes mechanisms; this is the summary of what a user
actually picks between. There are three methods, matching `KeyMode`'s
(§3) three values one for one.

| | **plain** (`none`) | **password** | **pq-hybrid** |
|---|---|---|---|
| Tag shown | `🚨 PLAIN` | `🚨 PWD` | `🛡️ PQH` |
| Where the key comes from | generated at connect | derived from a password (§8.3) | loaded from a keybundle file |
| Message encryption | RSA-OAEP per recipient (§8) | same | ML-KEM-1024 + X25519 wrap, AES-256-GCM content (§13.3) |
| Signed by the sender? | no | no | yes - ML-DSA-87 **and** RSA-4096-PSS, both must verify |
| Post-quantum? | no | no | yes, key exchange and signatures both |
| Identity survives a reconnect? | no | yes | yes |
| Byte-comparison pinning (§12)? | no | yes | yes |
| Forward secrecy? | no | no | yes (§13.10) |
| Recipient/room binding, replay protection? | no | no | yes (§13.3) |
| Who can address it? | anyone | anyone | only another `pq_hybrid` sender (§13.6) |

Reading the table honestly:

- **plain** exists for trying the app out. It encrypts every message for
  real, but the identity behind it is thrown away at disconnect, so
  nothing distinguishes a returning contact from a stranger.
- **password** buys a reproducible identity with nothing to carry around,
  at the cost that anyone who learns the password *is* you.
- **pq-hybrid** is the default and the only one that is post-quantum,
  signed, bound to its recipient and room, replay-protected, and forward
  secret at once. Its cost is that it only talks to its own kind (§13.6).

**plain** and **password** share §8's RSA-OAEP model entirely; only their
key *sourcing* differs. `pq_hybrid` is a different construction
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

**Replacing an identity** (§12.6) - no protocol exchange at all

```
  aloo --rekey-pq-hybrid old new     # signs the new identity with the old
       |
       v
  bob sees a different key, finds a valid certificate from the identity he
  pinned, moves the pin across, and is not asked anything
```

## 16. One-time-pad layer over `pq_hybrid`

An additional, optional layer of secrecy for one specific `pq_hybrid`
conversation at a time: the finished send this method already produces
(§13.3's setup-plus-chunk, or a stream's setup) is, when this layer is
active for that peer, further encrypted through a one-time pad before it
goes on the wire, and the reverse on the way in - before the ordinary
`pq_hybrid` open ever runs. Nothing about §13's key material, signatures or
binding changes; this layer sits entirely outside it.

This is pairwise and per-contact, never a property of an identity or a
whole channel: two peers who both use `pq_hybrid` may or may not have this
layer active between them, independent of what either uses with anyone
else. A channel message to a mix of such peers and ordinary ones sends an
extra-wrapped copy to the former and a plain `pq_hybrid` copy to the
latter, exactly as today's mixed-`key_mode` channels already do.

The pad itself is managed entirely by an external keychain tool, never by
this protocol or its implementation: generating pad material, tracking how
much of it remains, and physically destroying each byte the instant it is
used are all outside this document's scope. What this section defines is
only the two things the wire protocol itself is responsible for: how the
two sides agree on a shared pad in the first place, and how a send that
uses one is carried.

### 16.1 Turning it on, only once both sides explicitly agree

Either side may, at any time and only by its own user's explicit action,
propose starting a one-time-pad session with the other. This is never
automatic: not on connect, not on a schedule, not in response to anything
the peer does. **Neither side ever considers the layer active on its own
say-so** - starting it always ends in an explicit accept from the other
party, confirmed back to the proposer, and both users see the outcome
(started or cancelled) regardless of which of them asked.

The proposer first checks whether a pad is already in place for this peer
(from a previous session, or arranged by the two users themselves outside
this protocol entirely). That check decides which of two proposals to
send - it never skips asking the other side:

```
 alice (no pad yet)                                          bob
   |--- OtpKeySetup { name, size, offset:0,    total_len, ... } ->|   ordinary pq_hybrid envelope
   |--- OtpKeySetup { name, size, offset:16K,  total_len, ... } ->|   ordinary pq_hybrid envelope
   |--- ... (one per 16KB slice of enc_key/dec_key) -------------->|
   |<-- OtpKeySetupAck { name, accepted, reason } ----------------|   ordinary pq_hybrid envelope

 alice (pad already in place)                                 bob
   |--- OtpSessionRequest { name } -------------------------------->|   ordinary pq_hybrid envelope
   |<-- OtpKeySetupAck { name, accepted, reason } ----------------|   ordinary pq_hybrid envelope
```

All message types here are carried as ordinary `Envelope`s, sealed under
the ongoing `pq_hybrid` conversation exactly like a text message - the
one-time-pad layer cannot protect the handshake that establishes it, and
does not try to.

Generating a fresh pad is itself gated on the initiating user's explicit
confirmation - shown a plain choice ("generate and share one automatically
over pq_hybrid, or arrange it yourself and place the keys where the local
keychain expects them") before anything is generated or sent. Confirming
then asks for a size (MB per key, 1 to 900,000 - re-prompting on anything
outside that range rather than guessing), so a fresh pad is never
generated at some fixed size the user didn't choose. That size travels
with the setup message and is shown to the deciding side in its own
invite popup before it ever has to accept or reject - a much larger pad
takes longer to arrive and claims more local disk/keychain space than a
small one, and that isn't something to discover only after agreeing. The
pad material this produces (twice the chosen size, one key per direction)
is far larger than one `pq_hybrid` send can carry: a `pq_hybrid` envelope
still rides one
UDP datagram with no fragmentation of its own below this layer, well under
even one key's raw size, so it never travels as a single `OtpKeySetup`
message. Instead each side of the pad is sliced into small (16KB)
`OtpKeySetupChunk`s, each its own ordinary `pq_hybrid` send with its own
`offset`/`total_len`, and the receiving side accumulates them
(`OtpKeySetupReassembly`, keyed per sender) until the last one lands - only
then is the reassembled pad staged as a visible invite. A chunk that
doesn't pick up exactly where the last accepted one for that sender left
off (wrong contact, wrong total length, wrong offset) is rejected rather
than spliced in, so a stale or unrelated attempt can never produce a
corrupted "complete" pad. The bytes carried this way, once reassembled,
are opaque pad material for the *receiving* side's use, generated by the
initiator alongside its own half - never derived, negotiated, or
influenced by anything the wire has carried before, since a one-time pad's
only security property comes from being independent, true randomness.

The receiving side never acts on either proposal automatically: it is
shown who is asking and must explicitly accept or reject before anything
is written to its keychain or acknowledged. Accepting `OtpKeySetup` adopts
the received pad; accepting `OtpSessionRequest` instead confirms the
receiving side's *own* existing pad for this contact is actually still
there (a proposal alone is not proof of that). Either way, only a
genuine accept produces `OtpKeySetupAck { accepted: true }` - and only
receiving that reply lets the initiator consider the session active on
its own side too. A plain reject, or the initiating user declining the
local confirmation in the first place, ends the same way: `accepted:
false`, and neither side's keychain state changes as a result. Whichever
side learns the outcome shows it plainly - "OTP session started at
&lt;timestamp&gt;" or "OTP session cancelled" - so it is never only the
proposer who knows whether the session actually began.

One rejection reason is handled differently: `OtpSessionRequest` proposes
resuming a pad the initiator's own side believes already exists, but that
belief can be wrong - the initiator's keychain genuinely has an entry
while the peer's does not (an earlier attempt the peer never completed
being the ordinary way this happens). The peer's ack reports this exact
case as `accepted: false` with the reason "no matching key found on my
end", and *this* one the initiator does act on: its own stale keychain
entry is removed (`otp --remove-contact`) and forgotten locally, and the
same generate-and-share confirmation a first-ever `/otp` would have shown
is offered again - without it, a bare retry would keep proposing the same
already-broken contact forever, and a fresh key generation would be
refused outright by the initiator's own leftover entry (`otp
--add-contact` never overwrites an existing name). Every other rejection
reason - including a genuinely offline/never-provisioned peer's plain
reject - is left alone; this recovery is specifically for the one case
that is otherwise a permanent dead end.

### 16.2 Sending under the pad

Once active, a send to that contact is wrapped once more after the
ordinary `pq_hybrid` seal, and carries a `seq` naming its place in this
layer's own independent counter for that contact (unrelated to `send_id`,
which the underlying `pq_hybrid` send still has and still enforces on its
own terms):

```
 alice                                              bob
   |--- OtpEnvelope { channel, seq, envelope } -------->|
   |<-- OtpDeliveryAck { seq } --------------------------|
```

The receiving side only sends `OtpDeliveryAck` once the message has been
fully unwrapped *and* successfully delivered to the local application -
never on receipt alone. The sending side treats that ack, and only that
ack, as proof the message actually reached and was understood by the
other end, and will not encrypt a second message to this contact under
the pad until it has arrived. A message typed while one is still
outstanding is held locally and sent the moment the ack for the previous
one comes in; nothing about this queueing is itself visible on the wire.
This is the same requirement the underlying pad-management tool enforces
on its own local state (never spend pad material on a message before the
previous one is confirmed delivered) - here answered with the only thing
that can actually prove delivery across a network: a message from the
peer that received it.

**File content.** A file's *offer* is itself a genuine, independent pad
spend - `OtpFileOffer`'s `envelope` is wrapped through the pad exactly like
an ordinary `OtpEnvelope` (§16.2 above). This costs a bit of pad on every
offer, including ones later rejected - an accepted tradeoff for keeping
the filename and size off the wire in the clear, deliberately made in
favour of privacy over pad economy. The file's actual *content*, once
accepted, is a **second, wholly independent** pad spend, named by its own
`seq` (carried by `OtpFileContentSeq`, not the offer's) and closed by its
own `OtpDeliveryAck` - two pad-protected round trips per file:

```
 alice                                                bob
   |--- OtpFileOffer { stream_id, seq: A, envelope } ---->|   envelope: pad-wrapped pq_hybrid
   |<-- OtpDeliveryAck { seq: A } -------------------------|   the instant bob decrypts + queues
   |                                                       |   the popup - independent of accept
   |<-- FileAccept { stream_id } ---------------------------|
   |    (reserves a *second*, independent pad slot,
   |     encrypts the file whole through it into a
   |     local temp file)
   |--- OtpFileContentSeq { stream_id, seq: B } ---------->|   names the content-phase slot
   |--- FileChunk { stream_id, seq, blocks } -------------->|   any number, as today (§7.6)
   |--- FileEnd { stream_id } ------------------------------>|
   |    (bob decrypts the assembled temp file
   |     whole through the pad, into the real
   |     download, then deletes the temp copy)
   |<-- OtpDeliveryAck { seq: B } --------------------------|
```

Each `FileChunk` is still individually `pq_hybrid`/PQ-sealed exactly as an
ordinary transfer's chunks are (§7.6) - the pad layer wraps the file's
plaintext *once, whole*, before that chunking ever runs, rather than
per-chunk (the same reasoning §16.1 gives for the key-setup pad itself:
no per-chunk framing is cheap enough to spend pad material against).

Splitting the offer and the content into two independent slots is not
optional bookkeeping - the pad tool itself refuses a second `--encrypt`
for a contact before the first is confirmed delivered (§16.2 above), so
one slot could never honestly cover both. The content-phase reservation
is made only once the file-content encrypt genuinely succeeds (the same
reserve-after-spent ordering the offer and every text send already use),
so a genuine encrypt failure there needs no gate release either - nothing
was ever reserved to begin with. If the *content*-phase gate happens to be
busy when `FileAccept` arrives (something else is mid-flight for this
contact), the content encrypt is queued and retried the moment that
other send's ack clears the gate - the accepted offer itself is never
re-sent or re-decided, only the pad-protected encrypt of its bytes waits.

Because the offer is a genuine pad spend, its recovery follows exactly
the same rule AC-147/§16.2 gives every other pad-protected send:
once it has left the machine, nothing may encrypt a fresh offer to that
contact again until either a real `OtpDeliveryAck` arrives or
`recover_and_resend` replays the *exact* ciphertext already sent - never a
freshly re-encoded one. A user who goes offline before the offer's ack
arrives has no other path forward; the next reconnect's recovery pass is
what resumes it.

**Voice content.** Recording under this layer is never live: there is no
per-chunk framing cheap enough to make streaming practical against a
resource destroyed the instant it is used, so instead of the ordinary
live `StreamStart`/chunks/`StreamEnd` sequence (§7.3), the whole message
is captured locally first and only then sent, once, as a `FileOffer`
would be - except a voice message has no consent prompt to wait for
(voice never has one, on or off this layer), so it skips the
accept/reject round trip that a file offer waits for: the pad is spent
encrypting the complete recording immediately, and `OtpVoiceOffer` carries
both the offer and the (already-encrypted) content's arrival in one
uninterrupted exchange - the receiving side answers with `FileAccept`
itself, automatically, the moment the offer decodes:

```
 alice                                              bob
   |    (finishes recording; encrypts the
   |     whole clip through the pad, into a
   |     local temp file)
   |--- OtpVoiceOffer { stream_id, seq, envelope } ----->|   envelope: ordinary pq_hybrid
   |<-- FileAccept { stream_id } -------------------------|   sent automatically, no popup
   |--- FileChunk { stream_id, seq, blocks } ----------->|   any number, as §7.6
   |--- FileEnd { stream_id } --------------------------->|
   |    (bob decrypts the assembled temp file
   |     whole through the pad, decodes it back
   |     to PCM, and deletes the temp copy)
   |<-- OtpDeliveryAck { seq } ---------------------------|
```

Once decrypted, the recording becomes an ordinary, already-finished voice
message in the peer's log - the same shape a completed live stream would
have left behind - so replaying it (Enter, §7.3) works identically either
way; the only difference this layer makes is that it arrives all at once
once fully received, rather than becoming playable partway through.

### 16.3 Session visibility in the DM log

Every error/confirmation this layer shows (§16.1's "started"/"cancelled",
§16.2's queued-message notice, any of the failure paths above) is shown
two ways at once, not just as the small top-right status notice: the same
text is also logged as a line in the relevant peer's own DM room, marking
it unread exactly like any other arrival if that room isn't the one
currently open. The notice itself clears; the room's own history of how
its session got set up (or why it didn't) does not.

While a mutual-consent session is genuinely active with a DM's peer
(§16.1's "started" moment, on either side), every real message shown in
that room - never the app's own lines about the session itself - carries
a 🛡️ prefix, so which conversation is currently under the extra pad layer
is never something the user has to remember or go check.

A text message is logged the moment it's typed, before the send it
describes has actually been attempted - the same optimistic-then-corrected
approach a plain (non-OTP) send already uses. If that send then genuinely
fails - the underlying `pq_hybrid` envelope couldn't be built, or `otp`
itself failed to encrypt it (including a pad that's run out, §16.2) - the
row it was logged under is found again and shown in red, so a message
that never reached the peer is never left looking identical to one that
did. This is scoped to direct messages: a channel send can be OTP-wrapped
independently per recipient, so there is no single row a failure could
unambiguously mark.

### 16.4 Recovering a send whose ciphertext already left

Once a message's ciphertext has genuinely gone out and this layer's own
gate is holding (§16.2 - waiting for `OtpDeliveryAck`), the sender must
never build a fresh one for that contact, no matter how long the ack
takes or why it never arrives - not a lost packet beyond what the direct
link's own reliable retransmission already covers, not this app
restarting mid-conversation, not the peer's connection dropping and
coming back. Encoding a second message before the first is genuinely
acknowledged would desync the receiving side's decode position from that
point on, permanently - the pad has no integrity check of its own to
catch this, so a misaligned decrypt does not fail, it silently returns
garbage.

The pad-management tool this layer shells out to already keeps a small
safety copy of the last ciphertext it produced for each contact,
recoverable without spending any key: `otp --recover-last <contact>
--sent` re-streams those exact bytes, byte for byte, repeatably. Recovery
means replaying that copy, never re-encrypting the original message
fresh.

This is retried automatically every time a direct link to that contact
transitions to genuinely reachable again (not on a timer, not polled) -
covering a reconnect, a link flap, or this app's own restart once the
link comes back up:

```
 alice restarts, reconnects to bob                            bob
   |    (link becomes Active again)
   |--- OtpEnvelope { seq: 4, envelope } ----------------------->|   the same seq as the
   |                                                              |   original, un-acked send
   |<-- OtpDeliveryAck { seq: 4 } ---------------------------------|
```

A file or voice content resend works the same way, just carrying a fresh
offer (a new `stream_id`, a new outer transport key, since the original
one existed only for the lifetime of the connection that made it) around
the *same already-encrypted* recovered bytes - `otp --encrypt` never runs
a second time for that content either.

**Why a resend can never be treated as automatically safe on the
receiving side.** The peer may have already decrypted the original
message successfully - only the acknowledgement travelling back to the
sender was lost, not the message itself. Resending must not then cause a
second, genuine decrypt of content the pad has already been spent on:
`otp --decrypt` has no way to recognize its own input as a duplicate, so
handing it the same ciphertext twice consumes a second range of key and
returns garbage the second time, exactly the corruption this whole layer
exists to prevent. The receiving side's own per-contact sequence counter
(§16.2) is therefore checked *before* `otp --decrypt` is ever invoked, not
after - a resend of a sequence already accepted is rejected outright,
never reaching the pad a second time. This makes a resend of an
already-delivered message a harmless, silent no-op on the receiving end,
not a failure.

A recovery attempt that finds nothing to recover, or that fails for any
reason, leaves the gate exactly as it was - it never falls back to
building a fresh message, and the same check runs again on the next
reconnect.

### 16.5 Live key-metadata header

While a mutual-consent session is active with a DM's peer (§16.1's
"started" moment), a 1-line header renders above that room's message log:

```
OTP SESSION with bob - Receive Key (dec): 5 500 1.91MB - Send Key (enc): 3 300 1.91MB
```

`OTP SESSION` is highlighted, `with <nickname>` is yellow, and each
direction's `<Seq> <Offset> <remaining>MB` triple follows the pad's own
terms: `Seq` is that direction's message count, `Offset` is how many bytes
of that direction's pad have been consumed, and `remaining` is what is
left, in megabytes. `Seq`/`Offset` are always grey; `remaining` is green at
or above 0.5MB and red below it, so a pad running low is visible before it
actually runs out.

This is purely local display, not a wire message - nothing here is sent to
or read from the peer. The three figures come from `otp --show-contact
<contact>`, the one `otp` command that reports each direction's pad
offset (`--status --porcelain`, §16's other read path, does not carry it).
`--show-contact` has no porcelain mode and its exit code cannot be used to
detect a missing contact (verified directly against the installed binary:
it still exits `0`, with the error on stderr) - unlike `--status`, so this
one read is parsed from the command's ordinary `Label: value` output
instead, checking for a leading `Contact:` line rather than trusting the
exit code.

The header's figures are fetched once immediately when a session starts, on
both the initiator's and the accepter's side, and again the instant this
contact's pad is actually spent in either direction from then on - every
genuine send and receive (text, a file's offer or content phase, voice)
re-fetches right after its own `otp --encrypt`/`--decrypt` succeeds, so the
figures change the moment the action that changed them completes rather
than waiting on a timer. A roughly-once-a-second refresh runs alongside
this, for whichever peer's room stays the one open, as a safety net for
anything that isn't this app's own send/receive (e.g. the same keychain
used with `otp` directly, out of band) - never for a room that isn't
currently on screen, so an idle session elsewhere in the app costs nothing
beyond its own occasional safety-net fetch.

## 17. OTP mail: asynchronous, server-stored delivery

Everything before this section is *live*: both parties connected, content
over a direct link, the server carrying none of it. OTP mail is the one
asynchronous path - a whole mail (subject line, body text, voice
recordings, file attachments), sealed under the same per-contact one-time
pad §16 established, handed to the **server** to hold until the recipient
next connects. It is the single deliberate exception to "content never
touches the server", and the exception is as narrow as it can be made:
what the server stores is one opaque pad-sealed blob plus the routing
metadata to hand it over (§10), on disk, deleted the moment the recipient
acknowledges decrypting it.

Nothing about §7's live messaging, §13, or §16's live pad layer changes.
A mail is not a fallback the live path degrades to - it is only ever
composed deliberately, in its own full-screen view, and confirmed
explicitly before anything is encrypted or sent.

### 17.1 Composing: what a mail is, and who can be written to

A mail's fields: `from` (the sender's nickname - on the wire the server
substitutes its own registered record of it, never trusting the claim),
`to` (a recipient nickname), `SendAtInUTC` (unix seconds at the moment the
send was confirmed), `subtext` (a subject line), `content` (body text),
zero or more voice recordings (complete PCM16 clips, the same shape a
finished live voice message holds), and zero or more file attachments
(name plus bytes, carried *inside* the sealed blob - unlike a live
transfer there is no separate streamed phase).

Two preconditions decide whether a recipient nickname is writable at all,
checked live as the field is typed:

1. **A pinned user with that nickname** (§12) whose pinned key is a
   `pq_hybrid` bundle - the pin is what the mail's addressing and
   verification anchor to, not the nickname string.
2. **An `otp` keychain contact for the pair** (the same
   fingerprint-derived contact name §16 uses), whose encryption key has
   **more bytes remaining than the whole encoded mail**. The compose view
   shows the remaining key (in MB) and re-derives it continuously as text
   is typed and recordings/attachments are added or removed; an
   attachment that would not fit the remaining key is refused at the
   moment of attaching, and the send path re-measures the real encoded
   size before any pad is spent.

There is no key-material negotiation here: if no pad exists for the pair,
the answer is §16.1's provisioning flow, not anything mail-specific.

### 17.2 Uploading: the mail's pad spend, and the storage acknowledgement

The payload is bincode-encoded, then signed with the sender's durable
identity (ML-DSA-87 + RSA-4096 over a mail-specific domain tag) and the
`(payload, signature)` pair sealed through `otp --encrypt` for the
contact. The signature exists because a one-time pad is perfectly
confidential but **malleable** - it authenticates nothing - and this blob,
unlike a §16 send, does not have a signed `pq_hybrid` envelope inside it.
Without the signature, whoever stores the blob could flip payload bits
undetected; with it, the receiver verifies the decrypted payload against
the sender's *pinned* bundle before believing a byte of it.

The upload:

```
 sender                                                       server
   |--- OtpMailSend { mail_id, to, contact_name, seq,             |
   |                  sent_at_utc, ciphertext } ----------------->|  stores pending/<mail_id>
   |<-- OtpMailResult { mail_id, ok, reason } --------------------|  on disk
```

- `mail_id` is sender-generated (16 random bytes, lowercase hex) so a
  retry carries the same id and the server deduplicates instead of
  storing twice. Both sides validate its exact shape before ever building
  a filesystem path from it.
- `seq` is the contact's **same** §16.2 send counter - a mail spends the
  same sequential pad as a live send, see §17.4.
- The mail spend passes through the same stop-and-wait gate as every
  other spend for that contact. What acknowledges it is
  `OtpMailResult { ok: true }` - durable storage on the server - rather
  than a peer's `OtpDeliveryAck`. Until that arrives, nothing else may
  encrypt for this contact.

That gate is what makes the retry rule sound: if `OtpMailResult` never
arrives (connection lost, client crashed), the `otp` CLI's `.last_sent`
safety copy still holds **exactly this mail's ciphertext**, because
nothing newer could have been encrypted. On its next connect the client
re-uploads any mail still awaiting acknowledgement with `otp
--recover-last <contact> --sent`'s replayed bytes - byte-identical, the
same `mail_id`, never a fresh encode or a second pad spend. A retried id
whose mail was meanwhile delivered and deleted is answered with
`OtpMailDelivered` instead of a second store.

`OtpMailResult { ok: false }` is exceptional (malformed id, ciphertext
over the size cap, a server disk failure) and terminal: the pad bytes the
mail consumed are destroyed either way, so the client reports it as a
hard failure naming the consequence (the contact's two pad halves are now
out of step - one range spent on the sending side that the receiving side
will never consume - and need re-keying via §16.1) rather than retrying
into the same wall. An honest client validates everything the server
would reject *before* encrypting, so this answer is never part of normal
operation.

### 17.3 Delivery: fetch, decrypt, acknowledge, notify

On every connect, a client with a local OTP keychain sends one
`OtpMailFetch` right after identifying. The server answers with both
halves of what that nickname is owed:

```
 recipient                                                    server
   |--- OtpMailFetch --------------------------------------------->|
   |<-- OtpMailDeliver { mail_id, from, contact_name, seq, ... } --|  one per pending mail,
   |<-- OtpMailDeliver { ... } ------------------------------------|  per-sender seq order
   |--- OtpMailAck { mail_id } ------------------------------------>|  deletes pending/<id>,
   |                                                                |  records delivered/<id>

 sender (later, or immediately if connected)
   |<-- OtpMailDelivered { mail_id } -------------------------------|
   |--- OtpMailDeliveredAck { mail_id } --------------------------->|  forgets delivered/<id>
```

If the recipient happens to be connected when `OtpMailSend` arrives, the
server pushes the `OtpMailDeliver` immediately as well - the fetch is the
guarantee, not the only path. Mails from one sender are always delivered
in ascending `seq` order; the pad is sequential, so no other order can
decrypt.

The receiving side runs a strict, layered check **before** `otp
--decrypt` ever touches the keychain - the pad-corruption rules of §16.4
apply with full force here:

1. **Dedupe**: an id already stored locally just re-acknowledges (its
   earlier ack was lost).
2. **Contact derivation from the pin**: the receiver derives the expected
   contact name from its *own pinned key* for the claimed `from`
   nickname. If that doesn't reproduce the mail's carried `contact_name`,
   the mail was sealed under some other identity's pad and is left on the
   server un-acknowledged and untouched - decrypting it against the local
   contact would consume the wrong pad range and corrupt the contact.
   The same holds when `from` isn't pinned at all: the mail waits until
   the identity question is resolved, exactly as §12 holds live traffic.
3. **The sequence guard**: only the exact next expected `seq` for the
   contact may reach the pad. A lower one re-acknowledges (already
   consumed); a higher one waits - an earlier spend is still in flight
   (§17.4).

Only then does the one genuine `otp --decrypt` run. The recovered
`(payload, signature)` is verified against the pinned bundle, and the
payload's own sealed `from`/`to` must match the server's claimed routing -
a mismatch on any of these discards the mail (with an acknowledgement:
the pad range is consumed and redelivery of the same ciphertext can never
work again, so leaving it pending would only wedge the contact).

**Storage on the receiving side.** The decrypted payload is immediately
re-encrypted under a locally generated one-time pad of its own length and
stored as that (ciphertext, pad) file pair - never as plaintext at rest.
The keychain pad that carried it is physically destroyed by the decrypt
(that is the `otp` tool's contract), so this local re-pad is what makes
the mail re-readable at all: each read XORs the two files together in
memory only. Removing a mail securely destroys both files, after which
its content is unrecoverable anywhere. Only once that pair is durably
written does `OtpMailAck` go back - the server deletes its stored copy
and records a delivery receipt for the sender, re-notified on every
future fetch until the sender's `OtpMailDeliveredAck` confirms it was
seen.

### 17.4 One pad, two transports: ordering across mail and live sends

A mail and a live §16 send to the same contact spend the **same**
sequential pad, and the receiving side may only ever consume them in
spend order - but they travel different transports at different speeds,
so one interleaving needs naming. The sender's gate clears on the
*server's* storage acknowledgement, not the recipient's decrypt: a live
send can therefore be encrypted (spend N+1) and reach the recipient over
the direct link *before* the mail (spend N) has been fetched from the
server. The recipient's §16.2 sequence guard rejects the early arrival
without touching the pad, exactly as designed - and the moment the mail
is fetched, decrypted, and acknowledged, the server's `OtpMailDelivered`
tells the sender the recipient's counter has advanced, which triggers the
sender's normal §16.4 recovery scan: the refused live send is replayed
from its kept ciphertext and now lands in order. No fresh pad is spent
anywhere in that resolution, and neither message is lost.
