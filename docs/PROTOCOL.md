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
  - [1.4 Optional TLS](#14-optional-tls)
- [2. Serialization](#2-serialization)
- [3. Domain types](#3-domain-types)
- [4. Connection lifecycle](#4-connection-lifecycle)
  - [4.1 Liveness: `Heartbeat`](#41-liveness-heartbeat)
  - [4.2 Coming back: reconnecting](#42-coming-back-reconnecting)
- [5. Authentication](#5-authentication)
  - [5.1 Logging in](#51-logging-in)
  - [5.2 Activation](#52-activation)
  - [5.3 Registration](#53-registration)
  - [5.4 Identify / nicknames](#54-identify-nicknames)
  - [5.5 Superadmin account status](#55-superadmin-account-status)
- [6. Channels](#6-channels)
  - [6.1 `JoinChannel { name, kind, password }`](#61-joinchannel-name-kind-password)
  - [6.2 `LeaveChannel { name }`](#62-leavechannel-name)
  - [6.3 `ChannelList { channels, superadmins }` / `ChannelCreated { channel }`](#63-channellist-channels-superadmins-channelcreated-channel)
  - [6.4 `UserOffline { user_id }` - full disconnect](#64-useroffline-user_id---full-disconnect)
  - [6.5 Password-protected private channels](#65-password-protected-private-channels)
  - [6.6 Brute-force protection](#66-brute-force-protection)
  - [6.7 Ownership and moderation](#67-ownership-and-moderation)
  - [6.8 Inactivity](#68-inactivity)
- [7. Messaging](#7-messaging)
  - [7.1 Direct peer-to-peer transport](#71-direct-peer-to-peer-transport)
    - [7.1.1 Reliable delivery over the punched link](#711-reliable-delivery-over-the-punched-link)
    - [7.1.2 Trust boundary: responding only within a shared channel](#712-trust-boundary-responding-only-within-a-shared-channel)
    - [7.1.3 Tearing down a link once it no longer serves a purpose](#713-tearing-down-a-link-once-it-no-longer-serves-a-purpose)
    - [7.1.4 Showing which peers are actually reachable](#714-showing-which-peers-are-actually-reachable)
    - [7.1.5 Punching with no server at all](#715-punching-with-no-server-at-all)
  - [7.2 Sending a channel or direct text message](#72-sending-a-channel-or-direct-text-message)
    - [7.2.1 Delivery acknowledgment](#721-delivery-acknowledgment)
  - [7.3 Voice streaming](#73-voice-streaming)
  - [7.4 `Error { message: String }`](#74-error-message-string)
  - [7.5 `RotateKey` / `KeyRotated` - per-peer key rotation relay](#75-rotatekey-keyrotated---per-peer-key-rotation-relay)
  - [7.6 File transfer](#76-file-transfer)
  - [7.7 Live voice calls](#77-live-voice-calls)
- [8. Encryption model](#8-encryption-model)
  - [8.1 RSA-OAEP chunking](#81-rsa-oaep-chunking)
  - [8.2 RSA signatures](#82-rsa-signatures)
- [9. Versioning and compatibility](#9-versioning-and-compatibility)
- [10. What the server never sees](#10-what-the-server-never-sees)
- [11. Rotating a peer's key during a session](#11-rotating-a-peers-key-during-a-session)
  - [11.1 Queueing while waiting for a fresh key](#111-queueing-while-waiting-for-a-fresh-key)
  - [11.2 Voice streams count as one message](#112-voice-streams-count-as-one-message)
- [12. Client-side identity pinning (`id_store`)](#12-client-side-identity-pinning-id_store)
  - [12.1 The gap this closes](#121-the-gap-this-closes)
  - [12.2 What gets pinned, and what doesn't](#122-what-gets-pinned-and-what-doesnt)
  - [12.3 When the check happens](#123-when-the-check-happens)
  - [12.4 What happens on a mismatch, and how a device is resolved](#124-what-happens-on-a-mismatch-and-how-a-device-is-resolved)
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
- [14. The two encryption layers, side by side](#14-the-two-encryption-layers-side-by-side)
- [15. Sequences](#15-sequences)
- [16. One-time-pad layer over `pq_hybrid`](#16-one-time-pad-layer-over-pq_hybrid)
  - [16.1 Turning it on, only once both sides explicitly agree](#161-turning-it-on-only-once-both-sides-explicitly-agree)
  - [16.1.1 A second, independent key for OTP mail: `/new-otp-mail-key`](#1611-a-second-independent-key-for-otp-mail-new-otp-mail-key)
  - [16.1.2 Device-qualified naming (`PqWrapped` only)](#1612-device-qualified-naming-pqwrapped-only)
  - [16.2 Sending under the pad](#162-sending-under-the-pad)
    - [16.2.1 One conversation end to end: every spend, its acknowledgement, and its retries](#1621-one-conversation-end-to-end-every-spend-its-acknowledgement-and-its-retries)
    - [16.2.2 A `Direct` pair's device claim: cleartext metadata, checked before the pad is touched](#1622-a-direct-pairs-device-claim-cleartext-metadata-checked-before-the-pad-is-touched)
  - [16.3 Session visibility in the DM log](#163-session-visibility-in-the-dm-log)
  - [16.4 Recovering a send whose ciphertext already left](#164-recovering-a-send-whose-ciphertext-already-left)
  - [16.5 Live key-metadata header](#165-live-key-metadata-header)
  - [16.6 Ending a session: /endotp](#166-ending-a-session-endotp)
  - [16.7 A session ends on both sides once its key is fully spent](#167-a-session-ends-on-both-sides-once-its-key-is-fully-spent)
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
| `Auth` | Logs in with a nickname and its password (§5.1) |
| `Activate` | Answers a pending account's emailed activation code (§5.2) |
| `Register` | Creates an account, if this server takes registrations (§5.3) |
| `Identify` | Claims the logged-in nickname, announcing a public key and method (§5.4) |
| `ChangePassword` | Changes the sender's own password, re-checking the old one (§5.1) |
| `JoinChannel` | Joins or implicitly creates a channel (§6.1) |
| `LeaveChannel` | Leaves one channel (§6.2) |
| `DeleteChannel` | The channel admin deletes a public channel (§6.7) |
| `BanFromChannel` | The channel admin bans a nickname from a channel (§6.7) |
| `UnbanFromChannel` | The channel admin reverses a ban (§6.7) |
| `SetChannelJoinLock` | The channel admin locks or unlocks who may join (§6.7) |
| `AssignChannelAdmin` | The channel admin hands off admin to a member (§6.7) |
| `RotateKey` | Offers a peer fresh key material (§7.5, §11, §13.10) |
| `RequestPeerLink` | Asks the server to pass candidates to a peer (§7.1) |
| `Heartbeat` | Proves the connection is still alive (§4.1) |
| `OtpMailSend` | Uploads one pad-sealed mail for an offline recipient (§17.2) |
| `OtpMailFetch` | Asks for pending mail and delivery receipts (§17.3) |
| `OtpMailAck` | Recipient confirms a delivered mail was decrypted and stored (§17.3) |
| `OtpMailDeliveredAck` | Sender confirms a delivery receipt was seen (§17.3) |
| `AdminDeactivate` | A superadmin locks an account out, with a reason (§5.5) |
| `AdminActivate` | A superadmin clears whatever blocks an account's login (§5.5) |
| `AdminRemoveAccount` | A superadmin removes an account and what it administers (§5.5) |
| `AdminRemoveChannel` | A superadmin removes any public channel (§5.5) |
| `RequestUsersList` | A superadmin asks for every registered user and what they administer (§5.5) |

| Server → client | Purpose |
|---|---|
| `Hello` | Whether this server takes registrations, and the control-channel offer (§1.3, §4) |
| `AuthResult` | Whether login succeeded, or is waiting on activation (§5.1, §5.2) |
| `RegisterResult` | Whether `Register` created an account (§5.3) |
| `IdentifyResult` | Whether the nickname was granted, and this client's `UserId` (§5.4) |
| `ChangePasswordResult` | Whether `ChangePassword` succeeded (§5.1) |
| `UsersList` | Answers `RequestUsersList`: every registered user and what they administer (§5.5) |
| `ChannelList` | The public channels and every current superadmin nickname, once, after identifying (§6.3, §5.5) |
| `Joined` | Confirms a join, last in the join snapshot (§6.1) |
| `ChannelJoinFailed` | A join failed for a non-password reason (§6.1) |
| `ChannelJoinRejected` | A join needs a password, guessed wrong, is IP-banned, is nickname-banned, or the channel is locked (§6.5, §6.6, §6.7) |
| `ChannelCreated` | A new public channel now exists (§6.3) |
| `UserJoined` | A peer is in a shared channel — carries their key (§6.1) |
| `UserLeft` | A peer left one channel (§6.2) |
| `UserOffline` | A peer's connection ended entirely (§6.4) |
| `ChannelRemoved` | The admin deleted a channel, or a superadmin removed it (§6.7, §5.5) |
| `UserBanned` | The admin banned a nickname from a channel (§6.7) |
| `UserUnbanned` | The admin reversed a ban (§6.7) |
| `ChannelJoinLockUpdated` | The admin locked or unlocked who may join (§6.7) |
| `ChannelAdminChanged` | A channel's admin changed (§6.7) |
| `KeyRotated` | A peer's relayed key rotation (§7.5, §11, §13.10) |
| `PeerCandidates` | A peer's relayed addresses, to punch against (§7.1) |
| `Error` | A soft, recoverable failure; the connection stays open (§7.4) |
| `OtpMailResult` | Whether an uploaded mail is durably stored (§17.2) |
| `OtpMailDeliver` | One stored mail, handed to its recipient (§17.3) |
| `OtpMailDelivered` | A sent mail was genuinely decrypted by its recipient (§17.3) |
| `AccountDeactivated` | A superadmin just deactivated this currently-connected account (§5.5) |

**Peer connection** — UDP, punched. Two layers: the datagram itself, and
the payload carried inside a reliable or unreliable one.

| Punch datagram | Purpose |
|---|---|
| `Ping` / `Pong` | Opens and confirms the NAT mapping (§7.1) |
| `DirectPing` / `DirectPong` | The same, for a link no server arranged - names the sender, since nothing relayed an identity (§7.1.5) |
| `Keepalive` | Stops an idle mapping expiring (§7.1) |
| `Reliable` / `Ack` | The retransmitting layer text and files ride on (§7.1.1) |
| `Unreliable` | Voice chunks, which are not worth retransmitting (§7.3) |

| Peer payload | Carried | Purpose |
|---|---|---|
| `Envelope` | reliably | One text message, channel or direct (§7.2) |
| `DeliveryReceipt` | reliably | Says a named message was decrypted here, and later that it was saved or played (§7.2.1) |
| `FileOffer` | reliably | Offers a file; nothing is sent until accepted (§7.6) |
| `FileAccept` / `FileReject` | reliably | The recipient's decision (§7.6) |
| `FileChunk` / `FileEnd` | reliably | The file itself, once accepted (§7.6) |
| `StreamStart` / `StreamEnd` | reliably | Brackets one voice recording (§7.3) |
| `StreamKeySetup` | reliably | A `pq_hybrid` stream's key setup, sent once (§13.3) |
| *(voice chunks)* | unreliably | The audio, as `Unreliable` datagrams (§7.3) |
| `OtpEnvelope` / `OtpFileOffer` | reliably | A `pq_hybrid` send additionally wrapped by the one-time-pad layer (§16) |
| `OtpFileContentSeq` | reliably | Names an accepted file's content-phase pad slot, independent of the offer's own (§16.2) |
| `OtpVoiceOffer` | reliably | Offers a fully-recorded voice message under the pad layer - auto-accepted, no popup (§16.2) |
| `OtpDeliveryAck` | reliably | Confirms an `OtpEnvelope`/`OtpFileOffer`/`OtpVoiceOffer` decoded, carrying proof of the nonce under its pad, unblocking the next one (§16) |
| `OtpPadStart` | reliably | Announces an incoming one-time pad: its length and the digests both sides will be held to (§16.1) |
| `OtpPadChunk` / `OtpPadEnd` | reliably | The pad's bytes, streamed small enough never to fragment, then the end of it (§16.1) |
| `OtpPadCancel` | reliably | Either side abandoned an in-progress pad transfer - the other stops waiting and erases what it staged (§16.1) |
| `OtpPadVerify` | reliably | What the receiver actually reassembled, and whether it was accepted - installs nothing (§16.1) |
| `OtpPadCommit` / `OtpPadCommitAck` | reliably | Both sides' digests matched: the sender has installed, the receiver may too, and confirms it has (§16.1) |
| `DeviceIdAnnounce` | reliably | This side's device id, sealed like any other content - sent automatically once `Active` (§12.7) |
| `ChannelPresence` | reliably | This side's joined channels, sealed - what turns a serverless punched path into a peer in shared channels (§7.1.5) |
| `KeyRotation` | reliably | A signed encryption-key rotation, carried on the link instead of relayed - what keeps forward secrecy working with no server in reach (§13.10, §7.1.5) |
| `CallInvite` | reliably | Proposes a live voice call (§7.7) |
| `CallAccept` | reliably | Joins a call, or replies to a newly-discovered participant - the mesh's only signal (§7.7) |
| `CallReject` | reliably | Declines an invite, sent only to whoever sent it (§7.7) |
| `CallEnd` | reliably | Leaves a call still in progress (§7.7); from the host, ends it for everyone |
| `CallMute` | reliably | Someone's microphone went off or back on: the host silencing (or restoring) one participant, or a participant reporting its own mute (§7.7) |
| `CallRoster` | reliably | Hands a late-joining participant the sender's own roster (§7.7) |

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
   |<-- Hello { registration_open,          |   (in the clear)
   |            control: ControlOffer } ----|
   |                                        |
   |--- SecureChannel(ControlAccept) ------>|   (in the clear)
   |                                        |
   |=== everything after this is sealed ====|
```

```
ControlOffer  { encap: PqEncapKeys }
ControlAccept { kem_ciphertext: bytes, wrapped_key: bytes[32],
                eph_x25519_pub: bytes[32] }
```

**Why.** Message content never touches the server at all (§7.1, §10), but
the conversation that sets a session up always travelled as plain TCP - and
it carries a login's nickname and password in the clear (§5.1), which
channels exist, who is in them, and the timing of every key rotation.
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
and reads everything. Nothing at this layer provides that: the offer
carries no signature, and a client accepts it as-is regardless of who
signed what. The channel is **encrypted but not authenticated** - it
defeats a passive observer, not an active man in the middle - and that is
a real limit, stated as one rather than implied away. A deployment that
needs the server authenticated runs the whole connection over TLS instead
(§1.4), whose certificate is checked before a single control-channel frame
crosses the wire.

Because the offer is per connection and thrown away with it, recording a
session and later gaining any long-term key this server holds - a TLS
private key included - still does not decrypt it.

### 1.4 Optional TLS

`server_ssl=on` in `~/.aloo/settings` serves the control connection under a
certificate pair named by `server_ssl_fullchain`/`server_ssl_privkey` - a
Let's Encrypt pair,
typically. A client opts in with `connect_using_ssl` in its own
`~/.aloo/settings` - the one setting for this, shared identically by a
normal (interactive) connect and a daemon start, with no popup field and
no CLI flag able to override it - trusting the public roots it ships with
plus, optionally, one PEM file of extra roots (`connect_ssl_ca`) for a
self-signed or privately issued certificate. The certificate is checked
against the host the user typed, standard TLS server-name verification.

This is the identity §1.3's own offer cannot provide, layered underneath
everything else unchanged: the control channel's own sealing (its
post-quantum key transport) still runs on top of TLS exactly as it runs on
top of plain TCP, so TLS here is what authenticates the server, not what
keeps the conversation confidential. A certificate that does not load, or
does not match its key, refuses the server's startup outright rather than
falling back to plaintext.

When a connect attempt fails for a reason that isn't already meaningful on
its own (not a wrong password, a taken nickname, a deactivated account, or
a pending activation code), the client makes one bounded, diagnostic-only
attempt at the same address with the opposite of `connect_using_ssl` -
never to actually connect that way, only to tell a genuine transport-mode
mismatch apart from every other kind of failure. If that attempt reaches a
real `Hello`, the error is enriched with a specific reason ("this server
appears to require SSL" / "...appears to reject SSL") instead of a bare,
unexplained failure - shown in red on the connect form, or failing a
daemon start outright with the same reason. The real session that
follows, if any, always uses exactly what `connect_using_ssl` says -
never the probed alternative; this never auto-negotiates or silently
degrades.

An automatic reconnect (§4.2) that hits the same kind of mismatch - the
operator flips `server_ssl`, or a client's own setting disagrees with a
server it is reconnecting to mid-session - is bounded and diagnosed the
same way, not left to hang: without this, the supervisor task parks on
that one attempt forever, with no further retries and nothing shown.

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
*nickname*, claimed by `Auth` and checked against the users registry
(§5.1), which **is** freed for reuse as soon as its holder disconnects
(§5.4) - two different clients can be assigned the same nickname over
time, but never the same live `UserId`.

```
UserInfo {
    id:             UserId
    name:           string
    public_key_der: bytes     // see below
    key_mode:       KeyMode
}
```

`public_key_der` carries a client's bincode-encoded `pq_hybrid` key
bundle (§13) - an identity is a bundle rather than one key, and it rides
this field rather than growing the wire shape. The bundle carries only
bootstrap encryption keys; the keys that supersede them as the
relationship rotates are never reflected here, only relayed via
`KeyRotated` (§7.5, §13.10).

```
KeyMode = PqHybrid
```

`KeyMode` names how a client's own `my_key` was obtained. There is one
value: `pq_hybrid`, a keybundle loaded from a file (§13). Peer-to-peer
traffic is therefore always the hybrid scheme in §13, optionally wrapped
in a one-time pad (§16). The field stays on the wire so a peer
implementation still announces *which* scheme it speaks rather than
leaving it implied.

| value | `my_key` type | key material | changes? |
|---|---|---|---|
| `PqHybrid` | `pq_hybrid` | a keybundle loaded from a file (§13) | signing half no, encryption half every message (§13.10) |

The identity is "static" for protocol purposes - exactly one keybundle for
the whole session, never rotated. Only its *encryption* keys rotate, which
is what `KeyRotated` carries (§13.10); `public_key_der`/the identity
itself stays good for the whole session.

`KeyMode` is broadcast (via `Identify` → `UserInfo`) so every peer can
render the tag next to that user's name (sidebar, private-room title -
SPEC.md Functionality #3):

| `KeyMode`    | Tag           | Position (`KeyMode::format_with_name`) |
|--------------|---------------|------------------------------------------|
| `PqHybrid`   | `🛡️ PQH`      | after the name: `name 🛡️ PQH`            |

(`KeyMode::label()` returns just the tag, unbracketed; `format_with_name`
composes it with a name, tag trailing.) The tag trails the name as an
annotation on it, not a classification label sitting in front. `🛡️` reads
as the strongest tier: quantum-resistant signing *and* key exchange, each
additionally hedged with RSA-4096.

```
ChannelKind = Public | Private

ChannelInfo { name: string, kind: ChannelKind }
```
`Public` channels are advertised to every client via `ChannelList` (§6.3);
`Private` channels are never advertised - a client must already know the
exact name to join one.

There is one way to authenticate: a nickname and its password, checked
against the server's users registry (§5.1). `AuthKind`/`AuthResponse` -
three interchangeable credential modes negotiated per `Hello` - no longer
exist; every server checks the same way.

```
Envelope {
    content: Content        // Text | FileOffer
    blocks:  list<bytes>    // exactly one element: a sealed send
                            // (§13.3) - or, under the OTP layer's
                            // Direct framing, the plaintext (§16.2)
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
   |<-- Hello { registration_open } ---------|
   |                                         |
   |--- Auth { nickname, password } -------->|
   |                                         |
   |<-- AuthResult { ok, .. } ---------------|
   |        (ok == false => connection closed by server, unless
   |         activation_pending - see §5.1, §5.2)
   |                                         |
   |--- Identify { public_key_der,           |
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
- The client's next message **must** be `Auth` or `Register`; any other
  message (or a clean disconnect) at this point causes the server to
  send `AuthResult { ok: false, reason: Some("expected auth message") }`
  and close the connection. `Register` is answered with
  `RegisterResult` and the connection closes either way (§5.3) - it is
  never followed by `Identify` on the same connection.
- On successful auth (activation included, where it applies), the
  client's next message **must** be `Identify`; otherwise the server
  sends `Error { message: "expected identify message" }` and closes the
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

### 4.2 Coming back: reconnecting

§4.1 is the server's side of a connection that dies without closing. This
is the client's.

Content is peer-to-peer (§7.1, §10), so a client whose control connection
drops keeps talking to every peer it already has a direct link to - those
links carry their own keepalives and re-punch themselves (§7.1.4), and
never notice the server is gone. Presence is the opposite: the nickname is
freed, peers are told `UserOffline` (§6.4), and anyone connecting
afterwards is never told this client exists. Left there, a client is
reachable but invisible - its messages arrive, and it is in nobody's member
list.

A client therefore reconnects, and keeps reconnecting:

- The first attempt is made as soon as the loss is noticed. Each failure
  doubles the wait before the next attempt, from 5s up to a ceiling of 30s.
  There is no attempt limit and no giving up: from the client's side a
  server that is down, restarting, unreachable, or simply on the other end
  of a network that is off are indistinguishable, and every one of them
  ends with the server answering again.
- A rejected nickname (§5.4) is retried like any other failure rather than
  treated as fatal. The connection that still holds the name is usually
  this client's own previous one, which the server frees within
  `HEARTBEAT_TIMEOUT` of it going quiet.
- The reconnected client is a **new** client in every way the server cares
  about: a fresh connection, a fresh `UserId` (§3), and no channel
  membership. It re-sends `JoinChannel` for each channel it was in, which
  is what puts it back in the member lists other clients - including
  clients that connected during the gap - are shown.
- Because the `UserId` it was known by is gone, everything the previous
  connection said about *other* clients is dropped on reconnect too: those
  ids were that connection's to hand out. Whoever is still there is
  re-announced in the membership snapshot the re-joins bring back (§6.1).
- Nothing about this is negotiated, and the server implements no part of
  it. A reconnect is an ordinary connection (§4), indistinguishable from a
  first one.


## 5. Authentication

There is one way in: `Auth { nickname, password }`, checked against the
server's users registry (`crate::server::users_registry`) - accounts on
disk under `~/.aloo/users/<nickname>/`, each a PBKDF2-derived key, an
optional email, and, while unactivated, a pending code. A server that
also takes registrations (§5.3) answers `Register` instead; either way
the connection closes once its one exchange is settled.

### 5.1 Logging in

```
Auth { nickname: string, password: string }
```

The server derives a candidate key from `nickname` and `password`
(`PBKDF2-HMAC-SHA256`, salted with the nickname) whether or not an
account by that name exists, and compares it in constant time against the
registered key - so a login attempt against an unregistered nickname
costs the same work, and gets the same `AuthResult { ok: false,
activation_pending: false }`, as one against a real, wrong password: a
login cannot be used to discover which nicknames exist. A correct
nickname and password on an activated account answers `AuthResult { ok:
true, activation_pending: false, reason: None }`, and the client's next
message must be `Identify` (§5.4). One still awaiting activation answers
`ok: false, activation_pending: true` instead - see §5.2.

Seven wrong-password (or unknown-nickname - the same one answer either
way) attempts from one source address within 24h refuse every further
login from that address, with a distinctly-worded reason, for the next
24h - checked before the slow key derivation runs, so a banned address
cannot burn server work either.

**Changing your own password.** Once fully connected (past `Identify`,
§5.4), either side of the pair can be rotated:

```
ChangePassword { old_password: string, new_password: string }
ChangePasswordResult { ok: bool, reason: string? }
```

`old_password` is re-derived and compared exactly like `Auth` would - the
connection having once authenticated is not itself trusted as ongoing
proof of the current password, since it may have been changed by another
session since. A wrong `old_password`, or an empty `new_password`,
answers `ok: false` with a reason and changes nothing; success answers
`ok: true`. Unlike `AuthResult { ok: false }`, the connection is never
closed either way - this is an ordinary authenticated request, not part
of the handshake.

### 5.2 Activation

An account created by `Register` (§5.3) is not usable until its emailed
code is given back, one way or another:

- **In the client.** A login whose credentials are right but whose
  account is `activation_pending` may send exactly one `Activate {
  code }` in reply, answered with another `AuthResult`. The right code
  continues the handshake into `Identify`; a wrong one refuses and the
  server closes the connection. A code more than `ACTIVATION_VALIDITY_SECS`
  (one hour) past the account's registration time is expired - rather
  than an outright refusal, the server first tries to reissue a fresh
  code and email it to the same address on file, exactly as registering
  the same nickname again already does (§5.3); this succeeds whenever
  there is an SMTP relay configured and an email on file to send to (a
  `register_manual` account, with no email at all, never has a pending
  activation to reissue in the first place), in which case the login
  attempt proceeds into the same "send `Activate`" exchange as an
  unexpired pending activation, now against the fresh code. Only when a
  fresh code cannot be sent does the connection close on the unchanged
  expiry refusal, the account still needing a fresh `Register` to recover.
  The client's own activation popup reaches this path two ways: opened
  automatically the instant `Register` succeeds ("Enter the activation
  code you received by email"), or opened on a later `Connect` attempt
  against an account still `activation_pending` ("`<nickname>` is
  registered but not activated yet..."). Either way it is the same
  popup, retrying the same `Activate` exchange until it succeeds or the
  user cancels.
Five wrong codes in a row against one still-pending account remove the
account outright, rather than leaving it open to indefinite guessing - the
popup itself retries with no limit of its own, so this is what actually
bounds it. That fifth answer names the removal specifically, distinct from
an ordinary wrong-code refusal, so the popup surfaces it as a plain
refusal (the nickname is free to register again) instead of asking for
still another code that can never work.

Activating an account is nothing more than deleting the pending code file
- there is no separate "activated" flag to fall out of sync with it.

### 5.3 Registration

```
Register { nickname: string, password: string, email: string }
```

Only answered when the server was started with `server_allow_registration
=on`; otherwise (or with no SMTP relay configured to send the code
through) it is refused - `RegisterResult { ok: false, reason: Some(...) }`
- and no account is created. On success the server writes the account
with a pending activation and emails a fresh code to `email`, answering
`RegisterResult { ok: true, reason: None }`; the account cannot log in
until that code comes back (§5.2). Registering a nickname whose previous
registration is still within its activation window is refused outright;
one whose window has expired may be registered again from scratch. `email`
must not already belong to a different registered nickname (active or
still pending) - one address cannot back two separate accounts; it frees
up again once the account holding it is removed. More than three
registration attempts from one source address within two days refuse that
one and every further attempt from the same address for the next seven
days.

This is a separate path from logging in - a client never sends `Auth`
and `Register` on the same connection - and from the server's own
`aloo --register-user`/`--change-password` (docs/SPEC.md "Server
startup"), which create or repair an account directly on the server's
own machine, with no email and no activation step at all.

### 5.4 Identify / nicknames

After a successful `Auth` (activation included, where it applies), the
client sends exactly one `Identify`:

```
Identify { public_key_der: bytes, key_mode: KeyMode }
```

There is no nickname field here any more - it was already claimed by
`Auth`. `public_key_der` carries a bincode-encoded `PqPublicBundle` (§13)
- other clients use this to encrypt messages addressed to this user
(§7.2, §8).

`key_mode` (§3) tells every peer, up front, which scheme `public_key_der`
speaks; it is always `PqHybrid`, a *bootstrap* encryption key that
individual peer relationships supersede via `KeyRotated` the first time a
message is exchanged with them (see §13.10). The server itself does not
branch on `key_mode` beyond storing and relaying it as part of `UserInfo`,
and using it to validate `RotateKey` (§7.5) - it never gates ordinary
messaging on it.

The server enforces that the logged-in nickname is not currently held by
any other connected client - matching is case-sensitive (`"dave"` and
`"Dave"` are different nicknames and may be held by two different clients
at once) - the check-and-register happens atomically under the server's
single registry lock, so two simultaneous `Identify`s for the same name
cannot both succeed. On success, the server assigns a fresh `UserId` and
responds `IdentifyResult { ok: true, you: Some(id), reason: None }`. On a
name collision, it responds `IdentifyResult { ok: false, you: None,
reason: Some(String) }` (the reason names the taken nickname) and closes
the connection immediately after - the client must reconnect (a new TCP
connection, restarting from `Hello`) to retry, which succeeds the moment
the other connection holding the name goes away. A nickname becomes
available again as soon as its holder's connection closes - cleanly (§4)
or because the server's heartbeat check decided it was dead (§4.1).

### 5.5 Superadmin account status

`server_superadmin` names zero or more nicknames (one settings-file line
each) that may send any of the five messages below. Every one of them is
checked server-side against that list on every call, regardless of
anything the client asserts about itself; a sender not on the list gets
`Error { message }` and nothing else happens. The same list, unchanged for
the server's uptime, is also sent to *every* client - superadmin or not -
as `ChannelList`'s own `superadmins` field (§6.3): folded into that
existing connect-time message rather than a second one sent right after
it, specifically so the number of messages a fresh connect delivers never
changes. A nickname's superadmin status is shown to everyone (a marker in
the sidebar and the user-info popup, `docs/SPEC.md`), not only used to
gate these five messages.

```
AdminDeactivate { nickname: string, reason: string }
AdminActivate { nickname: string }
AdminRemoveAccount { nickname: string }
AdminRemoveChannel { name: string }
RequestUsersList
```

**`RequestUsersList`, read-only.** Answered with `UsersList { users:
[{ nickname: string, admin_of: [string] }] }` - every registered
nickname, each with the public channels it currently administers (empty
for one administering none). Unlike the other four, this changes nothing
- it exists so a superadmin can see the whole registry's shape (who
exists, who administers what) without reading server-side files by hand.

**Account status is one model, reached two ways.** An account can be
blocked from logging in by either of two independent conditions: a still-
pending emailed activation code (§5.2), or a superadmin's deactivation.
`AdminDeactivate` sets the second condition, recording `reason`.
`AdminActivate` clears *both* conditions at once, whichever apply - it is
deliberately the same underlying operation ("make this account able to
log in right now") whether it is bypassing a code nobody entered yet or
reversing an earlier deactivation, which is why the two slash commands
this maps to (`/activate`/`/deactivate`) share their vocabulary with §5.2's
own activation rather than introducing separate terms.

A deactivated account's login attempt fails exactly like any other
credentials check up to the point the password is confirmed right - the
same timing-safety property §5.1's constant-time comparison already
gives an unactivated or a merely-wrong-password account - but then
answers with a dedicated signal rather than a generic refusal:

```
AuthResult { ok: false, activation_pending: false, deactivated: Some(reason), reason: None }
```

`deactivated` is its own field for the same reason `activation_pending`
already is one, rather than being folded into the free-text `reason`: a
client needs to branch on *why* without parsing English. If the account
being deactivated is currently connected, the server also pushes:

```
AccountDeactivated { reason: string }
```

There is no message that forces a connection closed - the server has no
such mechanism for anything (§4 covers the only two ways a connection
ever ends: the client closing it, or the heartbeat timeout). A client that
receives `AccountDeactivated` is expected to end its own session having
shown `reason`, the same way it would on an ordinary quit; it does not
wait for anything further from the server, since nothing further is
coming.

**`AdminRemoveAccount`** deletes the account outright (the same effect
`aloo --register-user`'s directory removal has, just reachable over the
wire) and additionally removes every channel it currently administers
(§6.7) - not reassigning them, removing them, exactly as `/delete-channel`
does, with every member of each notified via `ChannelRemoved`. If the
removed account is currently connected it is disconnected, without the
`AccountDeactivated` treatment - there is no reason to show a removed
account a specific message, since there is no account left for a
superadmin to reactivate afterward.

**`AdminRemoveChannel`** removes any channel by name, the same way
`/delete-channel` does but without requiring the sender to be its admin,
and without the public-only restriction that command has - except
`DEFAULT_CHANNEL_NAME`, which no message, superadmin or otherwise, may
remove. In practice only a public channel is ever reachable this way: a
private channel is never advertised to anyone outside its own membership
(§6.3), so a superadmin who isn't already in one has no name to send.

## 6. Channels

A channel is identified purely by its `name: String` (no separate numeric
ID) and is created implicitly by the first `JoinChannel` that references
it - there is no separate "create channel" message. The server always
seeds one channel, `DEFAULT_CHANNEL_NAME` (`"the-hall"`, `ChannelKind::
Public`), before any client connects - the one channel that survives being
emptied (§6.2).

A private channel's tab is shown prefixed with 🔒 and a space before the
name; a public one carries no icon at all, so a bare `#name` is itself
the "this one is public" signal (the channel view). There is one tab per
channel the client is a member of, and only those - the wider set of
public channels the server has announced (§6.3) is a directory the user
picks from, not a row of tabs.

### 6.1 `JoinChannel { name, kind, password }`

- `name` must pass the channel-name rule: non-empty, at most
  `CHANNEL_NAME_MAX_LEN` (30) characters, and every character an ASCII
  letter, digit, `-`, or `_`. This is enforced identically by the client (a
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
user_id }` - the leaver themselves gets no acknowledgment at all. Emptying
a channel this way does not by itself delete it - it, its admin, its ban
list and its join lock (§6.7) all survive being briefly empty, and only
`DEFAULT_CHANNEL_NAME` (`"the-hall"`) is ever exempt from being deleted at
all. What actually removes an emptied channel is either its admin's
`DeleteChannel` (§6.7), a superadmin's removal (§5.5), or the inactivity
sweep (§6.8) once configured; any of those - or simply never being
recreated - leaves the next `JoinChannel` for the same name creating it
fresh, with no memory of previous membership.

Since there's no server acknowledgment to the leaver, the client applies
`/leave` optimistically: the moment it's submitted (`UiState::
leave_channel_locally`), before the `LeaveChannel` write even reaches the
server. The channel's tab is removed either way, public or private - a tab
means "I am in this room". A public channel remains in the announced
directory (§6.3), so the `/channels` modal is where it's rejoined from; a
private one is never advertised there, and rejoining it means naming it
again (Ctrl+J). See §7.1.3 for what leaving does to any P2P links that
were only justified by that channel's membership.

### 6.3 `ChannelList { channels, superadmins }` / `ChannelCreated { channel }`

`ChannelList` is sent once, right after `IdentifyResult` (§4) -
`channels` is **public channels only**, sorted by name; `superadmins` is
every current `server_superadmin` nickname (§5.5), unrelated to channels
but carried on this same one-time message rather than a second one, so
the number of messages a fresh connect delivers stays fixed regardless of
how many superadmins are configured. `ChannelCreated { channel: ChannelInfo }`
is the live follow-up: sent to every *other* currently-connected client
the instant a genuinely new public channel is created (`Registry::
join_channel`, `!existed_before && kind == Public`), so a channel created
after the initial snapshot doesn't stay invisible to everyone who didn't
create or join it. A **private** channel creation never triggers this -
it stays unadvertised exactly as `ChannelList` already keeps it. Joining
an *already-existing* channel (public or private) never re-triggers it
either - only genuine creation does.

A client's own joins feed the same directory: `ChannelCreated` is sent to
every client *except* the creator, so joining a public channel is the only
signal the creator gets that it now exists, and the client records it (a
private channel is deliberately never recorded - it is advertised to
nobody, its author included).

Everything a client learns this way goes into its public channel
directory - the rows of the `/channels` modal, with the ones it has
already joined marked - and nothing in it is joined implicitly. Exactly
one automatic join happens per connection: `DEFAULT_CHANNEL_NAME`
("the-hall"), if the snapshot offers it and the client is not already in
a channel. Every other join is a deliberate one (`/channels`' Enter, or
Ctrl+J by name). Like every other channel-membership
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
persisted to disk - a server restart clears every ban. The users registry
itself (§5.1) is the opposite: on disk, so a restart never forgets who is
registered.

### 6.7 Ownership and moderation

Every channel other than `DEFAULT_CHANNEL_NAME` belongs to whoever
created it - public or private alike, fixed at creation exactly like
`kind`. `Joined` carries the current admin alongside the confirmation:

```
Joined { channel: ChannelInfo, admin: optional<string> }
```

`admin` is `None` only for `DEFAULT_CHANNEL_NAME`, which belongs to
nobody and is permanently exempt from every command below - each one
refuses it outright, naming "no admin" as the reason. A later change of
admin while already joined arrives instead as `ChannelAdminChanged`
(below); the directory (`ChannelList`/`ChannelCreated`, §6.3) never
carries `admin` at all, since the directory has no use for it and every
client that has actually joined already has it from `Joined`.

Five messages, all admin-only - checked server-side against the
channel's own recorded admin, never trusted from the client:

```
DeleteChannel { name: string }
BanFromChannel { channel: string, nickname: string }
UnbanFromChannel { channel: string, nickname: string }
SetChannelJoinLock { channel: string, allowed: optional<list<string>> }
AssignChannelAdmin { channel: string, nickname: string }
```

**`DeleteChannel`** removes `name` outright - only for a public channel;
a private one refuses with a reason. Every current member receives
`ChannelRemoved { name, reason }` and drops the channel. Recreating it is
nothing special: the very next `JoinChannel` for the same name creates it
fresh, exactly as it would for any other not-yet-existing name, and its
joiner becomes its new admin.

**`BanFromChannel`**/**`UnbanFromChannel`** add or remove `nickname` from
the channel's ban list. A ban force-removes the nickname from the channel
if currently a member, and refuses every future `JoinChannel` from it
against that channel with a new rejection kind:

```
ChannelJoinRejected { name: string, kind: UserBanned }
```

distinct from `Banned` (§6.6): that one is an IP-scoped brute-force
protection against password guessing; this one is a nickname-scoped
moderation decision, and the two never interact. Whether force-removed or
not, every member who was in the channel (the banned nickname included)
receives:

```
UserBanned { channel: string, user_id: UserId, nickname: string }
```

so a client can tell its own removal from an ordinary member-left notice
by comparing `user_id` to itself. `UnbanFromChannel` only reverses list
membership - it sends `UserUnbanned { channel, nickname }` to current
members and does not restore anything; the nickname simply may join
again.

**`SetChannelJoinLock`** replaces the channel's join allowlist outright:
`allowed: None` is "All users" - clears the lock entirely; `Some(list)`
restricts *future* joins to that list, plus the admin, always implicitly,
regardless of whether they're on it. It gates joining only, not
membership: a currently-joined member left off a narrower list is not
removed by applying one. A non-admin, non-listed nickname's `JoinChannel`
against a locked channel is refused as:

```
ChannelJoinRejected { name: string, kind: NotOnAllowlist }
```

Applying a lock (of either shape) notifies current members with
`ChannelJoinLockUpdated { channel, by }`, naming who changed it.

**`AssignChannelAdmin`** requires `nickname` to currently be a member of
`channel` - refused otherwise, so a channel is never handed to someone
not even present to accept it. On success the caller's own admin status
is released in the same stroke (a channel has exactly one admin at a
time) and every current member receives `ChannelAdminChanged { channel,
admin: Some(nickname) }`.

### 6.8 Inactivity

`server_channel_deletion_unactivity_period` (a settings-file duration -
`Ndays`/`Nweeks`/`Nmonths`, a month fixed at 30 days) configures a
background sweep that destroys a channel - any one but
`DEFAULT_CHANNEL_NAME`, permanently exempt - once it has **both**
currently zero members **and** no successful join within the configured
period. Unset (the default), the sweep never runs at all, and a channel
persists while empty indefinitely, the same way `DEFAULT_CHANNEL_NAME`
already does unconditionally.

Join events, not message content, are what this measures: the server
never sees anything of a channel's actual conversation (§7.1, §10), so a
join - the one thing it can observe - is the only available signal.
Membership alone isn't sufficient either: a channel with one long-standing
member who simply never rejoins must not age out from under them, so
"zero members" is a necessary condition alongside the elapsed period, not
a substitute for it. This replaces what earlier revisions of this
document described as instant deletion of an emptied channel - every
channel, admin, ban list, and join lock (§6.7) now survives being briefly
empty, which is what makes moderation state worth having in the first
place.

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
voice does not (§7.3) - a recipient
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

That minute is the transport's whole memory: it is bounded, and it dies
with the process. A client may additionally keep a *durable* queue on
disk for the content worth it - text and voice, never a file or anything
that only states something about right now (`queue_send_messages`,
`docs/SPEC.md` Functionality #34). That is entirely a local matter: what
it stores is the already-sealed payload, byte for byte, appended in the
order it was sealed and never overtaken by a later one, so a message
delivered from it is indistinguishable on the wire from one sent the
moment it was written, and a peer implementation needs to know nothing
about it. Two of this protocol's own properties are what make it sound:
delivery is ordered per link (§7.1.1), so a pad-wrapped run arrives in
the sequence its pad expects (§16.4); and an envelope is sealed against
the recipient's key as it was at that moment (§12.4), so one held across
a rotation fails to open exactly as any other stale envelope would.

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

That re-signal is a fresh attempt in the full sense of step 4, including
the reliable layer's restart (§7.1.1). A link that is not up may be *lost*
rather than merely waiting on a first reply, and a lost link still holds
the reliable-delivery state of whatever it was carrying when it died -
losing a link deliberately does not discard that, since the content was
never delivered and the restart belongs to the next attempt. The peer
that receives the new identifier concludes this side restarted and resets
its own sequence space to match, so a side that re-signalled *without*
restarting its own would keep numbering frames from where the dead link
stopped: every one of them then lands outside the peer's expected
sequence, is buffered as though it were merely early, and is
acknowledged - so it is never retransmitted either - and the content is
silently lost in both directions with nothing reported to either user.

**6. The rendezvous socket keeps serving.** The server side of step 1 is
unauthenticated and answers whatever arrives, and one socket serves every
client at once, so a single failed receive on it must never end it: doing
so would leave every client that connects afterwards with host candidates
alone - able to punch on a LAN and nowhere else - for the rest of that
server's uptime, with nothing to say why. Because it replies to whoever
asked, an ordinary client disappearing can itself surface as an error on
a *later* receive, which is exactly the case that has to be survivable.
Failures are therefore reported and skipped, with a brief pause first so
a permanently broken socket cannot spin.


#### 7.1.1 Reliable delivery over the punched link

UDP gives no ordering or delivery guarantee, so text and file content -
which must arrive complete and in order, unlike voice (§7.3) - get a
small hand-rolled reliable layer on top, carried
inside `PunchDatagram::Reliable { seq, payload }`:

- **Sender** (the sender): assigns an increasing `seq` to each outgoing
  payload, retransmits on a timeout with capped exponential backoff, and
  after 10 retries with no ack treats the link as dead - which per §7.1
  means re-punching it, not giving up on the content: anything still
  unacknowledged goes back onto the pending queue to be re-sent once the
  link reopens. The timeout itself is measured, not fixed: 400ms until the
  first round-trip sample comes back (nothing is known about the path
  yet), an RFC 6298-style estimate from the observed RTT after that
  (`SRTT + 4*RTTVAR`, floored at 100ms so a fast/local path doesn't fire on
  ordinary jitter, capped at 3s) - a lost frame to a nearby peer is
  retransmitted in well under 400ms rather than waiting out a guess sized
  for a much slower path. Only ever sampled from a frame that was never
  itself retransmitted (Karn's algorithm - an ack for a retransmitted
  frame can't say which transmission it belongs to), and reset whenever a
  link is re-punched, since a new path may have entirely different timing.
- **Receiver** (the receiver): acks every `Reliable` frame it sees
  immediately, even a duplicate or an out-of-order one; delivers frames to
  the application in order, buffering ones that arrive ahead of the
  expected sequence (bounded to 512 buffered frames - exceeding that fails
  the link rather than growing unbounded) and dropping duplicates.

The sequence space belongs to one punched link: both sides restart it
from zero when a link is re-punched, which they can do safely because
neither can transmit on the new link until both have entered the new
attempt.

This is deliberately minimal - no congestion control and no
selective-repeat - since it operates at chat-message/file-chunk
granularity, not bulk throughput. The one thing it is not minimal about is
what an ack means: an ack names the frontier the receiver has *delivered
in order*, not the highest `seq` that happened to arrive, so a frame still
sitting behind a gap in the reorder buffer repeats the old frontier and
retires nothing. That is what keeps the in-flight window tied to delivery
rather than to arrival. Note what it still does not say: an ack means a
datagram reached the peer's client, never that the peer could read what
was inside it - which is why delivery is reported separately, by the
recipient itself (§7.2.1).

**A queued frame is retired by the peer, not by the sender.** Content
released from a durable queue (§7.1) goes out carrying a local
correlation tag, and the sender's copy is deleted only when the ack for
that tag comes back. Handing a frame to this layer proves nothing about
its arrival: the link can die mid-flight, in which case the frame is given
up on above and nothing else would re-send it, and the process can be
killed between the two. In both cases the durable copy is still there and
is offered again the next time the link opens. A duplicate produced that
way is refused by the receiver's replay window (§13.4), so at-least-once
here is exactly once as far as the user is concerned. Unreliable frames
(§7.3) are the exception in the obvious way: there is no ack to wait for,
so they are released on handover.

**A frame that is delivered is never silently dropped.** Once the reliable
layer hands a payload up, the application owes the user a visible outcome
for it. Two cases used to fall short of that and no longer do. A payload
can arrive from a peer the client has not yet been *told about* - a
punched link carries content the moment it opens, which can beat the
server's word that the sender exists, leaving no public key to decrypt
with and no name to render under; such a message is held (bounded, the
same rule as the reorder buffer above) and re-offered on every turn of the
session loop, so it is shown as soon as the sender is known rather than
discarded for arriving early. And a payload can arrive *out of the order
it was sealed in*, which the durable queue (§7.1) makes ordinary; §13.4's
window is what keeps that from reading as a replay. Beyond those, where a
message is shown follows the ordinary rules: the room is created if it
does not exist, so a conversation closed with `/leave` reappears carrying
it, and a sender still under identity review has it held and revealed on
Accept (§12) rather than lost.

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
`PeerLink` state - it checks whether it still has any reason to reach the
sender at all, which is the same relevance check §7.1.3 uses to decide
whether to *keep* a link: a currently-joined channel in common, or DM
history with them. A request from someone who clears neither is dropped
silently, leaving nothing behind for a follow-up message to probe.

The two checks are deliberately the same one. Answering only within a
shared channel while retention also keeps a link for DM history leaves a
DM that has outlived every shared channel in a state neither side will
ever re-signal - each keeps retrying and each silently drops the other's
proposal. That is invisible for as long as the addresses learned earlier
still work, and becomes permanent the moment either peer's address moves,
which is precisely the situation signalling exists to recover from.

This check is **not** applied symmetrically to the *initiating* side
(the initiating side) - every call site that proactively opens a
link is already reachable only after legitimate prior contact: the eager
trigger above fires directly off a `UserJoined` for a shared channel; the
file-offer accept/reject and key-rotation-install paths only run for a
peer that already reached this client through an existing link or a
verified rotation. Gating those too would be pure redundancy. It is also
why the answering check has to admit DM history rather than a shared
channel alone: the supported case of still messaging someone in an open DM
after they have left every channel you shared (SPEC.md's "Offline users")
needs *both* directions to work, not just the one that initiates.

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

#### 7.1.5 Punching with no server at all

Everything above needs a server for exactly two things: to say who a peer
is, and to carry one round of candidate addresses between the two clients.
This section describes an alternative, entirely separate way to get a link
open that needs neither - the local preferences file supplies the identity
and the address, and the wall clock supplies the timing. It changes nothing
about §7.1: a client with it turned off behaves exactly as before, and a
client with it on still punches server-coordinated links for everyone else
in the ordinary way.

**Configuration.** Both peers must have configured each other. Each names
the other's nickname, the host their client is reachable on, and how often
to try:

```
direct_punch=on
direct_punch_to=bob,bobpublic.com,every_1m
direct_punch_to=marco,marcohost.com,every_1h
```

The host may be an IPv4 address, an IPv6 address or a hostname, and may
carry its own port (`bobpublic.com:19000`, `[2001:db8::1]:19000`) or a
bracketed list of them (`bobpublic.com:[18000,19000,21000]`); with no port
at all, both sides assume one well-known default. A written port must fall
between `DIRECT_PUNCH_PORT_MIN` and `DIRECT_PUNCH_PORT_MAX`, and one that
does not is refused with the range in the reason. The frequency is one of
`every_1m`, `every_5m`, `every_10m`, `every_15m`, `every_20m`, `every_25m`,
`every_30m`, `every_35m`, `every_40m`, `every_45m`, `every_50m`, `every_55m`,
`every_1h`.

Unlike §7.1's UDP socket, whose port is ephemeral because the server
relays whatever it happened to be given, this one is fixed: with nothing
relaying it, a port both sides agreed on in advance is the only thing a
peer can aim at.

**Why a line may name several ports.** Agreeing on a port is not the same
as arriving on it. Many NATs rewrite the source port of an outgoing
datagram whether or not the one asked for is free, so a peer aiming at the
agreed number reaches a port their router never mapped, and nothing
connects however well the two clocks agree. Which port survives is the
router's choice, not either peer's, so no single agreed number fixes it.

Being reachable on several ports is the other half of it, and it is not
the same thing as aiming at several: what a peer can reach this client on
is exactly the set of ports it sends **from**, never the ones it sends
**to**. So `direct_punch_port` takes a list too, one UDP socket is bound
per port, and probes are **paired** - the socket bound to 18000 probes the
peer's 18000. Two clients running the same list are then reachable on all
of it, and a router leaving any single port unrewritten is enough. A peer
port with no matching local socket is still probed, from the primary, so
two settings files that disagree punch with fewer chances rather than
none; a local port already in use is reported and skipped, and only all of
them failing falls back to an ephemeral socket.

Every datagram to a peer leaves from the socket that peer's own traffic
arrived on - the only one their NAT holds a mapping for - including the
probes of an attempt their own probe opened.

Naming several and probing them all on the same slot only needs *one* to
get through. Every named port is probed with the same `DirectPing`, and
the first reply settles it: the address a peer actually answers from is
locked in and becomes the only one probed thereafter, because the port
that answered is the port that survived both routers' rewriting. Losing
the link clears that lock and the next attempt sweeps the whole list
again - a NAT that reassigns its mappings makes the port that worked no
longer the port that works - re-resolving a named host with it, an address
having moved being the other reason a link drops for good.

**1. The slot grid, in place of signaling.** Hole punching only works if
both sides send at roughly the same moment - that is what the candidate
relay was buying. Here the wall clock buys it instead. Each target's
schedule is a grid of slots that **restarts at every o'clock** and steps by
that target's frequency: `every_1m` fires at :00, :01, :02, ...; `every_1h`
fires at :00 only. Both peers run the same frequency, so both grids land on
the same instants with nothing passing between them.

The grid is computed against UTC, not local time, so peers in time zones
with fractional-hour offsets stay on the same grid as everyone else.
Restarting it at each o'clock is also what makes `every_55m` well defined: its
slots are :00 and :55, and the one after :55 is the *next* hour's :00 - not
:50 past it. A client started mid-slot waits for the next boundary rather
than probing immediately, since a probe at any moment the peer has no
reason to be probing back is wasted.

**2. Punching, in place of a candidate exchange.** At each slot, a target
whose link is not already up is probed directly at its configured address:

```
PunchDatagram (continued from step 3 above) =
    | DirectPing { link_nonce: u64, from: string }
    | DirectPong { link_nonce: u64, from: string }
```

These carry the sender's own nickname because nothing else can identify
them: no candidate exchange named a peer, and the source address is
precisely what the receiver is trying to learn. A `DirectPing` is answered
**only** for a nickname the receiver itself lists in its own
`direct_punch_to`, and a nickname longer than a fixed small ceiling is
dropped before it is even looked up - so the fixed port is no more
discoverable by scanning it than an ephemeral one, exactly as §7.1's rule
for an unattributable `Ping` intends. A configured peer's probe also opens
the receiver's own attempt if it had not started one: their clock is as
good an alarm as ours, and without answering in kind there is no second
direction to punch open.

`DirectPong` echoes the nonce of the `DirectPing` it answers, and the
address it arrives from - frequently not the one configured, once NAT is
involved - is locked in as the link's active address. From that moment the
link is an **ordinary** one: it activates through the same path a
server-arranged link does, carries the same reliable and unreliable frames
(§7.1.1, §7.2, §7.3, §7.6), and is kept alive and watched for silence by
the same `Keepalive` and liveness rules. Nothing downstream of activation
knows or cares which way it was opened.

**3. One attempt lasts 30 seconds.** An attempt that nobody answers is
abandoned after a fixed window and the target waits for its next slot.
The window is comfortably inside the shortest grid step, so an attempt is
always finished - one way or the other - before the next one is due. The
whole window is genuinely spent probing: a link's own punch timeout
(step 4 of §7.1) is much shorter than this, so one attempt covers as many
link-level attempts, each with a fresh nonce, as the window has room for
rather than falling silent after the first one gives up.

**4. A link that is up is left alone.** A slot arriving for a target whose
link is already open does nothing at all: no re-punch, no new nonce, no
interruption. Only losing the link reopens the question.

**5. Losing a link that was up.** This is the one case that does not wait
for the next slot. The link is re-punched straight away, up to five
attempts, each getting its own full 30-second window - but only for a peer
no server could re-establish instead. That distinction is per peer, not
per session: a peer the server has named is handed back to §7.1's ordinary
re-signalling, which will reach them; a peer no server has ever named -
one who exists only in the preferences file - has nothing else that can
bring the link back, so the budget is spent on them. Coming back forgives
the budget entirely, so it bounds one outage rather than the session.

**6. Never two links between two people.** Whichever way a link was
opened, there is only ever one of it. While a direct punch owns a peer's
link, nothing about that peer is signaled through a server - not a send
waiting on it, not a retry backoff, and not a candidate proposal arriving
from the peer themselves, which is ignored rather than followed. And a
peer who is reachable *both* ways is one person with one link: a target
for someone the server has also named is filed under the identity the
server gave them, so the two routes converge on the same link instead of
opening one each.

**7. From a path to a person.** A punch opens a path; it does not say who
is at the other end. The nickname on a `DirectPing` is unauthenticated -
anyone able to reach the port could claim it - so nothing is registered on
one. What registers a peer is the first payload that *authenticates* them:

```
Content::ChannelPresence   // plaintext: the sender's joined channel names
P2pPayload =
    | ChannelPresence { envelope }     // sealed exactly like DeviceIdAnnounce
```

Sent when the link opens, and again whenever the sender's own membership
changes. Opening it is the authentication: the envelope is verified
against the key already pinned for that nickname and its recipient binding
is checked (§13.4), so one that opens could only have come from whoever
holds that key. This requires a pinned identity - a peer with none stays a
transport-only link - and one that reads as a keybundle, since that is
what the envelope is sealed to.

**A pad is the other thing that can register someone.** A pair who hold a
one-time pad for each other but have never exchanged keybundles cannot
send a `ChannelPresence` at all - there is nothing to seal one to - and
under the rule above they would stay transport-only forever, which is
exactly the pairing §16.2's `Direct` framing exists to serve. For them the
pad stands in, on both sides:

- **The side whose link comes up** registers the peer if a pad is
  provisioned for the pair, and marks the session active immediately.
  There is nothing left to negotiate - both ends already hold the key - so
  `/otp` opens no round trip and the very first message rides the pad.
- **The side a message arrives at** takes the sender's nickname from the
  link and their key from its own pin for that nickname - never from
  anything the sender claims - and registers them only once `otp
  --decrypt` has actually opened something from them. That verdict is the
  authentication, and a stronger one than a signature: it is tied to the
  holder of the mirror key at the expected offset, not merely to a keypair
  (§16.2).

Registering is all either does. It spends no pad, and what an impostor
taking the nickname can cost is bounded by the acknowledgement gate to a
single message they cannot read (§16.2).

Once registered, the peer is placed in the channels *both* sides have
joined (a channel only one side is in gives the other nowhere to put
them). The announced list is authoritative rather than additive, so a
channel dropped from it is how a peer says they left. A peer sharing no
channel at all is still registered, reachable as a direct conversation.

From that point nothing downstream distinguishes them from a peer a server
introduced: they are listed among a channel's members, channel-addressed
messages and voice reach them, a call's roster includes them, and a focus
naming them or their channel resolves. That is what makes a background
client's channel focus and its global push-to-talk work over a link no
server ever arranged.

Because such a link is not held by any channel, a channel departure does
not tear it down: it was opened by configuration and a schedule, and only
those end it.

**What this does not change.** A peer met this way is still subject to
every identity rule in §12. Registration leans on §12's pinning rather
than working around it: the pinned key is exactly what an arriving
envelope is checked against, so a peer whose key is unknown, or whose key
has changed, is not quietly admitted. No key exchange happens here - two
peers who have never established each other's key material through a
server have a working transport and nothing to encrypt over it.

**No-IP updates.** Everything above assumes a peer's `direct_punch_to` host
stays put. For one whose address changes - an ordinary home connection -
that host is instead a No-IP dynamic DNS hostname, and this side is what
keeps it pointed at wherever this machine currently is:

```
noip_when_no_server_and_direct_punch_is_active=on
noip_hostname=myhouse.ddns.example
noip_username=dave
noip_password=hunter2
```

All four are off/empty by default, and all three of the latter must be
filled in for anything to run - a toggle left on with one missing, or with
`direct_punch` naming no target, is reported once at session start and the
updater never starts (`client::noip::NoipConfig::from_settings`).

All four, like the `direct_punch` keys above them, are editable from inside
the client as well as by hand - `Ctrl+S`'s Direct Punch tab (`docs/SPEC.md`
Functionality #23). Unlike the punch schedule, which is reconfigured on the
spot, these take effect on the next start: the updater is resolved once,
from one settings snapshot, when the session begins.

The updater tracks whether there is a server to hear from, not merely
whether its own setting is on: it runs only while `--no-server` or the
server connection has been lost, and is torn down the moment the server is
reachable again (`SessionState::sync_noip_job`) - so this machine's No-IP
password only ever leaves it while a peer could actually need this side's
address to reach it directly.

Once running, it fires once immediately, then every 5 or 6 minutes
alternately, forever. Never a flat 5.5-minute period: 330 seconds is not a
multiple of 60, so no fixed period can land on the same wall-clock second
every time on its own. Alternating a 5-minute gap with a 6-minute one is
what keeps every single fire on second 50 of its minute - specifically so
the update completes before the direct-punch slot grid's own boundaries,
which always fall on second 0 of some minute - while still averaging
exactly 5.5 minutes over every pair of them.

One update is an HTTP GET to
`https://dynupdate.no-ip.com/nic/update?hostname=<noip_hostname>`,
HTTP Basic-authenticated with `noip_username`/`noip_password`. No-IP
reports its own outcome in the response body of an ordinary `200` - `good`
or `nochg` on success, a documented failure code otherwise - so only a
non-`200` exchange (a transport or proxy failure, not a No-IP-level
refusal) is treated as an error by the client itself; a body that is
neither `good` nor `nochg` is logged rather than retried early, since the
next scheduled fire is only minutes away regardless.

**Reconciling an unpinned nickname against an already-pinned key.** A
`direct_punch_to` nickname can punch successfully - the name matches, so the
transport link comes up - and still have no key pinned for it at all: maybe
the settings line was typed before the key was ever exchanged, maybe the
person is already known under a different name. Left alone this is exactly
the "transport-only link" §7.1.5 already describes above: nothing ever
registers them, and nothing tells the user why.

Instead, the moment such a peer sends whatever would normally prove their
identity - a `ChannelPresence` envelope for a `pq_hybrid` peer, or a
pad-wrapped message for a pad-only one - the user is asked: *"A connection
was received directly to your public ip from an unknown nickname
("&lt;name&gt;"). Do you want to check which of your local keys matches this
request?"* Declining costs nothing: no check runs, and a later, distinct
proof from the same nickname asks again from scratch.

Agreeing runs a real cryptographic scan against every *other* nickname
already pinned locally - never a guess, and only ever against a candidate
whose pin decodes as a `pq_hybrid` keybundle:

- a `ChannelPresence` proof is tried by attempting the ordinary
  envelope-open (§13's signature check) as if that candidate's key were the
  sender's;
- an OTP-wrapped proof is tried by attempting only the *outer* `pq_hybrid`
  seal a `PqWrapped` pad session carries (§16.2) - covering a peer who has
  a real identity *and* an OTP session layered on top of it, without ever
  touching the pad itself during the search.

A candidate whose pin does *not* decode is never tried at all, for either
proof kind - not because it couldn't in principle prove something, but
because doing so would mean running every locally-held one-time pad's own
decrypt against a ciphertext from an unverified source, one pad at a time,
to find out who is speaking. A `pq_hybrid` signature check costs nothing
to try repeatedly and fails cleanly on a wrong guess; a pad's decrypt is
real, spent key material, and repeatedly reaching for *every* pad held
just to attribute one unverified message is a materially different (and
here, deliberately unwanted) cost. A pad-only peer's unpinned nickname is
therefore never reconciled by this scan - the "impossible without a key"
outcome below is what such a peer's first message gets instead.

A wrong candidate has no side effect either way: both checks are ordinary
`pq_hybrid` signature verifications that fail before anything is spent.
Since a signature verifies under exactly one key, at most one candidate
can ever succeed - this is a cryptographic near-certainty, not something
the scan has to adjudicate. The pad itself, for the OTP-proof case, is
touched only once real content-decrypt happens - after the outer seal has
already named exactly one candidate as correct.

Finding no match tells the user plainly: *"Impossible to establish
communication with the user without a key. Requires a server for key
exchange or manually exchanging the keys."* Finding exactly one asks a
second question - *"I found that the request from &lt;name&gt; matches your
local key for &lt;matched&gt;. Do you want to use &lt;matched&gt;'s key to talk to
&lt;name&gt;?"* - and confirming it pins the same key bytes under the new
nickname too (no `IdStore` schema change: nothing ever required a key to
be pinned under only one name) and finishes registration from the
plaintext the scan already recovered, never decrypting a second time. For
an OTP-wrapped match this automatically shares the existing pad session,
since a `PqWrapped` contact name is a pure function of both sides'
fingerprints.

This is reachable only for a nickname that is itself a `direct_punch_to`
target - a stranger probing an unconfigured name is untouched, exactly as
above - and never for a server-introduced peer, since the server-coordinated
path's own datagrams (`Ping`/`Pong`) carry no nickname at all; only
`DirectPing`/`DirectPong` do, and that variant only exists here.

**A repeated, genuinely failed check is a strike against its source IP.**
Three strikes - the user agreed to check, the scan ran, nothing matched -
from one IP, spanning at least two different clock minutes, within a
rolling 10-hour window, bans that IP outright: no further `DirectPing` from
it is even shown a popup, checked first thing before any nickname is
looked at. Unlike §6.6's channel-password ban, this one has no auto-expiry
and does not live only in memory - it is written to
`~/.aloo/banned_ips.log` (date, ip, reason, one per line, plus a running
`<n> banned` header line recomputed on every write) and reloaded at
startup, so it survives a restart and is lifted only by editing the file
by hand.

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

A text message's plaintext is capped at `proto::TEXT_MESSAGE_MAX_LEN`
(10,000 `char`s) - client-enforced only, since the plaintext never reaches
the server (it lives inside `Envelope::blocks`, sealed before it ever
leaves the sender). `UiState::handle_input_key` refuses further keystrokes
at the cap; a paste is capped the same way defensively, though the
5,000-character file-conversion threshold below always diverts a paste
long enough to actually reach it.

A pasted block is submitted as a single message, embedded newlines
intact, the instant it arrives - it never lands in the compose bar for
editing first (`UiState::handle_paste`, fed by `Event::Paste` once
`tui::terminal::setup` enables bracketed paste). A paste longer than
`client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD` (5,000 characters)
is written to a `.txt` file under `client::file_transfer::paste_tmp_dir`
and sent as an ordinary file transfer (§7.6) instead - the same
`FileOffer`/`FileAccept`/`FileChunk` flow a `/file` send uses, just with
the file synthesized rather than picked from disk.

#### 7.2.1 Delivery acknowledgment

A sender may want to know that a message it sent actually got through to
the people it was addressed to. The reliable layer's own ack (§7.1.1) is
*not* that answer: it says a datagram arrived and was handed to the peer's
client, which says nothing about whether the peer could make sense of it.
Delivery is therefore a claim only the recipient can make, and it makes it
explicitly.

A sender names its message by putting a `msg_id` on what it sends -
`Envelope`, `OtpEnvelope`, `FileOffer`, `OtpFileOffer`, `StreamStart` or
`OtpVoiceOffer`. The id is the sender's own; nobody else interprets it,
and it is echoed back untouched. Omitting it asks for no receipt.

The recipient answers with `DeliveryReceipt { msg_id, stage }` **once it
has decrypted the content**, and never before. A message that arrives but
cannot be decrypted is deliberately left unacknowledged; its sender goes on
showing it as undelivered, which is the truth.

There are three stages, because for a voice message or a file the
interesting moment comes after decryption - being able to read a file
offer is not the same as having the file, and decoding audio is not the
same as having heard it:

| Content | `Decrypted` | `Viewed` | `Consumed` |
|---|---|---|---|
| text | the envelope opened | *(never used)* | *(never - there is nothing further to do)* |
| file transfer (`.txt`, staged - §7.6) | the **offer** opened | opened in the preview popup without being saved | the whole file has arrived and been written to disk |
| file transfer (anything else) | the **offer** opened, so the recipient knows what is being sent | *(never used)* | the whole file has arrived and been written to disk |
| voice message | the stream ended having produced decrypted audio | *(never used)* | that audio was actually played |

`Consumed` may come long after `Decrypted`, or never: a file offer may be
rejected or its transfer fail part way, and audio decoded while its sender
was muted sits unheard until the recipient replays it - which is exactly
when the receipt is sent. Either way, `Consumed` implies `Decrypted`; a
sender receiving them out of order (a re-punch can reorder anything) must
treat the stronger one as covering the weaker - `Viewed` is weaker than
`Consumed` and never overrides it once received, even if a `Viewed` for
the same message arrives afterward (`UiState::mark_delivered`): a file
genuinely saved stays reported as saved.

A message decrypted but withheld from the user pending a trust decision
(§12) still counts as `Decrypted`: the gate decides whether to show it, not
whether it made sense.

The properties that follow:

- **It is per recipient.** A channel send is one independently-addressed
  message per member (§7.2), each with its own link and its own receipt,
  so a channel message is delivered to *some* of its recipients long
  before it is delivered to all of them. A sender is expected to
  distinguish the three cases - none, some, all - and a direct message,
  having exactly one recipient, only ever has two of them.
- **It survives the link.** A receipt is sent reliably like any other
  content, and the message it answers is itself queued and re-sent across
  a re-punch (§7.1.1). A message therefore turns delivered late rather
  than never, however many attempts either direction took.
- **It is not a read receipt.** `Decrypted` says the recipient's client
  could read the message, not that a human has. `Consumed` says what their
  client did with it - wrote the file, played the audio - which for a voice
  message is as close to "they heard it" as a protocol can honestly get,
  and still says nothing about whether anyone was listening.
- **It does not survive a restart.** A `msg_id` names something in the
  sender's own running state; a sender that stops has nothing left to
  attribute an incoming receipt to, and a message left undelivered at that
  point stays that way.

This is a different acknowledgment from `OtpDeliveryAck` (§16.2), which
answers a different question: that one is about the one-time pad's gate -
whether the sender may spend the next pad slot - and is keyed by the pad
sequence rather than by a message. Both are sent for an OTP-wrapped text
message, and neither substitutes for the other.

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

**A chunk can reach a receiver before its own `StreamStart` does.**
`StreamStart` is sent first, but travels the reliable channel while
`Chunk`s travel unreliable UDP over the same socket - nothing guarantees
which one is *processed* first, only which was *sent* first. For an
ordinary multi-second recording this is harmless: the stream self-heals
the moment `StreamStart` catches up, at the cost of one or two chunks. A
recording short enough to finish - and send `StreamEnd` - before
`StreamStart` is processed is a different matter: since `StreamEnd`
travels the same reliable, in-order channel as `StreamStart`, it is
guaranteed to finalize the stream immediately after `StreamStart` starts
it, with nothing to attach any earlier chunk to in between. Left
unhandled, this would silently lose every chunk such a recording ever
sent. The reference client's receiver holds a chunk that arrives with no
matching stream in a small bounded buffer, keyed by `(from, stream_id)`
exactly like the stream table itself, and replays it - in arrival order -
the moment that stream actually starts; a buffer whose `StreamStart` never
arrives at all is aged out after a few seconds, and the number of chunks
and of distinct never-started streams it will hold at once are both
capped, so a lost or withheld `StreamStart` cannot grow it without bound.
This is a receiver-side implementation detail, not part of the wire
protocol - it changes nothing about what a sender puts on the wire.

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

**No rate/format field.** Unlike `Envelope`, chunk payloads carry
no `Content` tag and no sample-rate/channel-count metadata - the
plaintext recovered by decrypting `blocks` is understood, by convention
between this app's own client implementations, to be one coded chunk of
mono audio at a fixed rate (16000Hz in the reference client). The wire
protocol itself does not encode or
enforce the rate; it is purely a convention two cooperating clients must
already agree on out of band. An implementation using a different
sample-rate convention would not be interoperable with clients using
this one, and the protocol gives a receiver no way to detect that
mismatch from the bytes alone.

**Chunk coding.** The plaintext of one chunk is:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | Codec tag. `1` is the IMA/DVI ADPCM coding described here; a receiver rejects a chunk carrying any other value rather than guessing |
| 1 | 1 | Low 7 bits: the ADPCM step index this chunk starts from, 0-88. Top bit: set when the final payload byte holds one sample rather than two |
| 2 | 2 | The chunk's first sample, signed 16-bit little-endian. Reproduced exactly on decode |
| 4 | .. | 4 bits per remaining sample, low nibble of each byte first |

Every chunk decodes **standalone** - it carries the predictor and step
index it begins from rather than continuing the previous chunk's. This is
required, not an optimisation: chunks travel unreliably, so one that is
lost or arrives out of order must not corrupt every chunk after it. The
cost is the four-byte header and a slightly worse first sample per chunk.

Because each chunk restarts, the step index it starts from matters: a
chunk that began at the bottom of the step table would spend its first
samples climbing, which at one chunk every 15ms is a continuous buzz
rather than an occasional artefact. A sender therefore chooses the
starting index to match the chunk's own average sample-to-sample
movement, and states it in the header - which is why the header carries
the index at all.

Coding rather than raw PCM is what makes a multi-party call practical: a
live call is a full mesh (§7.7) with no server in the middle, so each
participant sends separately to every other, and raw 16kHz PCM16 would be
256kbit/s per direction per peer. At 4 bits a sample that is 64kbit/s.

A chunk's *accumulated* form - what a receiver reassembles a finished
recording into, and what the reference client replays, exports and sends
under one-time-pad framing - is decoded PCM, not this coding. The coding
exists only between `*Start` and `*End`, on the wire.

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
`Content::FileOffer` and `envelope.blocks` opens (§13.3, the same one-chunk
sealed send a text message uses) to a bincode encoding of:

```
FileOfferPayload { filename: string, size: u64 }
```

Bundling `filename`/`size` into the encrypted plaintext (rather than
cleartext fields on `P2pPayload::FileOffer`) keeps them as private as the
rest of the message - the server never sees any of it at all anymore
(§10), not even ciphertext size, since the offer travels the direct link
(§7.1), not the server. Once accepted, the actual file bytes are **never**
wrapped in a struct at all - each `FileChunk`'s `blocks` is the PQ-hybrid
(§13) encryption of a raw slice of the file, exactly like voice's raw-PCM
chunk convention (§7.3's "no content/rate/format field").

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
(§7.1), so it's sized to keep worst-case sealed-chunk ciphertext under
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
no separate save-location prompt; accepting *is* saving - **except for a
`.txt` offer**, which instead streams into a staging directory
(`client::file_transfer::incoming_preview_dir`, `~/.aloo/tmp/incoming`) so
its content can be previewed without yet counting as saved (below).

**`.txt` preview**: `Enter` on a staged `.txt` receive opens a full-width,
scrollable, read-only popup showing its content, capped at
`client::file_transfer::PREVIEW_MAX_BYTES` (1 MiB) with a truncation
notice if the real file is longer - the file on disk is never truncated,
only what is read into memory for display. Opening the preview sends one
`Viewed` receipt (above), the first time only. Pressing `d` inside the
popup does exactly what accepting any other file already does
automatically: moves the staged file into `~/.aloo/downloads` and sends
`Consumed`. A staged file never explicitly saved is left where it is,
cleared at the next session start the same way `~/.aloo/otp/.tmp` is. This
is scoped to non-OTP transfers only: an OTP-protected receive's own
acknowledgment already depends on decrypting straight to its final
destination (§16.2's `ack_proof_for_file`), a materially different,
proof-based mechanism this staging step does not touch - an OTP-wrapped
`.txt` file is saved on arrival exactly like any other OTP file.

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
CallMute   { call_id: u64, target: user_id, muted: bool }
CallRoster { call_id: u64, members: list<user_id> }
```

`call_id` is a fresh random token (unguessable off-path, like a link's
`link_nonce`, §7.1) chosen by whoever runs `/call`, naming the call for its
whole lifetime. `channel: some(name)` on `CallInvite` addresses a channel
call, `none` a call to one DM peer - carried in the clear (unlike a file
offer's filename, §7.6, there's nothing about a call's existence worth
hiding from a peer it's already addressed to).

**The host.** Whoever ran `/call` is the call's **host**, named for the
rest of the call's life by the simple fact that theirs is the `CallInvite`
each participant accepted. The host is an ordinary participant for audio
purposes and holds no state anyone else depends on, but three decisions
are theirs alone: muting a participant (`CallMute`), inviting more people
mid-call (a further `CallInvite`), and ending the call for everyone (their
own `CallEnd`, below). An implementation must honour those three only from
the host of the call it is actually on, and ignore them from anyone else -
that check is the whole of the host's authority.

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

**A participant's audio can reach a receiver before their own `CallAccept`
does - the same race §7.3 describes for `StreamStart`, with `CallAccept`
playing that role here.** `CallAccept` travels the reliable channel while
audio chunks (and the one `StreamKeySetup` a `pq_hybrid` participant sends)
travel unreliable UDP over the same socket, and nothing orders one
relative to the other; a peer sends its `StreamKeySetup`/first chunks the
instant *it* adds *us*, which is routinely before *its* `CallAccept` has
reached us and let us add it - this is the ordinary order of events, not
an edge case. Unlike a short voice message, a call cannot lose its entire
audio this way (there is no `StreamEnd`-equivalent racing right behind
`CallAccept` to finalize anything early - the stream simply runs for as
long as both sides participate), so the cost of dropping early arrivals is
smaller: only that participant's first moment of audio would be missing
every time they join a call already in progress. The reference client
avoids even that by holding both the key setup and any chunks that arrive
before the participant is added, and replaying them - setup first, then
chunks in arrival order - the moment they actually are added.
(§7.3's stream-identity rule, unchanged here), an implementation must
distinguish a call's `call_id` from an ordinary voice message's
`stream_id` some other way if it needs to route them differently (the
reference client tracks which `(from, id)` pairs belong to its current
call's roster) - the two numbers are drawn from disjoint generators (a
call's is fully random; a voice message's is a small per-connection
counter) and so cannot collide in practice, but nothing on the wire tags a
chunk with which kind of stream it belongs to.

**Muting oneself stops the audio locally, and is announced.** A muted
participant simply stops sending chunks to everyone for as long as it's
muted; every recipient's mixer hears silence from that source in the
meantime because nothing is pushed to it, the same as a moment of natural
silence during an ordinary recording. On top of that it sends
`CallMute { call_id, target: <itself>, muted }` to every participant it
knows about, so every roster can say who can currently be heard. That
message carries no authority: it is a statement about the sender's own
microphone, which stays the sender's alone to lift.

**A host mute is not local either.** `CallMute { call_id, target, muted }`
with a `target` other than the sender is the host's decision about someone
else, and is sent to every participant the host currently knows about,
`target` included. `target` stops sending audio until the host sends the
matching `muted: false`; its own mute toggle neither lifts nor deepens
that. Every other participant applies it to its own view of the roster, so
a muted participant reads the same to everyone. **Who may send which:**
`target == from` is accepted from anyone, and only ever moves a roster row
- it can never gate the receiver's own capture, whoever it names;
`target != from` is accepted only from the host of the call the receiver
is on, and ignored from anyone else. A participant who joins after a mute was
issued is brought up to date by the host repeating the outstanding
`CallMute`s to them alongside the `CallAccept` that admits them.

**Late invites, and `CallRoster`.** The host may invite someone mid-call
who was never a member of the call's channel (or, for a DM call, is not
the DM peer). Such a participant cannot derive the roster the way rule 1's
broadcast assumes - the channel/DM membership it would broadcast to simply
isn't the call. `CallRoster { call_id, members }` closes that: whenever a
participant adds someone new, it sends that newcomer the list of every
*other* participant it currently has, and the newcomer answers each of
them with an ordinary `CallAccept`. Rules 1 and 2 then converge the rest
exactly as before; `CallRoster` is an optimisation of discovery, never a
source of truth - a `CallRoster` naming someone unreachable or unknown is
simply skipped.

**Leaving.** `CallEnd { call_id }` is sent to every other participant a
leaving client currently knows about, and each one, on receiving it, tears
down that one pairwise audio stream and drops the leaver from its roster.
For every participant but the host, the call has no separate "end" beyond
that - it is, at any moment, simply whichever participants haven't yet
sent (or received) a `CallEnd` for it.

**The host's `CallEnd` ends the call for everyone.** A participant
receiving `CallEnd` from the host of the call it is on tears down its
entire participation - every pairwise stream, not just the host's - and
leaves the call, rather than carrying on with whoever remains. Nothing is
relayed on: the host sent its own `CallEnd` to every participant it knew
of, and each of those does the same teardown independently. A participant
the host never knew about is covered by whoever *did* know about it
leaving in turn. A client that never receives `CallEnd` from a peer who is
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

**There is no shared/session key anywhere in this protocol outside the
sealed sends of §13.** Every plaintext payload - a text message, a file
offer, one voice chunk - is encrypted **separately for every individual
recipient**, sealed to that recipient alone under the hybrid scheme (§13).
The server relays exactly as many independently-sealed copies as there are
recipients; it never sees, generates, or forwards a key, and could not
decrypt a multi-recipient message even if it colluded with one recipient
(each recipient's ciphertext is entirely independent).

Per-recipient sealing costs strictly more CPU and wire bytes per
additional recipient, which is the direct reason voice capture is kept to
a low sample rate (§7.3) and streamed in small chunks rather than one
large blob. Within one send, §13's setup-plus-chunks shape does establish
a per-send symmetric key (`k_data`) - a KEM produces a shared secret by
its very nature - but that key never spans recipients: each gets its own,
wrapped to its own keys.

A recipient's identity here is good for the whole session: a `pq_hybrid`
keybundle is loaded from a file and never rotates (§13). Its *encryption*
keys - not the identity - do rotate per peer relationship, on every
message sent or received with that peer; see §13.10.

**RSA-OAEP survives in exactly one place**: the server's `Rsa` auth
challenge (§5.3), where the client proves it holds the server's key by
decrypting a nonce. That is a client-to-server proof, not peer-to-peer
content, and §8.1 describes the chunking it uses.

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


### 8.2 RSA signatures

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
- Auth material as sent - a nickname and its plaintext password reach the
  server inside a sealed frame (§5.1), compared against a PBKDF2-derived
  key it stores; the password itself is never persisted.
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
`Identify` and never reused, and a nickname is freed the instant its
holder disconnects and immediately available to the next connection that
claims it via `Auth` (§5.1, §5.4) - there is no requirement, or even a mechanism, for a
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
`(nickname, device_id)` pair was last seen with (the full DER bytes, not a
fingerprint of them; §12.2), so a reconnect under a *different* key can be
flagged instead of silently, indistinguishably trusted. The model is the
same one SSH's `known_hosts` and Signal's safety numbers use for pinning,
but - unlike either of those, and unlike this app's own earlier
passive-banner implementation - a mismatch here is a **blocking**
decision, not merely a displayed warning: messaging with the mismatched
peer stays gated (§12.4) until the user explicitly Accepts or Rejects the
new key via an on-screen popup (`docs/SPEC.md` #9's "Identity review
popup"). This is still not a *permanent* lockout, which matters precisely
because a false positive is possible (e.g. a peer legitimately
regenerating their `my_key` file): a `Reject` is reconsiderable at any
time (selecting the peer again reopens the same popup), and nothing about
the decision is silent or automatic in either direction - the human
reviewing it decides, the app never guesses.

**A nickname's pin is per-device, additive, never silently replacing.**
Reconnecting from a *second physical machine* is a routine, expected event
- not automatically distinguishable, from the wire alone, from "an
unrelated key change" or "an impersonator" - and device id (§12.7) is what
lets a client actually tell the three apart instead of forcing every
device switch through the same mismatch review a genuine impersonation
gets. `id_store` therefore pins one key per `(nickname, device_id)` pair,
not one per nickname: a nickname with two devices holds two independent
entries, and pinning a new device's key never touches, replaces, or
removes another device's existing entry - adding is the only way in short
of an explicit, per-device delete the user performs themselves
(`docs/SPEC.md`'s Contacts section). Device id is self-reported and
therefore untrusted exactly like a nickname (§12.7) - it is never what
*grants* trust, only what narrows *which* already-pinned entry a byte
comparison runs against or a keychain slot resolves to; a spoofed device
id can, at most, cause an unnecessary review or an unnecessary
re-provisioning prompt, never bypass a key comparison or forge a pad's
authentication (§16.2), since both of those still rest on cryptographic
material alone. §12.4 is the full algorithm this enables.

### 12.2 What gets pinned, and what doesn't

**Scope: this section is about byte-comparison pinning only** - the
pin-and-compare path the identity check drives, where the alarm condition
is "these bytes differ from last time". It is the only pinning mechanism
this app has.

Byte comparison only works where the key really is the *same* key across
two separate connections, and `pq_hybrid` is: the identity keybundle is
loaded from a file (§13.2), so the same file produces the same bundle on
every connect, for as long as it exists. Rotation (§13.10) only ever
changes the encryption half, never the identity pinned here.

That is the whole of it, because `pq_hybrid` is the only `my_key` this
protocol has. A peer announcing bytes that do not decode as a keybundle
has no identity to pin at all in this dimension - see the next paragraph
for what happens to those instead.

**A nickname's `pq_hybrid` pin and its `Direct`-framed raw-pad pin
(§16.2) are independent, non-colliding trust dimensions**, distinguished
by each device entry's `key_mode` (`PqHybrid` or, for a raw pin, unset).
Every comparison in §12.4's algorithm, and every naming rule in §16
(§16.1's OTP contact naming, §16.2's Direct-pair pad binding), only ever
compares a nickname's entries that share the same `key_mode` as the one in
hand - a pre-existing Direct-framed raw pairing key for a nickname never
"mismatches" against that same nickname's first-ever `pq_hybrid` sighting;
a fresh, `key_mode`-scoped pin is created silently instead, and the
otp-only entry is left exactly as it was. This is what lets meeting the
same person once serverless (an otp-only relationship) and later through a
server (a `pq_hybrid` identity) coexist for one nickname with neither ever
touching the other.

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

### 12.4 What happens on a mismatch, and how a device is resolved

Device id (§12.7) is not known at the moment a peer's `pq_hybrid`
identity first needs checking - `UserJoined` arrives before
`DeviceIdAnnounce` ever could - so the algorithm runs in two phases:

**Phase 1, device-blind (`session::check_identity`, at `UserJoined`).**
Compares the newly-announced key against *every* `pq_hybrid`-scoped entry
this nickname has, regardless of device (`idstore::compare_key`): an exact
match against any of them is silent; no match against any of them opens a
review, coarsely, against the most-recently-seen entry (refined once the
device resolves, below); nothing pinned at all for this nickname yet is a
provisional, *unbound* first sighting (`pin_new_device(nickname, "",
key)`) - deliberately not yet attributed to any device, since none is
known. Either way, this phase never re-pins or persists a genuine
mismatch on its own; only an explicit `Accept` does (point 3 below).

**Phase 2, device-aware (`session::finalize_identity_pin`, once this
connection's device id resolves - §12.7).** Runs the precise, per-device
version of the same comparison, narrowed now that a specific device id is
in hand:

1. **`(nickname, device_id)` already has a bound entry, and the key
   matches it** - silent; last-seen is refreshed (§12.7).
2. **No entry for this exact device, but the phase-1 provisional entry is
   still unbound and its key matches** - claimed in place
   (`IdStore::claim_unbound`): the *same* entry's `device_id` field is
   rewritten to the one now confirmed, never duplicated. This is "filled
   in on first use" applied to the identity pin itself.
3. **A bound entry for this device exists, but its key differs** - or
   **no entry for this device exists, and the nickname has one or more
   *other* devices already pinned** - a continuity certificate (§12.6) is
   tried first, scanned against *every* one of the nickname's device
   entries sharing this `key_mode`, not just the one that mismatched (a
   `--rekey-pq-hybrid` cert can legitimately surface on a different device
   than the one that ran it - e.g. rekeyed, then the new keybundle file
   moved to a new machine). A match re-pins that one entry silently, no
   review, its `device_id` updated to the one now announcing it. No match
   against any entry falls through to the ordinary review (point 3 in the
   list below), scoped to just this device.
4. **The nickname has no pinned devices at all** (phase 1's provisional
   pin never landed, or was since removed) - first sighting, pinned
   silently, scoped to this device.

Case 3's review and its resolution work exactly as before, just narrowed
to one device's entry rather than the nickname as a whole:

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
3. On `Accept` (`session::accept_identity_review` -
   extracted from `handle_ui_action`'s `AcceptIdentity` arm so it is
   directly unit-testable against a hand-built session/UI pair, since the
   live two-daemon test harness cannot model two distinct devices for one
   nickname in a single run):
   pins the new key **for this connection's specific device only**
   (`IdStore::replace_device_key` if this device already had an entry,
   `pin_new_device` - additive - if it didn't), records the address/device
   id this connection was actually reviewed under as that device's
   last-seen values (§12.7), and **saves the store to disk immediately,
   synchronously** - the on-disk file reflects the new pinning the instant
   the decision is made, not batched or deferred. Crucially, **every other
   device this nickname has pinned is left completely untouched** - a
   second device announcing a new key never overwrites, demotes, or
   removes the first device's own entry; the two coexist, and an
   independent `check_identity`/`finalize_identity_pin` pass for the first
   device's own connection (if it's live) is entirely unaffected by this
   one's Accept. Every message held per point 2 is then revealed into the
   real log, in arrival order, and the peer is fully trusted again
   (sidebar color, sending, everything).
4. On `Reject`: no `id_store` write at all - the previous pin for this
   device (if any), and every other device's pin, is left exactly as it
   was on disk and in memory. The peer's review stays recorded (not
   discarded) so selecting them again re-opens the same popup for
   reconsideration, rather than having nothing left to show - this is what
   makes `Reject` a *reconsiderable* decision, not a permanent one
   (§12.1).

Multiple peers can have unresolved reviews at once; only one popup is shown
at a time, front of a small FIFO queue - a peer's mismatch is queued the
instant it's detected and the popup for it opens automatically as soon as
whichever review is currently showing gets resolved (`Accept` or `Reject`
either). Two different devices of the *same* nickname mismatching at
around the same time queue and resolve completely independently of one
another - each is its own device-scoped review.

A first-ever sighting of a nickname (nothing pinned for it yet) still saves
immediately and silently as an *unbound* entry (phase 1, case above) - so
it's durably pinned for the *next* reconnect, not just held in memory for
the current session - and this case never opens a review at all, since
there's nothing to compare against. A sighting that matches what's already
pinned for that device is likewise silent and writes nothing (nothing
changed, so there's nothing to persist). Only a genuine byte difference
against every device sharing this `key_mode` reaches the review flow
above.

**What `Accept` touches, and what it deliberately leaves alone.**
`accept_identity_review`'s only state changes are to `id_store` (the
additive pin above) and the UI's identity-review queue (lifting the trust
gate) - nothing else needs updating, for two separate reasons:

- **Channel/DM encryption never needed a separate update in the first
  place.** `known_users`/`channel.members` (`recipients_for_channel:244`)
  already hold whichever key that connection actually
  announced, set once at `UserJoined` time - *before* `check_identity` can
  even open a review - so a send immediately after `Accept` already
  encrypts to the live new-device key, not because `Accept` changed
  anything about how sends resolve a key, but because there was never a
  separate, staler copy of it anywhere to begin with. The same is true of
  `/info`/`i` (`client::contacts::handle_request_user_info`),
  which reads the live `session.peer_device_ids` for that exact
  connection, never `id_store` - it shows a freshly-accepted device
  correctly whether or not the review has been resolved yet.
- **An `/otp` session is a disjoint piece of state.** OTP/OTP-mail
  keychain names are device-qualified (§16.1.2/§17.1, folding in both
  sides' own `(fingerprint, device_id)`) - an entirely different keyspace
  from `id_store`'s pinning, computed independently of it. `Accept` never
  reads or writes `otp_store`, so a session already running under an old
  device is left completely untouched - same pad, same contact name, same
  keychain slot - by a new device being accepted for the *same* nickname's
  `pq_hybrid` identity. A fresh `/otp` is still required for the new
  device; only the ordinary `pq_hybrid` messaging moves over automatically.

### 12.5 Store format and location

The store is a small flat file, one line per pinned **device** (not per
nickname):

```
<nickname><TAB><device_id><TAB><hex-encoded public_key_der><TAB><trust><TAB><last addr><TAB><last seen unix><TAB><key mode><TAB><pinned from>\n
```

e.g. `alice\tlaptop\t30820122300d06092a864886f70d01010105000382010f00...\ttofu\t203.0.113.7:51820\t1700000000\tpqhybrid\t\n` -
the full DER bytes, lowercase-hex-encoded (lowercase hex, the same
encoding the fingerprint already uses, not base64 or raw bytes) so
the file stays plain text no matter what the key bytes are, unless it is
itself empty - a *bare contact* placeholder (`IdStore::pin_bare_contact`,
`/contacts`' "Add contact" with no identity card): a reserved
`(nickname, device_id)` slot with no key at all yet, invisible to every
reader of "the pinned key" (`get_for_device`, `get`, `check_key` all skip
it), that the first real key later pinned to the same slot silently fills
in place rather than sitting beside as a second entry; `device_id`
is the primary-key half of `(nickname, device_id)` - empty for an
*unbound* entry (§12.4's phase-1 provisional pin, or a pin imported from
an identity card, §12.6, neither of which has a confirmed device yet);
`trust` is `tofu` or `verified` (§12.6); `last addr` is §12.7's last-seen
value, scoped to this one device; `last seen unix` is when it was last
recorded (the contacts list's "last seen" column); `key mode` is this
device's pin `KeyMode`, `pqhybrid` or empty (§12.2's `key_mode` scoping);
`pinned from` is the identity-card file path an imported pin (§12.6's
"Importing one") came from, empty for every pin that arrived over the
wire instead. Every column from `last addr` on is independently optional
on the way in, so a store written before any of them existed still loads
correctly. A nickname with several pinned devices is simply several
lines sharing the same `nickname` column. Entries are written in
sorted-by-`(nickname, device_id)` order on save so the file diffs
cleanly under version control or manual inspection.

**This is a breaking format change from the single-key-per-nickname
store that predates the device-pinning model, with deliberately no
migration path.** A file written in the old
`<nickname><TAB><hex><TAB><trust><TAB>...` shape (no `device_id` column)
does not parse under the new column positions - its old hex-key column is
read as `device_id`, fails to look like one, and the line is simply
skipped - so an old file loads as *empty*, exactly like any other
unparseable line (below), never as a migration or a half-upgraded state.
Anyone reconnecting after an upgrade re-pins on first sight, same as any
other first-ever sighting (§12.4).

A nickname or device_id containing a tab, `\n`, or `\r` is never pinned
(silently treated as if it were a first-ever sighting, with nothing
written) - both are attacker-controlled input (any connected peer chooses
their own nickname; a device id is announced the same way, §12.7), and
accepting one containing the file's own field delimiter would let a
remote peer inject spurious records into a purely local trust file. The
key half has no such restriction - hex digits can't collide with any
delimiter no matter what the underlying bytes are, so any DER-encodable
key is always storable. A line whose key half fails to hex-decode (odd
length, non-hex character - e.g. hand-editing damage) is skipped on load,
same as a line missing the name, device id, or key column entirely; the
trust/address/key-mode/pinned-from columns are all independently optional
on the way in (a store written before one of them existed, or with an
empty field, still loads correctly) - loading the store never fails the
whole store over one bad line, an old-format line, or an unparseable one.

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

**Importing one.** The PQH key's "Create key" action on `/contacts`' key
details popup (docs/SPEC.md "Contacts") opens a file browser for a card
file; the card is refused, and nothing is pinned, unless its own attested
nickname matches the contact row it was opened from exactly - a card
always *upgrades* an existing row's identity rather than ever creating a
new one. The file it came from is recorded (`id_store`'s `pinned_from`
column, §12.5) purely for display in that same popup.

**What remains open.** None of this authenticates a first contact that
arrives with no card and no prior pin; that is still trust-on-first-use,
and the protocol has no way around it without an anchor outside itself.

### 12.7 Device id and last-seen address

An address is display-only, purely informational, and cannot be kept
confidential in transit anyway (it's the packet's own source, inherent to
any IP communication - see §12.1's "what remains open" reasoning extended
to this). **Device id is different: since the device-pinning model
(§12.1-§12.4), it is load-bearing rather than merely displayed** - it
decides which of a nickname's pinned entries a byte comparison runs
against, which keychain slot an OTP/mail name resolves to (§16.1), and
which device a `Direct`-framed pad is currently bound to (§16.2). It is
still entirely self-reported by whoever holds it - nothing stops a
modified client from lying about theirs - so its role is bounded exactly
the way any untrusted input's is: it can *narrow* which already-pinned
entry is compared or which slot is used, but it can never *grant* trust
or bypass a byte comparison on its own. A spoofed device id can, at most,
cause an unnecessary review to open, an unnecessary re-provisioning
prompt, or (§16.2) a message to be wrongly *held* pending the right
device - never cause an illegitimate connection to be wrongly accepted,
since real acceptance still rests on cryptographic material alone (a
matching pinned key, or - for a `Direct` pad - a genuine decrypt). It
always travels sealed exactly like ordinary content - never in the clear,
and never inside the punch handshake itself - with one deliberate
exception: a serverless, pad-only pair has no `pq_hybrid` envelope to seal
one to at all, so §16.2 instead carries it as cleartext wire metadata
alongside each pad-protected message, checked strictly *before* the
pad-consuming decrypt ever runs - see §16.2 for why that ordering is the
whole point.

**Device id.** Each installation generates a random 8-character
lowercase-hex id the first time it connects as a given nickname, and
reuses it for that nickname's whole lifetime: `crypto::random_bytes(4)`
hex-encoded, checked against every id already on file (any nickname) so
one machine never assigns the same id twice, then written alongside that
nickname to `~/.aloo/d_id` (`client::device_id::load_or_create`, one
`nickname\tdevice_id` line per nickname this machine has used) and read
back as-is on every later run rather than regenerated. A machine used
under several nicknames gets a distinct id per nickname. An empty string
is reserved internally as `id_store`'s "unbound" sentinel (§12.4), so an
announced device id that decodes to empty, fails to decode as UTF-8, or
contains a tab/newline (which would corrupt this file's own line format)
is refused outright rather than cached
(`client::device_id::accept_announced`) - a peer must never be able to
plant the sentinel value themselves.

**`DeviceIdAnnounce`: sent encrypted, once a link is `Active`.** A new
`Content::DeviceIdAnnounce` tag and `P2pPayload::DeviceIdAnnounce {
envelope: Envelope }` (§7.1's `PunchDatagram::Reliable`, exactly like a
text message or file offer) carry it - `envelope`'s plaintext is just the
device id's raw UTF-8 bytes, sealed per-recipient as a `pq_hybrid`
one-chunk send (§13), through the same `envelope::encrypt_envelope_for`
every other content type goes through. The punch handshake itself
(`Ping`/`Pong`) carries no device id at all - deliberately kept out of
that layer, which has no notion of recipient keys - so a device id is
only ever sent once the link reaches `Active` and the peer's key is
already known (from `Identify`/`UserJoined`, over the TCP control
channel). Sent automatically, unprompted, every time a link reaches
`Active` (`session::send_device_id_announce`) - idempotent, and cheap
enough that a link flap simply resends it. Silently skipped if the
recipient announced no keybundle to seal to (the same partial-delivery
rule every other content type follows) or encryption fails for any other
reason; there is nothing to retry beyond
the automatic resend the next `Active` transition already gives it.

On arrival, `session::on_device_id_announce` decrypts it (independent of
any trust gate on the sender - this is exactly the data an impersonation
review needs to resolve, not visible chat content subject to §12.4's
hold-and-reveal) and caches the plaintext. Processed unconditionally on
both sides regardless of who initiated the mismatch review, if any.

**Last-seen address.** Once *both* a peer's direct link is `Active` (the
address) and their `DeviceIdAnnounce` has decrypted (the device id) - the
two arrive independently and may race either way, so whichever happens
second is what actually acts (`session::maybe_resolve_p2p_identity_data`,
which also runs §12.4's phase 2, `finalize_identity_pin`) - the address is
recorded against *that specific device's own entry* in `id_store` (§12.5's
`last addr`/`last seen unix` columns), refreshed on every later `Active`
transition for that same device, not just the first. This deliberately
does **not** happen while a mismatch review for that device is still
outstanding (`AwaitingPeerInfo`/`Pending`): the review needs to compare
against whatever was recorded *before* this connection, so nothing
overwrites it until the user actually `Accept`s (at which point the
newly-reviewed connection's address becomes that device's new last-seen
value, per §12.4 point 3).

**How this shows up in a mismatch review.** §12.4's mismatch popup message
gets two more lines, one for each side of the comparison:

```
Last known from <addr> (device <id>).
Now connecting from <addr> (device <id>).
```

The "last known" half is read straight from `id_store` - whatever was
recorded for the *specific device entry* this review was opened against
(`session::reveal_pending_identity_review` finds it by matching the
previously-pinned key bytes the review itself carries), `unknown` if that
never happened (e.g. the pin was set by an `--export-identity-card`
import, §12.6, rather than a live connection, or there is genuinely no
prior device to compare against at all - §12.4's phase 2, case 3's
"no entry for this device, and the nickname has one or more other
devices").
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

`KeyMode::PqHybrid` is this protocol's one `my_key` method:
ML-DSA-87+RSA-4096 signing, ML-KEM-1024+RSA-4096 key-wrap, AES-256-GCM
bulk encryption. It needs a shared symmetric key per send by construction,
so it is documented here as its own self-contained model rather than as a
variation on §7-§8's per-recipient framing. Like §11/§12, this section
says what `public_key_der`/`Envelope.blocks` actually contain, but
otherwise reuses existing message types unchanged - no new
`ClientMessage`/`ServerMessage` variant, no change to `Envelope`'s or
`UserInfo`'s shape.

### 13.1 Why this method, and why it looks different

A per-recipient-only scheme - encrypt to the recipient's public key and
nothing else - needs nothing from the *sender*: no identity, no private
key, no signature. That is convenient, and it is exactly what makes real
post-quantum *authentication* impossible to bolt on without a shared-key
step: producing an ML-DSA-87 signature needs an ML-DSA-87 signing key.
This protocol requires one of every sender instead, which is what §13.6
below rests on.

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
- **Replay onto the same link.** each `send_id` is accepted at most once
  from a given peer (§13.4).

`recipient_fp` is an *identity* fingerprint, not a connection one - stable
across reconnects, unlike a `UserId`. Gaps in `send_id` are ordinary and
accepted: the counter is per connection rather than per recipient, so a
channel message addressed to five people consumes one value for all of
them and a message to somebody else consumes a value this peer never sees.

**How the two shapes travel.**

- **Text and file offers** put the whole `HybridSend` - setup and its
  single chunk - as the one element of `Envelope.blocks`. `Envelope`'s own
  shape is unchanged from when `blocks` held N RSA-OAEP blocks; it now
  always holds exactly one sealed send.
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
- **Replay**: `binding.send_id` must not already have been accepted from
  that peer. This is a *sliding window*, not a high-water mark: the last
  `replay::WINDOW` ids below the newest accepted are tracked individually,
  and an unused one among them is accepted. Anything that has fallen
  further behind than the window is refused.

  A window rather than a high-water mark because sends no longer
  necessarily arrive in the order they were sealed. A message written to
  somebody offline is sealed - `send_id` and all - when it is written, then
  waits in the durable queue (§7.1.1) until they return; by then the sender
  has sealed newer things, so the one that waited arrives *after* ids above
  it. A high-water mark reads that as a replay and drops it silently, which
  is the one outcome the queue exists to prevent. Re-injecting a captured
  send still fails, because its id is already marked as taken.

  State is kept per live `UserId` and only for the life of the session -
  deliberately, since a peer who reconnects gets a fresh `UserId` and
  restarts their counter, and keying this by identity instead would reject
  everything they sent after reconnecting.

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

Step 1 needs the *sender's* ML-DSA-87/RSA-sign identity, and every client
has one - `pq_hybrid` is the only `my_key` this protocol has (§3), so
every peer reached through a server can both produce and open a sealed
send. There is no partial-reachability case left here at all.

The one peer that cannot be sealed to is one who announced no keybundle:
a `--no-server` direct-punch peer (§7.1.5) never went through `Identify`,
so there is nothing to seal against. Such a peer is reachable only under
an already-installed one-time pad, framed direct (§16.2), and is silently
excluded from any ordinary channel/DM/file/voice send - the same
partial-delivery pattern as any other unreachable recipient in this app
(an offline member, a not-yet-fresh rotating-key recipient, §11.1/§11.2).

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
file-loaded keybundle would otherwise be something that cannot be used the
moment you open the app for the first time: a blank
`file_pub`/`file_priv` fails the form's validation with no in-app way to
fix it short of quitting, running `aloo --keygen-pq-hybrid` externally,
and reopening the form - real friction for the only `my_key` this app has.
Two pieces close that gap:

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

**Resolving a prefix to that pair** (`crypto::pq::resolve_bundle_paths`),
for the one entry point that names a keybundle by prefix rather than by its
two paths: `aloo --daemon --my-key <prefix>`. Two spellings of the private
half exist on disk in the wild - `aloo --keygen-pq-hybrid <prefix>` writes
the bare `<prefix>`, while anything auto-generated (below) writes
`<prefix>.priv` - so both are accepted, `.priv` winning when both are
present, and a freshly written one takes the documented `<prefix>` form.
This matters more than it looks: a reader that knew only one spelling did
not merely fail to find the other, it reported an *intact* keybundle as
half-present, and the auto-generation above then did exactly what it is
specified to do and regenerated both - destroying the public half and
silently swapping the identity, with no §12.6 continuity certificate for
the contacts who had pinned it.

**Refusing a mismatched pair** (`crypto::pq::bundle_pair_matches`, checked
by `resolve_my_keypair` after loading): two files that both exist are not
necessarily two halves of one bundle, which the "either missing regenerates
both" rule above does not cover. Such an identity has no local symptom - it
signs every send, rotation and identity card with a key no peer holds the
counterpart to - so it is refused at load time rather than connected with.

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

## 14. The two encryption layers, side by side

Everything above describes mechanisms; this is the summary of what a user
actually gets. There is one peer-to-peer method - `pq_hybrid`, matching
`KeyMode`'s (§3) one value - and one optional layer over it, the one-time
pad (§16).

| | **pq-hybrid** | **pq-hybrid + OTP** |
|---|---|---|
| Tag shown | `🛡️ PQH` | `🔑 OTP` (replaces it) |
| Where the key comes from | a keybundle file, auto-generated on first connect (§13.9) | the above, plus a pad both sides hold (§16.1) |
| Message encryption | ML-KEM-1024 + X25519 wrap, AES-256-GCM content (§13.3) | a one-time pad on the message, sealed inside that envelope (§16.2) |
| Signed by the sender? | yes - ML-DSA-87 **and** RSA-4096-PSS, both must verify | yes, plus the pad's own decrypt verdict |
| Post-quantum? | yes, key exchange and signatures both | yes, and the pad layer is information-theoretically secure |
| Identity survives a reconnect? | yes | yes |
| Byte-comparison pinning (§12)? | yes | yes |
| Forward secrecy? | yes (§13.10) | yes, and pad bytes are spent once and gone |
| Recipient/room binding, replay protection? | yes (§13.3) | yes, plus strict pad sequencing (§16.2) |
| Scope | channels and DMs | DMs only (§16.2) |

`pq_hybrid` is post-quantum, signed, bound to its recipient and room,
replay-protected and forward secret all at once, and costs the user
nothing to choose: the keybundle generates itself on first connect
(§13.9).

The one case with no envelope around the pad at all is a peer who
announced no readable keybundle - a `--no-server` direct-punch peer
(§7.1.5), which never went through `Identify`. A pad both sides already
hold still carries that conversation, authenticated by the pad's decrypt
verdict alone (§16.2).

## 15. Sequences

Every flow in one place, for a reader implementing this from scratch.
Details are in the sections referenced.

**Connecting** (§1.3, §4, §5)

```
 client                                        server
   |--- TCP connect --------------------------->|
   |<-- Hello { registration_open, control } ---|   in the clear
   |--- SecureChannel(accept) ----------------->|   in the clear
   |=========== everything below is sealed =====|
   |--- Auth { nickname, password } ------------>|
   |<-- AuthResult { ok, .. } ------------------- |
   |--- Identify { key, key_mode } -------------->|
   |<-- IdentifyResult { ok, you } ---------------|
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

`/otp`, `/new-otp-mail-key`, and `/mail` all refuse locally, before
touching the network or opening any popup, the moment the local `otp`
binary isn't available - checked fresh every time (never cached), so a
binary installed or removed mid-session is reflected immediately rather
than through a stale flag. Nothing about starting or resuming a session,
provisioning a mail key, or composing a mail can require the binary partway
through and only discover its absence there.

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
   |--- OtpPadStart { name, size, key_len, enc_digest, dec_digest } ->|
   |--- StreamKeySetup ---------------------------------------------->|
   |--- OtpPadChunk * n ---------------------------------------------->|
   |--- OtpPadEnd ---------------------------------------------------->|
   |<-- OtpPadVerify { name, accepted, enc_digest, dec_digest } ------|
   |--- OtpPadCommit { name } ---------------------------------------->|
   |<-- OtpPadCommitAck { name } -------------------------------------|

 alice (pad already in place)                                 bob
   |--- OtpSessionRequest { name } -------------------------------->|   ordinary pq_hybrid envelope
   |<-- OtpKeySetupAck { name, accepted, reason } ----------------|   ordinary pq_hybrid envelope
```

The proposals and acknowledgements are carried as ordinary `Envelope`s,
sealed under the ongoing `pq_hybrid` conversation exactly like a text
message - the one-time-pad layer cannot protect the handshake that
establishes it, and does not try to. This is what separates them from
`/endotp`'s notice, which *is* padded (§16.6): `OtpSessionRequest` and
`OtpKeySetupAck` are precisely what decides whether a usable pad exists,
and the side receiving a setup ack has not yet committed the key it would
need to open a padded one. A `Direct` pair never sends either, having
nothing left to agree (§16.2).

The pad's own bytes are the exception, and travel differently for two
reasons. Wrapping each slice in its own envelope costs a signature and a
key exchange per slice - a fixed overhead of several kilobytes that, at the
sizes a pad may reach, comes to more than the pad itself. And the resulting
datagrams were large enough to be fragmented by IP, so losing any one
fragment lost the whole slice, and equipment that discards fragmented UDP
outright discarded the setup entirely - which made provisioning across a
real network path fail far more often than it succeeded, while working
perfectly between two clients on one machine.

So the pad streams the way any other bulk content does: one key exchange
establishes a symmetric key for the transfer, and the bytes follow in
chunks small enough that no datagram is ever fragmented. The two keys are
sent back to back - the peer's encryption half first, then its decryption
half - so the transfer is twice `key_len` and the receiver splits it at
that boundary. Nothing marks the boundary on the wire; it is known in
advance from `OtpPadStart`.

The sender hands over more chunks only while what the link is already
carrying stays under a fixed bound, so a transfer paces itself to whatever
the path actually drains rather than queueing ahead of it. That is what
allows a pad of any size: memory holds one chunk and a bounded queue,
never the pad.

**Neither side installs a pad until both have proven they hold identical
bytes.** A one-time pad carries no integrity check of its own - that is
inherent to the cipher - so two sides whose copies differ by a single byte
produce ciphertext that decodes to plausible-looking garbage, with nothing
anywhere reporting an error. The exchange therefore commits in two phases.
`OtpPadStart` declares a digest of each half up front. The receiver
reassembles to a staging area and checks that it received exactly `2 *
key_len` bytes and that both halves hash to what was declared. Only a pad
the receiver's user has not already agreed to - nothing was proposed and
accepted for this contact beforehand - asks then; one already accepted
when the exchange was first proposed re-verifies on arrival with no
further prompt, including a second (or later) arrival of the very same
pad after a full resend (below) - the decision was already made once, at
the point where declining still saved both sides the whole transfer.
Accepting (whichever way it happened) produces `OtpPadVerify` carrying the
digests the receiver actually computed - it installs nothing. The sender
compares those against its own staged files, and only on a match installs
its own half and sends `OtpPadCommit`; receiving that commit is the sole
authorisation for the receiver to install, and is also what finally
retires the recorded acceptance - there is nothing left to re-verify once
installed. A mismatch at either point ends the attempt with nothing
installed anywhere, rather than leaving a pair that would silently produce
garbage.

Because a commit means the sender has already installed, the receiver can
never end up holding a pad the sender does not - and the receiver's
`OtpPadCommitAck` is what lets the sender stop retrying a commit whose
delivery it cannot otherwise confirm. That retry is durable, exactly like
every other owed thing in this layer: the commit is the one provisioning
payload whose loss splits the pair asymmetrically (the sender provisioned
and active, the receiver holding only staged bytes it was never
authorised to install), so from the moment the sender installs, the
commit is recorded as owed against the contact name and re-sent on every
reconnect until the ack genuinely lands. The receiver answers a repeated
commit idempotently - re-acknowledging one already installed - and finds
its staged pad by the durable contact name the commit itself carries
rather than by the sender's connection-lifetime `UserId`, so a retry
arriving from a fresh connection still completes an install whose staging
was left behind under the dead one.

A commit whose install genuinely fails on the receiver's side (the local
`otp` binary unreachable, a full disk, any other error) leaves the staged
pad exactly in place and sends no acknowledgement at all - never the
"already installed, nothing to do" answer idempotence gives a *repeated*
commit. A retry that found the staged pad already gone here would get that
answer by mistake, telling the sender the exchange fully succeeded while
the receiver genuinely holds nothing for that contact - every message the
sender then sent would fail to decrypt on the receiver's side with nothing
shown for it, indistinguishable from the message never arriving at all.
Leaving the staged bytes untouched on a failed install is what lets the
very next retried commit try the same install again for real, once
whatever kept it from working the first time clears.

Generating a fresh pad is itself gated on the initiating user's explicit
confirmation - shown a plain choice ("generate and share one automatically
over pq_hybrid, or arrange it yourself and place the keys where the local
keychain expects them") before anything is generated or sent. Confirming
then asks for a size (MB per key, 1 to 1,048,576 - that is 1TB per key,
the one-time-pad tool's own documented streaming limit - re-prompting on
anything outside that range rather than guessing), so a fresh pad is never
generated at some fixed size the user didn't choose. No size is refused for being too large to
deliver: there used to be a ceiling here, derived from how many chunks the
link's queue could hold, and the streamed self-pacing transport above
removed the reason for it. What a large size costs is time, and the
initiating side is told the estimate before it commits. Generation streams
its randomness in fixed-size chunks rather than building the whole pad in
memory first, and reports progress as it goes, so the initiating side can
show how far along a large pad is instead of appearing to hang.

**Both slow phases are shown, on both sides.** Generating and transferring
are separately slow - one bounded by how fast this machine produces
randomness, the other by the link's round-trip time - and the second is
invisible without help: the deciding side is not asked to accept until the
whole pad has arrived and both digests match, so on a large pad the gap
between "generating" ending and the invite appearing is the entire
transfer. The progress popup therefore switches from generation to transfer
rather than closing, with its own bar over both halves, and the receiving
side opens the same popup as the pad begins to arrive. That size travels
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

The initiating side writes nothing to its own keychain when it generates a
pad. Both halves - its own and the peer's - are staged on disk, and only
the peer's genuine acceptance moves its half into the keychain. This is
what stops a failed invitation from poisoning the next one: for a
`PqWrapped` pair the contact name is derived from both sides'
fingerprints *and* device ids (§16.1.2), so every attempt between the same
two *devices* produces the identical name, and `otp --add-contact` refuses
to overwrite. An invitation that is refused, unanswered, or interrupted by
the peer going offline therefore leaves nothing behind, and a later `/otp`
from *either* side simply generates a fresh pad.

Because the contact name is derived from the pair, two users who both press
`/otp` before either has answered generate two pads competing for one name,
and only one may ever be adopted - a pair that adopted one each would hold
halves of two different pads, which nothing can tell apart and which would
encrypt to silent garbage. The tie is broken exactly as a simultaneous link
open is (§7.1): the numerically smaller fingerprint's pad wins. Both sides
compare the same two values and reach the same answer with no round trip to
negotiate over, since each has already sent its pad by the time it learns of
the other's. The conceding side drops its own staged pad and answers the
winner's invitation normally; the winning side refuses the pad it receives
with the reason "we both proposed at once - keeping the other pad", which is
what tells the loser to drop it. Accepting any peer's pad likewise retires
whatever this side had staged for that contact, since only one pad can live
under the name.

A pad that has been generated but not yet accepted is *owed* to the peer,
recorded against the contact name (not the connection, which does not
survive a reconnect) so it outlives both a fresh `UserId` and an app
restart. Whenever a direct link to that peer becomes reachable again, the
staged bytes are re-offered unchanged - never regenerated, since two
different pads under one contact name have no integrity check to tell them
apart and would decode to silent garbage. If the peer did receive the pad
and only their acknowledgement was lost, the re-delivery arrives at a side
that already holds the contact, and is answered with a fresh
acknowledgement rather than a second invite popup.

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
end" - given whether the user accepted or rejected, since which button was
pressed says nothing about whether the key exists, and "no" is the natural
answer to an invitation you have no key for. *This* reason the initiator
does act on: its own stale keychain
entry is removed (`otp --remove-contact`) and forgotten locally, and the
same generate-and-share confirmation a first-ever `/otp` would have shown
is offered again - without it, a bare retry would keep proposing the same
already-broken contact forever, and a fresh key generation would be
refused outright by the initiator's own leftover entry (`otp
--add-contact` never overwrites an existing name). Every other rejection
reason - including a genuinely offline/never-provisioned peer's plain
reject - is left alone; this recovery is specifically for the one case
that is otherwise a permanent dead end.

### 16.1.1 A second, independent key for OTP mail: `/new-otp-mail-key`

Everything above provisions the *live* session key - the one `/otp`
proposes and a live send/receive spends. OTP mail (§17) never spends that
key: it has its own, entirely independent one, provisioned the same way
but under `/new-otp-mail-key` instead of `/otp`.

`/new-otp-mail-key` runs through the identical state machine §16.1
describes for the *generate-and-share* case - the same consent popups, the
same streamed transfer and two-phase commit, the same glare resolution -
parameterized only by *purpose* (`OtpPurpose::Live` for `/otp`,
`OtpPurpose::Mail` for `/new-otp-mail-key`). What changes is the keychain
contact name each files its result under: mail's own name is the live
name with a `mail-` prefix (`crypto::otp::contact_name_for_mail`/
`contact_name_for_keys_mail`), which can never collide with a live one,
since a live name is always lowercase hex plus a `-`. Every
keychain-name-keyed structure - `OtpStore`, the pending-setup directory,
every `otp` CLI call - is isolated between the two purposes purely by
that name, with nothing else to change.

**"Already have a key" means something different for each purpose.** For
`/otp`, a key already existing is not the end of it: a live session is a
mutual on/off state that can be paused (`/endotp`) and resumed, so
`/otp` still sends `OtpSessionRequest` to reconfirm/restart it even when
the keychain entry is already there. Mail has no such state at all - a
mail key is either usable or it isn't, and one `check_recipient` call at
compose time (§17.1) already answers that. But that does not mean
`/new-otp-mail-key` has nothing left to do once a key exists: unlike
`/otp`, it never *resumes* - there is no session to resume - so it always
proceeds to the identical fresh-generate confirmation a first-ever request
would, whether or not a mail key already exists. This is deliberate: a mail
key running low is exactly the situation a user runs `/new-otp-mail-key`
in, and an outright refusal would leave no way back except a manual
`/contacts` delete first. The install step is what actually replaces the
old key - both `commit_pending_setup` (the proposing side's own half) and
the streamed pad's receive-side install remove any existing contact under
that name immediately before `otp --add-contact` (which otherwise refuses
to overwrite one outright), so the old key and the new one never coexist
even momentarily. Every install over an existing name also drops whatever
this side still held under the old pad - sealed messages waiting in the
contact's queue, a text held behind an old spend, content staged for an
offer the old pad carried - since none of it can be read under the new
one, and pumping it there would wedge the new pad at position zero before
it carried a single message. A pad-only (`Direct`-framed) mail contact is the one
exception: there is no channel to share a freshly generated pad over
regardless of whether one already exists, so `/new-otp-mail-key` there
still refuses unconditionally, the same as first provisioning it - only a
manual `/contacts` install can ever replace it.

A pair may hold a live key, a mail key, both, or neither, in any
combination; installing, generating, or losing one never touches the
other. A pair's own popups (the generate/accept confirm, the size prompt,
the keygen/transfer spinner) always name which of the two is under way -
"OTP session" or "OTP mail key" - so the two are never visually
confusable mid-handshake.

**Concurrency scope.** Fully isolating every piece of shared provisioning
state per purpose (so a live and a mail handshake with the *same* peer
could run genuinely at once) would be a substantially larger change than
the feature itself needs. Instead, a second provisioning handshake - of
either purpose - with a peer who already has one in flight (a queued
invite from them, or an in-flight incoming/outgoing transfer on this side)
is refused outright, with a plain notice naming the peer. Two different
peers may each provision independently at the same time; only a second
attempt at the *same* peer is refused, and the existing exchange is left
completely untouched by the refusal.

### 16.1.2 Device-qualified naming (`PqWrapped` only)

`crypto::otp::contact_name_for`/`contact_name_for_mail` sort and hash two
`(fingerprint, device_id)` pairs, not two bare fingerprints - each side's
own device id (`SessionState::own_device_id`, always known locally) and
the peer's, resolved from `session.peer_device_ids` once their
`DeviceIdAnnounce` decrypts (§12.7). Both device ids are already known by
the time any `/otp`/`/new-otp-mail-key` handshake can even start (§12.7's
"sent automatically... every time a link reaches `Active`" - strictly
before a user can act on it), so this needs no negotiation: both sides
independently compute the identical name with nothing sent over the wire
for it, exactly as the un-qualified naming this replaces always did.

This makes rule 3 of the device-pinning model - "an OTP-only mismatch
cannot communicate; keys must be exchanged via the existing methods" -
true with **no dedicated gating code at all**: a pad provisioned on device
A names a keychain slot that device B's connection can never derive, so
`contact_name_if_active`/`contact_name_for_sending` simply return nothing
for device B - OTP reads as "not provisioned on this device", and every
existing fallback already handles exactly that (`/contacts`'s red ❌
badges, `/mail`'s hard "no otp mail key" modal, §17.1's
`RecipientCheck::NoMailKey`). Re-provisioning via `/otp`/
`/new-otp-mail-key` (which now names device B's own slot) or manually via
`/contacts` is "the existing methods" the rule refers to.

**This is a breaking naming change from the un-qualified naming that
predates the device-pinning model, with deliberately no migration path**:
a pad provisioned under the old two-fingerprint name is simply not found
under the new device-qualified name and reads as not-provisioned - no
rename-in-place, no legacy-name fallback lookup. Re-provisioning once via
either method above is the only path forward, same as any other genuine
cross-device mismatch.

The unknown-nickname scan (§7.1.5's "who is this" flow,
`session::scan_pinned_keys_for_match`) runs *before* a connection's device
id is confirmed - the scan is literally what confirms it - so it tries,
for each candidate nickname, every one of that nickname's known
device-qualified names (`IdStore::devices_of`, not just one), the same
"try several candidates safely, only a genuine decrypt has any effect"
property the scan already relies on for iterating candidate nicknames.

A `Direct`-framed pair's naming
(`contact_name_for_keys`/`contact_name_for_keys_mail`) is **not**
device-qualified, and does not need to be: a raw pad is a single instance
shared out-of-band between two users, so there is exactly one slot per
raw-key pair regardless of how many devices either side has - two
genuinely distinct devices already pin as two distinct raw keys under the
ordinary additive multi-device flow (§12.1-§12.4), so naming never needs
qualifying here the way `PqWrapped` naming does. §16.2 covers how a
`Direct` pair still gets device-aware treatment, just through a different
mechanism.

### 16.2 Sending under the pad

Once active, a send to that contact goes through the pad, and carries a
`seq` naming its place in this layer's own independent counter for that
contact (unrelated to `send_id`, which the underlying `pq_hybrid` send
still has and still enforces on its own terms):

```
 alice                                              bob
   |--- OtpEnvelope { channel, seq, envelope } -------->|   a fresh nonce rides under the pad
   |<-- OtpDeliveryAck { seq, proof } -------------------|   proof = sha256(that nonce)
```

Alice's next send stays gated until that proof arrives - one message
outstanding at a time, per contact (`OtpStore::pending_unacked_out_seq`).
If bob's own `OtpDeliveryAck` is what gets lost rather than alice's
original send, alice's only recourse is to retry the same ciphertext - and
bob must never answer that retry with silence, or the gate stays shut
forever with nothing left to unstick it. So an arriving message whose `seq`
has already been accepted is checked against the *one* ack bob has
outstanding for this contact (`OtpContactState::last_received_ack` - only
the single most recent accepted message can legitimately reappear this
way, since the gate never allows more than one in flight): a match
re-sends that exact recorded ack, at no further cost - no re-decrypt, no
pad spent - while anything older is a genuinely stale replay and is still
dropped in silence. This is the same shape as a repeated `/endotp` notice
(§16.6), just one step earlier in the chain: there, the *ack* is what gets
recovered and resent; here, it never had a ciphertext of its own to
recover, only the raw `(seq, proof)` pair a plain `OtpDeliveryAck` is built
from - which is exactly what `last_received_ack` durably records.

Every one of these records lives in the per-contact store (`otp_store`,
alongside its content-staging sibling and the OTP mail index), and the
store itself is written the only way a crash cannot corrupt it: to a
`.new` sibling, synced, then renamed over the old file. Truncating in
place would let a kill or a power cut between the truncate and the write
leave an empty store - every counter at zero, no gate armed - and the very
next send would then spend a real pad position under a sequence number the
peer's counter has long passed, while overwriting the previous message's
only recovery copy. With the rename, a crash costs at most the single most
recent mutation, which is exactly the window the write-ahead record below
already reconciles.

The same discipline survives the process itself dying mid-step, on either
side. Every encrypt writes ahead what it is about to be
(`encrypt_intent`), and that write is *checked* before anything is spent:
a record that never reached the disk - a full disk being the realistic way
that happens, since setting it in memory still succeeds - protects
nothing, so the send is refused rather than spending a position nothing
could later account for. Because the receiving counter admits no gaps
(§16.2), a position spent and then lost track of is not a delayed message
but every later message being refused. With the record safely down, a kill
between the tool's encrypt succeeding and
the spend being recorded is reconciled at the next startup: the tool's
own counter says whether anything was spent, and a real orphan is promoted
to an ordinary recorded send that recovery then resends - never silently
leapfrogged by the next message. A kill between a *decrypt* succeeding and
its acceptance being recorded is healed at the moment the sender's retry
is refused: the exact off-by-one between the tool's counter and the
store's identifies the crash shape, and the orphaned plaintext - nonce
included - is recovered whole from the tool's received-side safety copy
and processed as if the decrypt had just happened. A file's or voice
message's *content* spend is held to the same two rules: its named
position is checked against the receiver's counter *before* the assembled
ciphertext is decrypted (a consumed position is re-answered from its
record, a wrong or unnamed one is refused with nothing spent), and a
rejection that turns out to be this side's own crash between the decrypt
and its record is healed from the same received-side copy, streamed
straight to the destination. Consuming the slot then advances the
receiver's expectation and records its `(seq, proof)` exactly like every
other slot; a receiver who restarted after accepting re-registers the
retried transfer from its announcement alone, landing the bytes
generically rather than dropping the retries and wedging the pair. OTP
mail's single decrypt (§17.3) heals through the identical check.

A decrypt that fails for any reason other than the crash shape just
described, or `otp`'s own metadata rejection (a replayed, reordered,
foreign, or corrupted message), is never silently dropped either - the
contact never actually installed on this side's keychain, the `otp`
binary unreachable, or any other error the tool reports all produce the
same kind of visible notice, naming who the message was from and what
went wrong. Silently dropping this class of failure used to be
indistinguishable, from the sender's point of view, from the message
simply never arriving at all.

The *sender's* side of that same window survives a restart too, and for
the same reason nothing here may ever depend on memory alone. A file or
voice offer is a genuine, durable, gated spend the moment it goes out - but
the *content* it announces is staged as plaintext, waiting on the peer's
acceptance, before any of it is padded. That staging is written to disk the
instant the offer leaves (contact name and plaintext path only - never a
`UserId`, for the same reason nothing else here keeps one), not left to
the in-memory bookkeeping that would otherwise be the only record of it.
A restart in that window - before the peer's acceptance ever arrives, or
after an old process already saw it and died before acting on it - is
resolved the next time this side reconnects: the peer is re-resolved fresh
and the exact same acceptance-handling path runs as if a live acceptance
had just arrived, so a peer who already accepted before this side ever
noticed needs to do nothing at all. No pad is ever at risk either way - the
content's own spend only happens once this resolves, exactly as it would
from a live acceptance - and a resumed attempt racing a genuinely
re-delivered acceptance for the same transfer is never queued twice.

**One rule: the pad goes on the payload, and the seal goes around the
pad.**

```
 pqhybrid_otp    seal(pad(payload))
 direct_otp      pad(payload)
```

The same shape for every payload this layer carries - text, a file offer,
a voice offer, and `/endotp`'s notice and its ack (§16.6). A file's and a
voice message's *content* arrives at the same nesting a different way: it
is padded whole in one streaming pass and its chunks are sealed
individually (below).

Sealing outermost is worth two things. A sealed envelope weighs ~6.4KB of
ML-DSA/ML-KEM/RSA regardless of the message, so padding it rather than the
message meant a short chat line spent roughly thirty-five times its own
length of an irreplaceable pad. And the signature is now checked *before*
the pad is touched, so a forgery costs nothing rather than a spend.

What it costs is that the seal's binding (§13.3) becomes the outermost
layer, and would otherwise be the one thing on the wire that names who is
talking to whom. So an OTP send leaves nothing identifying in it:

- **the room** travels under the pad, in a small header ahead of the
  payload, and is checked against where the message arrived only after
  unwrapping - against pad ciphertext no third party can produce. A
  `Direct` pair has no binding at all, so this is where their routing has
  to live regardless; sharing one shape means both framings decode by the
  same path.
- **the recipient's fingerprint** is signed but transmitted zeroed. The
  recipient substitutes their own back before verifying, so a send bound
  to somebody else still fails - on the two signatures rather than on a
  plaintext comparison, which is the check that was doing the work all
  along.
- **`send_id`** stays readable. It nonces the chunk, so the recipient
  needs it before anything can open, and it says no more than the `seq`
  in the same frame already does.

**Two framings.** Whether there is a seal at all depends on one observable
fact: whether the peer announced a keybundle that decodes as a
`PqPublicBundle` (§3).

- **`PqWrapped`** - the ordinary case, and every peer reached through a
  server. The pad ciphertext is sealed to the peer's keybundle. The
  envelope's own signature and the pad's decrypt verdict both apply.
- **`Direct`** - one side or the other has no readable keybundle. In
  practice that is a pair who found each other peer to peer and never
  exchanged identities: no server, a server that never introduced them, or
  one that has since gone away (§7.1.5). There is nothing to seal against,
  so `Envelope.blocks`' single element is the pad ciphertext itself.
  `Envelope` is reused rather than a parallel shape so `content` still
  routes the message identically at the far end.

  Such a pair needs no session handshake either. The handshake exists to
  agree on generating and sharing a pad, and a `Direct` pair by definition
  already holds one - so `/otp` turns the layer on locally and the first
  message goes straight under the pad. Their acknowledgement is the only
  consent a pad-only pair can express, and the only one it needs.

**Every kind of send works under either framing.** Text, a file offer and
a voice offer are each one padded payload, framed as above. A file's
content phase and a voice message's audio stream go as ordinary
`FileChunk`s (§7.6) instead: the content is padded whole before the first
chunk leaves, and the chunks are then sealed to the recipient's keybundle
under `PqWrapped`, or carry the pad ciphertext verbatim under `Direct`.
Either way it is the same nesting - pad innermost, seal outermost -
arrived at by streaming rather than in one piece.

Nothing is given up under `Direct`. Authentication is entirely the
pad's decrypt verdict - a message is accepted only if the pad tool
confirms it was produced by the holder of the mirror key at the expected
offset and is next in sequence - which is a *stronger* statement about who
is speaking than an identity signature would be, since it is tied to the
specific key position rather than merely to a keypair. Both sides read the
same announced key, so they always agree on the framing; one never wraps
while the other expects bare plaintext.

The receiving side only sends `OtpDeliveryAck` once the message has been
fully unwrapped *and* successfully delivered to the local application -
never on receipt alone. The sending side treats that ack, and only that
ack, as proof the message actually reached and was understood by the
other end, and will not encrypt a second message to this contact under
the pad until it has arrived.

**The sender's delivery indicator.** An ordinary message's `->` arrow and
its details popup are driven by the peer's `DeliveryReceipt` (§7.2.1). A
pad-protected one is not: the receipt is unsigned and names only a `msg_id`,
so on this layer the arrow answers to `OtpDeliveryAck` instead, and stays
gray until a *verified* one arrives. The two acknowledgements otherwise
remain distinct statements - the ack additionally releases the pad gate,
which no receipt ever did - so a pad-wrapped text message sends no
`Decrypted` receipt at all; it would only repeat, unprovenly, what the ack
already establishes. A `Consumed` receipt (they played the audio, saved the
file) still travels normally, but on this layer it records only what the
ack has already established rather than implying delivery on its own.

**What makes the ack believable.** A bare `seq` is quotable by anyone who
watched the packet go past, so every pad spend buries a fresh 16-byte
nonce in front of its plaintext, and the acknowledgement carries
`sha256(nonce)` back. Reaching that value requires having actually opened
the message, which requires the mirror pad - so the ack is bound to *this*
message rather than to a number, and an acknowledgement that does not
match the expectation leaves the gate closed (§16.2's queueing simply
continues to hold). The nonce itself is never echoed: that would hand an
observer 16 bytes of known plaintext against known ciphertext, which is 16
bytes of recovered pad. The hash costs the receiver no pad at all, which
is the point - an acknowledgement that spent pad would itself be a message
needing acknowledgement, with no bottom to the recursion.

This is also what bounds an impersonator. Contact selection is bound to
keys rather than nicknames (§16.1), but a peer holding a stolen identity
key still has no pad, and therefore can never produce a matching proof: it
extracts exactly one message before the gate closes for good, and even
that one is not lost - nothing overwrites its `--recover-last --sent` copy
while the gate holds, so it is still deliverable to the genuine contact
afterwards.

For the two spends that carry the user's bytes verbatim - a file's content
phase and a voice message - there is nowhere to bury a nonce without
corrupting what lands on the receiver's disk, so the plaintext's own
`sha256` stands in. It proves the same thing: only a party that decrypted
the content can name it.

None of this varies with framing. The nonce lives at the pad layer, under
whatever is sealed around it, so a `PqWrapped` pair and a `Direct` pair
acknowledge each other identically - and since the pad is innermost either
way, they now spend the same amount of it too. A
message typed while one is still
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
is captured locally first and only then sent, as **exactly the two spends
a file uses** - the offer, then the content.

The offer goes through the pad just as a file's does. That is what keeps
the duration out of the clear: it lives in the payload rather than in the
cleartext `OtpVoiceOffer` tag, and under `Direct` framing there is no
envelope to hide it in, so the pad is the only thing that can. The
recording itself is the second, later spend, encrypted whole only once the
offer has been acknowledged.

The one way it differs from a file is that nobody is asked: a voice
message has no consent prompt, on or off this layer, so the receiving side
stages and accepts in the same step it opens the offer in.

```
 alice                                              bob
   |    (finishes recording; stages the PCM
   |     locally, still plaintext)
   |--- OtpVoiceOffer { stream_id, seq: A, envelope } -->|   envelope: pad-wrapped
   |                                                     |   (bob opens it, reads the duration)
   |<-- OtpDeliveryAck { seq: A, proof } ----------------|   the offer's own slot, closed
   |<-- FileAccept { stream_id } ------------------------|   sent automatically, no popup
   |    (encrypts the whole clip through the
   |     pad, into a local temp file)
   |--- OtpFileContentSeq { stream_id, seq: B } -------->|   names the recording's own slot
   |--- FileChunk { stream_id, seq, blocks } ----------->|   any number, as §7.6
   |--- FileEnd { stream_id } -------------------------->|
   |    (bob decrypts the assembled temp file
   |     whole through the pad, decodes it back
   |     to PCM, and deletes the temp copy)
   |<-- OtpDeliveryAck { seq: B, proof } ----------------|
```

Once decrypted, the recording becomes an ordinary, already-finished voice
message in the peer's log - the same shape a completed live stream would
have left behind - so replaying it (Enter, §7.3) works identically either
way; the only difference this layer makes is that it arrives all at once
once fully received, rather than becoming playable partway through.

It autoplays exactly like a live `pq_hybrid` stream does, too - muted or
trust-gated (`suppress_playback_from`), or simply not the DM currently on
screen (`is_viewing_dm`), and it plays itself the instant it's fully
decrypted; a row that skipped autoplay for any of those reasons still ends
in the same red "not listened" marker until replayed. The only difference
is *when* that decision is made: a live stream decides once at
`StreamStart` and then pushes each chunk to the mixer as it decrypts,
where an OTP voice message has no chunks to gate - the decision is made
once, the moment the whole clip finishes decrypting, and either the entire
thing goes to the mixer at once or none of it does.

### 16.2.1 One conversation end to end: every spend, its acknowledgement, and its retries

Everything above describes the shapes one at a time; this is the timeline
they compose, with the stop-and-wait gate made explicit. One rule
generates every line of it: **a spend closes the gate behind it, and only
its own proof-carrying acknowledgement - which always costs zero pad -
reopens it.** `seq` is one ordered space per direction, shared by text,
both file phases, both voice phases, and the `/endotp` notice alike; the
mirror direction (bob's sends to alice) is the same picture with its own
independent counters and gate.

```
 alice                                                        bob
   |--- OtpEnvelope { seq 0, Text } ------------------------->|  [pad] gate CLOSED behind it
   |      (a second text typed now is QUEUED locally,          |  decrypts, shows, records
   |       spending nothing)                                   |  (seq 0, proof) durably
   |<-- OtpDeliveryAck { seq 0, proof=sha256(nonce) } ----------|  [no pad]
   |      gate OPEN -> the queued text goes out as seq 1        |
   |--- OtpEnvelope { seq 1, Text } ------------------------->|  ...and so on
   |<-- OtpDeliveryAck { seq 1, proof } ------------------------|
   |                                                           |
   |--- OtpFileOffer { stream_id, seq 2 } -------------------->|  [pad: filename+size]
   |<-- OtpDeliveryAck { seq 2, proof } ------------------------|  acked on decrypt, before
   |<-- FileAccept { stream_id } -------------------------------|  the user even decides
   |--- OtpFileContentSeq { stream_id, seq 3 } --------------->|  [no pad] names the next slot
   |--- FileChunk ... FileChunk ------------------------------>|  [pad: the whole file, padded
   |                                                           |   once, streamed as chunks]
   |<-- OtpDeliveryAck { seq 3, proof=sha256(plaintext) } ------|  content has nowhere to bury
   |                                                           |  a nonce; its digest is the
   |                                                           |  proof, and consuming the
   |                                                           |  slot advances bob's
   |                                                           |  expectation like any other
```

A voice message is the same two-spend shape as a file - `OtpVoiceOffer`
(auto-accepted, no popup) then `OtpFileContentSeq` + chunks - and `/endotp`
is simply the next occupant of the same space, drawn in §16.6.

**A duplicate is re-answered from the record, never reprocessed.** The
peer retries a spend only because the acknowledgement this side already
sent was lost; answering again costs nothing, and staying silent would
hold their gate shut forever:

```
 alice                                                        bob
   |--- OtpEnvelope { seq 4, Text } --------------X            |  bob's ack is what got lost
   |          (ack lost in transit)  <------------------------ |  (he decrypted fine)
   |--- OtpEnvelope { seq 4 } (recovered, resent) ------------>|  seq gate: already consumed -
   |                                                           |  the pad is never touched
   |<-- OtpDeliveryAck { seq 4, recorded proof } ---------------|  answered from the durable
   |      gate OPEN                                             |  (seq, proof) record
```

**A reconnect retries by recovery, never by re-encryption.** Whatever
single spend is unacknowledged when the link dies is resent byte-identical
from the tool's own kept ciphertext (`--recover-last --sent`), under the
same `seq`, on every reconnect until its acknowledgement genuinely lands -
re-encrypting would consume a second pad range for a message the peer's
decoder still expects at the first, desyncing the pair for good:

```
 alice                                              bob (offline)
   |--- OtpEnvelope { seq 5 } ---------------X        (never arrives - his
   |                                                   connection handle is dead)
   |        ...bob reconnects, minutes or days later...
   |--- OtpEnvelope { seq 5 } (recovered) ------------------->|  same ciphertext, same seq:
   |<-- OtpDeliveryAck { seq 5, proof } -----------------------|  decodes exactly as the
   |      gate OPEN                                            |  original would have
```

**Even the process dying inside a spend reconciles.** Both windows are
covered (the details in §16.2's prose): a sender killed between the
encrypt and its record finds the write-ahead intent at the next startup,
promotes the orphan, and the recovery above resends it; a receiver killed
between a decrypt and its record recognises the sender's retry by the
exact off-by-one between the tool's counter and the store's, and recovers
the orphaned plaintext - nonce and all - from the tool's received-side
safety copy:

```
 alice (killed mid-send)                                      bob
   |  [encrypt ran; process died before record/send]           |
   |        ...restart: intent + tool one-ahead =>              |
   |           promoted to an ordinary pending send...          |
   |--- OtpEnvelope { seq 6 } (recovered) ------------------->|  indistinguishable from an
   |<-- OtpDeliveryAck { seq 6, proof } -----------------------|  ordinary delayed delivery

 alice                                     bob (killed mid-receive)
   |--- OtpEnvelope { seq 7 } -------------->|  [decrypt ran; process died
   |                                          |   before accept/ack]
   |--- OtpEnvelope { seq 7 } (recovered) --->|  tool refuses (already past it);
   |                                          |  counter off-by-one identifies the
   |                                          |  crash; plaintext recovered from
   |                                          |  --recover-last --received, then
   |                                          |  accepted, shown, and acknowledged
   |<-- OtpDeliveryAck { seq 7, true proof } -|  as if the kill never happened
```

**A file or voice send's *content* phase has one more window of its own,
before either side has spent anything on it.** The offer is a durable
spend the moment it goes out, but the content it names is only staged
plaintext until the peer's acceptance arrives - and that staging, unlike
every spend above, is not itself a pad spend to recover. A restart here is
resolved by resuming the *acceptance*, not the pad:

```
 alice                                     bob (killed awaiting accept)
   |--- OtpVoiceOffer { seq 8 } ------------->|  [pad spent for the offer;
   |<-- OtpDeliveryAck { seq 8, proof } -------|   content staged, not yet
   |--- FileAccept { stream 9 } ---------X    |   encrypted - process dies]
   |            (never processed - the        |
   |             in-memory target is gone)     |
   |                                            |
   |        ...bob reconnects...                |
   |                                    resume_pending_content_sends:
   |                                    the staged record survived on
   |                                    disk; bob re-resolves alice and
   |                                    re-enters accept-handling fresh -
   |                                    alice never has to do anything
   |--- OtpFileContentSeq { stream 9, seq 10 } ->|  content now genuinely
   |--- FileChunk ... ------------------------->|  encrypted, exactly once
   |<-- OtpDeliveryAck { seq 10, proof } --------|
```

### 16.2.2 A `Direct` pair's device claim: cleartext metadata, checked before the pad is touched

A `Direct`-framed (pad-only, serverless or unpinned) pair has no
`pq_hybrid` envelope to seal a `DeviceIdAnnounce` to at all - §12.1's own
"what remains open" boundary extended one step further. There is also no
provisioning handshake to piggyback a negotiation on: a `Direct` pair
sends neither `OtpSessionRequest` nor `OtpKeySetup` (§16.1's own note -
"having nothing left to agree"), since both users placed matching pad
files entirely out of band before ever connecting. So device id instead
rides inside every ordinary message, checked at decrypt time - no separate
negotiation step, and communication starts on the very first message
rather than waiting on one.

Every `P2pPayload::OtpEnvelope`/`OtpFileOffer`/`OtpFileContentSeq`/the
voice-offer variant carries a `sender_device_id` field alongside `channel`/
`seq`, **outside `envelope.blocks` - cleartext wire metadata, never inside
the padded payload.** This is a deliberate, security-critical placement,
not an incidental one: `otp --decrypt` is destructive the instant it runs
- it physically consumes that range of the local pad file whether or not
the caller likes the result - so a check that needs the decrypted payload
to run at all would spend the pad even on a device it then has to refuse.
Putting the claim in cleartext instead is what lets the check run
*strictly before* `unwrap_incoming`/`otp --decrypt` is ever invoked, the
same reasoning `is_next_expected` (a check against purely local counters)
already applies to spending a pad slot at all. This is not a new exposure
for this framing - `Direct`'s own model already sends the sender's
nickname unauthenticated and in the clear over `DirectPing`/`DirectPong`
(§7.1.5) - and device id has never carried any security weight of its own
beyond narrowing (§12.7): a spoofed value can at most cause a legitimate
message to be wrongly *held*, never cause an illegitimate one to be wrongly
*accepted*, since acceptance still rests entirely on the pad decrypt
actually succeeding.

**The gate** (`OtpContactState::bound_peer_device_id`,
`otp::finish_opening_otp_envelope` - the one place every receive path for
this framing funnels through):

- `None` (nothing bound yet) - the claimed device id is provisionally
  accepted and decryption proceeds normally. Only if that decrypt
  genuinely succeeds does the pad actually bind to it
  (`OtpStore::bind_peer_device`) - a bare claim with no successful decrypt
  behind it binds nothing, so a claim from someone with no pad access
  still can't plant a false binding. This is why the *first* message on a
  fresh pad always succeeds regardless of what it claims: there is
  nothing yet to compare against.
- `Some(id)` matching the claim - ordinary decrypt, unchanged; the
  binding is a no-op once already bound to this same device.
- `Some(id)` **not** matching the claim - refused before `otp --decrypt`
  is called at all: no pad byte touched, no offset moved, no ack sent.
  From the sender's side this looks exactly like any other never-acked
  send - the stop-and-wait gate keeps retrying it on every reconnect,
  unchanged, and it decrypts and acks cleanly the moment the device the
  pad is actually bound to is the one that answers, since nothing about
  the pad's position was ever disturbed by the refused attempt. A local
  status notice on the receiving side distinguishes this from an ordinary
  transient failure ("claims a different device than this pad is bound
  to").

A one-time pad has no safe multi-device story - spending the same slot
from two machines desyncs both sides' offsets and produces silent garbage
for both - which is exactly why this is a hard, exclusive *binding*, in
deliberate contrast to the identity pin's own additive, multi-device
model (§12.1-§12.4): the pin answers "is this really who I think", the
pad binding answers "is this pad still safe to spend from here", and they
protect different things. The identity pin for a `Direct`-framed nickname
still gets the full additive, multi-device treatment - a raw pinned key
showing up from an inconsistent device still runs the ordinary
review flow (someone's raw pairing key really can be copied to a second
machine, even though the *pad* built from it can't safely be spent from
both) - fed by this same claim, now cryptographically meaningful, since it
only ever arrives bundled with a genuine successful decrypt rather than a
bare, self-reported announce.

**`direct_punch_to` addresses one device at a time; the claim confirms it,
never discovers it.** These are different questions. If a nickname has
several devices, each with its own independently-generated raw pairing
key (the ordinary case, §12.1), `direct_punch_to=<nickname>[+<device_id>],
<host>[:<port>],<frequency>` (§7.1.5) names which one a given line
addresses - an optional suffix on the nickname field, split at the first
`+`. An unsuffixed line is unaffected by this syntax existing at all and
keeps resolving to whichever device `IdStore`'s ordinary most-recently-
seen default names, exactly as before; two lines for the same nickname but
different devices produce genuinely distinct synthetic `UserId`s
(`p2p::direct_peer_id` folds the device id into its hash, only when one is
given), distinct links, and - since the two devices' raw keys already
differ - distinct pads. `PunchDatagram` itself carries no device id (a
wire-format change this deliberately avoids), so an incoming
`DirectPing`/`DirectPong` naming a shared nickname is disambiguated by the
address it actually arrived from against each candidate line's own
resolved address; an ambiguous claim that cannot be resolved this way is
dropped rather than guessed at. Once a link is up, this section's claim
does the job it was actually designed for - confirming the address already
chosen is still being answered by that same device - rather than trying to
discover or arbitrate between a peer's several devices, which is entirely
a `direct_punch_to` configuration question.

### 16.3 Session visibility in the DM log

Every error/confirmation this layer shows (§16.1's "started"/"cancelled",
§16.2's queued-message notice, §16.6's "ended" notices, any of the failure
paths above) is shown two ways at once, not just as the small top-right
status notice: the same text is also logged as a line in the relevant
peer's own DM room, marking it unread exactly like any other arrival if
that room isn't the one currently open. The notice itself clears; the
room's own history of how its session got set up (or ended, or why it
didn't) does not.

The compose bar carries a 🔑 prefix for exactly as long as a mutual-consent
session is genuinely active with that DM's peer (§16.1's "started" moment,
on either side, through to §16.6's "ended" moment, on whichever side ends
it) - live state, so it appears and disappears with the session itself and
is unaffected by either side disconnecting and reconnecting in between.

A logged message's own 🔑 prefix is a different, permanent fact about that
one message rather than a reflection of the bar above it: it is decided
once, when the message is sent or received, from what actually protected
it (`MessageCrypto::Otp`, captured alongside the row itself), never from
whether a session happens to be active right now. A message sent while the
pad layer was on keeps its prefix in the log forever, `/endotp` included -
ending the session changes nothing about how that message was already
encrypted. The app's own lines about the session (never a real message)
are never given the prefix, session active or not.

"Decided once" is deliberately not "decided when the row is first shown":
a sender's own outgoing row is logged the instant Enter is pressed, on the
UI thread, from whatever the session-active toggle reads at that exact
moment - but the send itself is only genuinely decided and performed later,
once the queued action reaches the session task and re-checks that same
toggle independently. A session starting or ending in the gap between
those two moments - bounded by however long the peer's confirmation takes
to round-trip back, which loopback makes negligible and a real network
does not - would otherwise leave the row's own prefix disagreeing with
what it actually sent under. The send path corrects the row to the scheme
it genuinely used the moment it decides it, for both directions: logged
before a session activates but actually sent under the pad once it has,
or logged while active but actually sent plain once the session has ended
first.

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

### 16.6 Ending a session: /endotp

A mutual-consent session, once started (§16.1), stays active indefinitely -
neither participant's connection dropping, nor either side's app
restarting, ends it on its own. It ends only when one of the two
participants deliberately runs `/endotp` against that contact's private
room. Unlike starting a session, ending one needs no round trip to agree:
either side may do it alone, and the far side is *told*, not asked.

```
 alice (has decided to end it)                                bob
   |   pauses her own copy of the pad - the keychain
   |   entry, its sequence counters, and any send still
   |   awaiting acknowledgement are left exactly as they
   |   are; only a pad still owed to bob from an
   |   unfinished setup is abandoned, and the contact
   |   stops being active
   |--- OtpEndSession { contact_name } ----------------------------->|   under the pad, as OtpEnvelope
   |                                                                  |   bob does the same local
   |                                                                  |   pause on his side
   |<-- OtpDeliveryAck { seq, proof } ----------------------------------|   the ordinary proof-carrying ack
```

**The notice travels under the pad as an ordinary stop-and-wait send** -
framed by §16.2's single rule (`seal(pad(payload))` for a `PqWrapped`
pair, `pad(payload)` for a `Direct` one), carried by `OtpEnvelope`,
closing the gate behind it, recoverable-never-re-encrypted while
unacknowledged, and confirmed by the same proof-carrying `OtpDeliveryAck`
(§16.2) every message earns. Ending a session is something said to this
contact, so it is said - and, crucially, *sequenced* - the same way
everything else is; spending a little pad to say it is deliberate. For a
`Direct` pair it is also the only shape that can carry it at all, there
being no envelope to seal it into. An earlier design gave the notice its
own parallel machinery - a dedicated padded `OtpEndSessionAck`, a sequence
number taken *without* arming the gate, retries that re-encrypted - and
every piece of that specialness was a desync in waiting: a re-encrypted
retry spent a second pad range for a message the peer's decoder was still
expecting at the first; the un-gated notice could overwrite an in-flight
message's `--recover-last` safety copy (the tool keeps exactly one per
contact) or leapfrog it on the pad; and the ack, itself an unconfirmable
pad spend, could be overwritten or leapfrogged the same way on the other
side. As an ordinary send, all of that is impossible by construction: at
most one ciphertext per contact is ever outstanding, in either direction.

Unlike the two provisioning payloads (§16.1), the notice has no bootstrap
problem to solve: a session that can be ended is by definition one whose
pad both sides already hold. The one case that cannot be padded - a
contact whose pad is gone or was never usable - falls back to an ordinary
sealed `Envelope`, which needs a keybundle and so exists only for a
`PqWrapped` pair; having spent no pad, it is confirmed by a sealed,
unpadded `OtpEndSessionAck` (the one place that payload still exists)
rather than a pad proof, and retried by fresh re-encoding, which for an
unpadded envelope costs nothing.

A notice that arrives twice - its first ack having been lost - is answered
exactly like any other repeated message (§16.2): from the durable
`(seq, proof)` record its acceptance left behind, at no pad cost and with
no re-decrypt. Nothing about a duplicate notice is special any more.

**Ending is two-phase: nothing takes effect anywhere until the peer's
confirmation lands.** `/endotp` *requests* the end - recorded durably, so a
crash or link drop mid-handshake still finishes it on the next reconnect -
and the initiator's side stays fully in the session until the peer's
proof-carrying acknowledgement of the notice arrives. That acknowledgement
is the single point the end becomes effective: the receiving side pauses
the moment the notice lands, the initiating side pauses the moment the
confirmation lands, and so the two sides always leave the session
together - never one paused while the other unknowingly keeps spending the
pad at it. In the window between request and confirmation, a new send to
that contact is refused out loud ("the session is ending - waiting for
their confirmation"), never queued behind the very notice ending things
and never silently rerouted; a repeat `/endotp` reports the end already in
flight; and `/otp` cancels the pending end for a user who changes their
mind. The confirmed pause abandons only a pad still owed to the peer from
an unfinished `OtpKeySetup` (§16.1) - never installed anywhere, so
dropping it costs nothing. The keychain entry itself, both sequence
counters (`EncryptedSequence`/`DecryptedSequence`,
`EncryptionKeyOffset`/`DecryptionKeyOffset` - §16.1), *and any send still
awaiting its acknowledgement* are deliberately left untouched: `/endotp`
pauses a session, it does not destroy the pad - and an in-flight message's
pad was already spent, so the peer's decoder is waiting on exactly that
ciphertext; abandoning it would leave them permanently unable to decrypt
anything this side says afterwards, the notice included. When such a send
is outstanding at `/endotp` time, the notice itself is *deferred*: the end
is recorded as owed but spends nothing, the in-flight message keeps both
its recovery copy and its place on the pad, and the moment its genuine ack
arrives - immediately, or on a reconnect days later - the notice goes out
as the gate's next occupant. A later `/otp` against the same peer finds
the existing keychain entry still there and proposes resuming it via
`OtpSessionRequest` (§16.1), the identical pad picking up exactly where it
left off rather than a new one being generated. A status notice announces
"ending session - waiting for them to confirm" the moment `/endotp` is
accepted, and "OTP session ended - confirmed by them" the moment it
completes (§16.3).

`/endotp` is refused - out loud, nothing sent or torn down - in four
cases: there is no *active* session with that peer (merely provisioned, or
already paused, is nothing to end); the peer is currently offline, since
an end they cannot confirm would leave the two sides out of step - the
very thing the two-phase design exists to prevent - so the user is asked
to try again when they are back; an end handshake is already in flight (a
second `/endotp` has nothing to add, and re-running the send step would
spend pad on a duplicate notice); or an OTP mail (§17) to that exact
contact is still waiting on the pad's stop-and-wait gate (the contact's
pending send names a mail, not a live P2P one). The mail case matters
because a mail's upload acknowledgement arrives from the *server*, on its
own schedule, and ending mid-flight would interleave two different
confirmation authorities over one gate. A live in-flight send (a P2P text,
file offer, file content, or voice spend) never blocks `/endotp` - it
defers the notice behind itself instead, as above, and both are delivered
in order.

**The receiving side never gets a say.** `OtpEndSession` is not a
proposal; there is nothing to accept or reject, only to converge to. On
receipt, the same local pause runs - the contact stops being active, any
owed setup is abandoned, and the keychain entry, sequence counters, and
this side's *own* in-flight send (if any) are left alone - and a status
notice/DM-room line announce "OTP session ended by &lt;name&gt;". The
proof-carrying `OtpDeliveryAck` goes back the moment the notice decrypts,
exactly as for a message - it costs the receiving side no pad, so nothing
of its own that might still be in flight is disturbed by answering.

**The notice is retried until it is genuinely heard, however long that
takes** - the same durability §16.1 already gives a pad invitation still
owed to a peer. `/endotp` only *starts* with the peer online, but they can
still vanish inside the handshake window - after the notice went out,
before their confirmation landed - so the end request is recorded as owed
against the contact name (not the connection, which does not survive a
reconnect), persisted to the same on-disk store every other per-contact
OTP record lives in. Every time
a direct link to that peer next becomes reachable - a reconnect, a link
flap, this app's own restart once the link comes back up - the notice is
re-driven: already encrypted, it is recovered and resent by the same
`--recover-last` pass every unacknowledged spend takes (§16.2's recovery
rule - never a second encrypt, which would consume a second pad range for
a message the peer's decoder was still expecting at the first, breaking
their very first decrypt of the retry with the tool's "no valid metadata"
refusal); still deferred behind an in-flight message, it simply waits -
that message is what the recovery pass resends, and its ack is what sends
the notice; deferred with nothing in flight any more (the gate cleared but
the app restarted, or the link died in the same breath as the ack), it is
encrypted fresh, which is safe exactly because no notice ciphertext exists
yet and nothing is ahead of it. Only the notice's own proof-carrying
acknowledgement clears the debt; a link transition with nothing
acknowledged yet simply retries again next time.

```
 alice runs /endotp; bob drops before confirming                 bob
   |   end requested; alice's side stays in the
   |   session until bob confirms - the notice (or
   |   the message it is deferred behind) is orphaned
   |
   |   ...bob reconnects, sometime later...
   |--- OtpEnvelope { seq, OtpEndSession } ---------------------------->|   the same ciphertext, recovered
   |                                                                      |   bob pauses his own side
   |                                                                      |   right away, and acknowledges
   |<-- OtpDeliveryAck { seq, proof } --------------------------------------|
```

**A session's own liveness is independent of the connection carrying it.**
Nothing about a peer's `UserId` changing on reconnect (§3) affects whether
their contact is still provisioned - that fact lives entirely in the
fingerprint-derived, contact-name-keyed store (§16.1), which a reconnect
never touches. The one thing that is naturally connection-scoped is which
UI surface currently shows the session as active (the 🔑 prefix and the
key-metadata header, §16.5); that is re-established the moment a peer who
is already provisioned is seen again under a fresh `UserId`, so it never
lags behind the underlying, persistent fact for long. Re-establishing it
that way never moves the view - unlike agreeing a session in the first
place, which opens the room it is with, since that is a thing both people
just asked for.

Ending a session never ends the underlying `pq_hybrid` conversation itself:
the DM room stays open and usable exactly as it was before OTP was ever
turned on for that contact. While the session was active, every send to
that contact rode the pad unconditionally - there was never a way to drop
back to a plain, non-pad-wrapped send in the meantime (§16.2) - but from
the moment it ends, a plain send to them works again immediately. Only the
extra pad layer, and the 🔑 marking it, are gone.

Two more ways a session ends, both automatic rather than a user's own
`/endotp`:

Deleting a contact's OTP key from `/contacts` - the live key alone, a
whole device, or a whole contact - ends any session that key was backing
immediately, the same local effect an incoming `/endotp` from the peer
has: the "active" marker clears and a notice announces it. Without this,
the marker stayed stuck true for the rest of the process - the compose
bar kept showing OTP as protecting the contact, every send kept routing
through the pad and failing at encrypt time against a keychain entry that
no longer existed, `/otp` refused to restart ("already active"), and
`/endotp` itself did not help either, since by then `otp_store` had
already been cleared too and it took the "no active session" branch
without ever touching the marker.

And the mirror case: a message that cannot be decrypted because the
*receiving* side genuinely has no keychain entry for that contact any
more - deleted, or otherwise gone - ends the session there immediately,
the same way, and that side tries to tell the sender directly with a
real, sealed `OtpEndSession` notice, so both sides converge on ended
rather than the sender being left to believe the session is alive while
every message they send here keeps failing to decrypt, forever, with
nothing on their side ever explaining why. That notice needs a readable
`pq_hybrid` identity for the sender to seal it to; a pad-only pair (whose
one and only shared secret was the very pad that is now gone) has no such
channel, and by design no server relay either - for that pairing only the
discovering side converges, and the sender finds out only because her own
sends here now go forever unacknowledged, exactly as an undelivered send
to an unreachable peer already looked, not worse. A decrypt failure with
the contact still genuinely present - a transient `otp`/disk hiccup -
never triggers either of these; only a confirmed-missing contact does.

**Receiving any end-of-session notice also settles this side's own
end-notice bookkeeping for the same contact, if any is outstanding.** A
side can end up with its own `/endotp` still pending (waiting on an
acknowledgement) at the exact moment the peer's notice - a genuine
`/endotp`, or the substitute one above - arrives instead of that
acknowledgement: most notably when the peer discovers their contact is
gone and answers with their own fresh `OtpEndSession` rather than the
`OtpDeliveryAck`/`OtpEndSessionAck` this side's send was actually waiting
for. Without settling it there, `pending_end_notice` and the gate that
side's own notice armed would stay set forever - every further send to
that contact refusing with "the session is ending", and a repeated
`/endotp` reporting "already ending" - even though the UI already shows
the session as over. So the local pause that answers *any* incoming
end-of-session notice clears both: the peer's notice (`clear_end_notice`)
and, if this side had one outstanding for the same contact,
its own send's gate too (only when what is actually pending is the end
notice itself - an ordinary message still in flight for the contact has
its own, unrelated resolution path and is never discarded just because the
session happens to be ending too).

### 16.7 A session ends on both sides once its key is fully spent

A one-time pad's two directions - `EncryptionKey`/`DecryptionKey`, one
consumed by every send, the other by every receive - each run down
independently, and either can reach zero bytes remaining while the other
still holds plenty (in general, the two sides of a real conversation don't
send equally often). Once *both* reach zero, the contact can no longer
encrypt or decrypt a single further byte in either direction.

This never deletes anything. Neither the keychain entry nor aloo's own
per-contact bookkeeping for it is removed just because it emptied out -
only a user's own explicit `/contacts` delete does that, or a later
`/otp`/`/new-otp-mail-key` genuinely replacing it (§16.1.1's
`commit_pending_setup`/streamed-pad-receive install, which already remove
whatever keychain entry is there before installing a fresh one, exhausted
or not - so a later replace works correctly either way, with nothing extra
needed here).

What *does* react, checked right after every genuine live send/receive (a
text, a file's offer or content phase, a voice message) and every mail
encrypt/decrypt: for a live contact whose session was active, the pad
running out can protect nothing further either way, so the session ends
locally on this side immediately - exactly the same local pause discovering
the peer's key is *missing* already triggers (§16.6's "the mirror case",
AC-380) - and this side tries to tell the peer directly too, with the
identical sealed, unpadded `OtpEndSession` and the identical limit: only a
`PqWrapped` pair has a readable identity to seal it to, so a pad-only
pair's key running out converges only on the discovering side, for the
same structural reason its missing-key case does. The notice names both
facts: the key is fully used up, and the session has ended, naming whether
the peer was actually told or could not be reached. A mail key has no
session to end, only the key itself, so its notice says only that the key
is gone and points at `/new-otp-mail-key`. A contact with bytes still left
in only one direction is left entirely alone - only nothing left in
*either* direction triggers any of this - and every contact is keyed by
its own distinct `contact_name`, so exhausting one live session or mail key
never touches a different contact, purpose, or peer: a user with several
live sessions and several mail correspondents open at once sees exactly
one of them affected, never a wider sweep.

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

**The device selector.** A pinned nickname may name more than one device
(§12's per-`(nickname, device_id)` pinning); rather than silently guessing
which one to address, the compose view lists every one of the nickname's
pinned devices in a row below To, each with a check or cross for whether
it carries a mail key, and lets the user pick explicitly with Up/Down.
The default is the most-recently-seen device that actually has a mail
key - falling back to the most-recently-seen device overall only if none
does, so the hard gate below still explains why - and every check
(remaining key, attach budget, Send) runs against whichever device is
currently selected, never an implicit guess. `client::otp_mail::
enumerate_mail_devices` gathers the list once per distinct nickname
(never per keystroke); `check_recipient` itself no longer resolves a
device on its own at all - every call now names one explicitly.

Two preconditions decide whether the selected `(nickname, device)` pair is
writable at all, checked live as the field is typed or the selection
moves:

1. **A pinned device under that nickname** (§12) whose pinned key is a
   `pq_hybrid` bundle - the pin is what the mail's addressing and
   verification anchor to, not the nickname string.
2. **An `otp` keychain contact under mail's own, independent, per-device
   contact name** (§16.1.1 - never the live session's name, even when
   both exist for the same device pair), whose encryption key has **more
   bytes remaining than the whole encoded mail**. The compose view shows
   the remaining key (in MB) and re-derives it continuously as text is
   typed and recordings/attachments are added or removed; an attachment
   that would not fit the remaining key is refused at the moment of
   attaching, and the send path re-measures the real encoded size before
   any pad is spent.

There is no key-material negotiation here: if no mail key exists for the
pair, the answer is `/new-otp-mail-key` (§16.1.1), never `/otp` - a live
session key is never substituted for a missing mail one, no matter how
much of it remains unspent.

**The hard gate.** A recipient with no mail key is not merely shown as
invalid: the entire compose view is blocked outright. A centered, red
modal reads "no otp mail key available for &lt;nickname&gt; - install one
manually from /contacts or exchange one with the user if he is online
using /new-otp-mail-key (requires pinned contact)", rendered over the
compose view still visible underneath. Every key but Escape is absorbed -
typing, attaching, Ctrl+S all do nothing while it is showing - and Escape
closes the modal *and* the whole compose view together, in the one step;
there is no way to edit the recipient in place and continue, since fixing
this means installing or exchanging a key first (`/contacts` - see
docs/SPEC.md "Contacts" - or `/new-otp-mail-key`) and opening a fresh
`/mail` afterward. A recipient whose mail key is ready is never blocked
by this at all.

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
over the size cap, a server disk failure) but not terminal: the mail stays
exactly `AwaitingServerAck` and the gate stays closed on that exact
sequence number, precisely as if nothing had been acknowledged yet. This
used to clear the gate and mark the mail `Failed` outright, on the
reasoning that the pad bytes were spent either way so the contact must not
wedge forever - but that traded a sender-side wedge for a *receiver*-side
one that was both permanent and silent: letting the next mail spend past
the refused one meant the receiver's `next_expected_in_seq` could then
only ever be satisfied by the one ciphertext that never got stored, so
every mail sent after it would sit forever behind a sequence number
nothing could fill. Instead the client retries with the exact same
recovered ciphertext immediately, and again on every later reconnect
(the same `.last_sent` replay the ordinary retry path above already
uses) - durable across a full process restart, since both the mail's own
status and the contact's gate are disk-backed, and the reconnect retry
pass runs at every fresh login, not only a live reconnect. An honest
client validates everything the server would reject *before* encrypting,
so this answer is rare in normal operation; when it does happen, nothing
about it is designed to require a re-key - only a genuinely permanent,
self-inflicted client bug (a malformed id or nickname, which validation
should already have caught) would make the retry loop forever without
ever resolving.

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
   This is also what makes addressing a specific device (§17.1) safe on a
   nickname connected from a *different* one than the mail was sealed for:
   the server has no notion of devices at all (`contact_name` is an opaque
   routing string to it, `StoredMail` carries no `device_id`), so it keeps
   handing the same still-pending mail back out on every future
   `OtpMailFetch`/immediate push, whichever device happens to be
   connected, until the one that actually derives a matching contact name
   connects and genuinely acknowledges it. (The receiver's own side of
   this derivation still resolves the *sender's* device as
   most-recently-seen rather than per-mail - a separate, orthogonal, and
   for now untouched limitation: §17.1's selector lets the sender choose
   which of the *recipient's* devices to address, it does not yet let a
   multi-device sender be disambiguated on receive.)
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
