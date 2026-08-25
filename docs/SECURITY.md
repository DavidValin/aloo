# Security claims

What aloo protects, what it does not, and how much confidence each claim
deserves. Written to be read by someone deciding whether to trust it, and
by anyone reviewing it adversarially — so the gaps are stated as plainly as
the strengths. A security document that only lists what works is marketing.

`docs/PROTOCOL.md` is the normative description; this is the summary of
what that design amounts to.

## The short version

aloo is a peer-to-peer chat client. Message content — text, voice, files —
never passes through a server, not even as ciphertext. Every message is
encrypted for its recipient with post-quantum-hybrid cryptography, and the
keys that unlock past messages are thrown away as conversation continues.

It has **not** been independently reviewed. Everything below is a
description of the design and of what the test suite checks, not the
finding of an audit.

## What is protected

| Property | Status | Where |
|---|---|---|
| Content confidentiality | Yes — ML-KEM-1024 + X25519 key wrap, AES-256-GCM content | §13.3 |
| Content authenticity | Yes — ML-DSA-87 **and** RSA-4096-PSS, both must verify | §13.3/§13.4 |
| Post-quantum key exchange | Yes, every message, category 5 | §13.2 |
| Post-quantum signatures | Yes, every message, category 5 | §13.2 |
| Hybrid hedging | Yes — breaking one primitive alone is never sufficient | §13.1 |
| Forward secrecy | Yes, from the first rotation, bounded by an 8-key window | §13.10 |
| Recipient binding | Yes — a message cannot be re-wrapped for someone else | §13.3 |
| Room binding | Yes — a DM cannot be replayed into a channel | §13.3 |
| Replay protection | Yes, per connection | §13.4 |
| Content never on a server | Yes, by architecture — no relay of last resort | §7.1/§10 |
| Control channel confidentiality | Yes | §1.3 |
| Server persistence | None — nothing survives a restart | §10 |

## What is not protected, and why

**Post-compromise security is partial.** Stealing a `pq_hybrid` keybundle
gets an attacker the *signing* half, which lets them sign rotations and
impersonate that identity indefinitely. Recovering requires generating a
new keybundle and having contacts re-pin it (a continuity certificate makes
that painless, §12.6), not an automatic ratchet. MLS-style group ratcheting
heals from compromise on its own; this does not. This is the largest
remaining gap.

**Forward secrecy starts at the first rotation.** The bootstrap encryption
key lives in the keybundle file, so the very first message of a
relationship — sent before either side has rotated — is recoverable from
that file. Every message after the first rotation is not.

**A first contact is trust-on-first-use.** With no prior pin and no
identity card, there is nothing to check a stranger's identity against.
Safety phrases and identity cards (§12.6) exist to close this, but they
require the user to do something out of band. No protocol can fix this
without an anchor outside itself.

**A mismatch review's address/device id are unauthenticated hints, not
evidence.** The impersonation review popup shows the address and
self-reported device id a new connection announces (§12.7), alongside
what was recorded last time - but a device id is exactly as trustworthy
as a nickname: whoever holds the connection chooses what to send, so a
deliberate impersonator can announce any device id, and an address is
whatever NAT/network they happen to be behind that moment. Neither is
checked against anything; both exist purely to give a human more context
for a decision the key-mismatch signal already forced, not to make that
decision for them.

**The control channel is unauthenticated without a server key.** Under
`--password` or open auth, the control channel is encrypted but a man in
the middle can substitute their own offer. Only RSA auth (§5.3) gives the
client something to verify against. Passive observers are defeated in all
modes; active ones only with a server key.

**The server learns who talks to whom.** It routes by nickname, channel
membership and peer-link requests, so it knows who is online, which
channels exist, who is in them, and which pairs are establishing a direct
link, with timing. It never sees content, filenames, or how much is said
once a link is up. Traffic analysis of the direct links themselves is not
addressed at all.

**No deniability.** Messages are signed, so a recipient can prove to a
third party who sent them. This is a deliberate trade for
authenticity — the opposite choice from OTR-style protocols.

**No offline delivery.** Both parties must be online simultaneously. There
is no store-and-forward and no queue.

**Metadata on disk.** The identity store (`~/.aloo/ids_store`) and the
connect cache record who you have talked to and which servers you use, in
plain text. They are local files with no special protection beyond
filesystem permissions.

**Denial of service is not addressed.** A hostile peer or server can refuse
service, and no rate limiting exists beyond the channel-password
brute-force ban (§6.6).

**The one-time-pad layer (§16) is only as good as its own keychain, and
carries no integrity of its own.** All pad generation, storage and
consumption is delegated entirely to the external `otp` command
(github.com/DavidValin/otp-toolkit) - this codebase contains no independent review
of that tool, and trusts its keychain and crash-recovery behaviour as-is.
A one-time pad provides secrecy, not authenticity: a flipped ciphertext
bit flips the same plaintext bit undetectably at that layer, which is why
this app still runs the message through the signed, authenticated
`pq_hybrid` seal underneath it rather than relying on the pad alone.
Turning the layer on for a contact (`otp --add-contact`, whether via this
app's handshake or done by the user directly) is itself trust-on-first-use
with no independent verification that the pad material received really
came from, and only from, the intended peer - the same limit §12
describes for a first contact, applied a second time to this layer's own
setup message.

**Ending a session (§16.6) is unilateral by design, unlike starting one.**
Either participant may run `/endotp` alone, with no consent from the other
side - deliberately asymmetric with the mutual-accept required to turn the
layer on, since requiring agreement to *stop* using something would let an
unresponsive or hostile peer trap the other side into it indefinitely. The
practical consequence: one participant can always unilaterally end the
extra pad-layer secrecy for a conversation the other party may have wanted
to keep, though never their ability to talk at all - the underlying
`pq_hybrid` conversation is unaffected, and the peer is always told, even
if only once they are next reachable.

**OTP mail (§17) widens what the server sees and stores, not what it can
read.** A mail is the one piece of content the server ever holds: an
opaque pad-sealed blob on its disk, plus the routing metadata beside it -
sender and recipient nickname, the pairwise contact name, a sequence
number, a size, a client-claimed timestamp - which is strictly more
sender/recipient linkage than the live path's "these two are setting up a
link" (§10). Because a bare pad is malleable, the sealed payload carries
its own ML-DSA-87 + RSA-4096 signature under the sender's durable
identity, verified against the *receiver's pin* after decrypt - the
mail-path counterpart of the `pq_hybrid` seal live sends keep underneath
the pad. A received mail is deliberately kept readable at rest as a
(ciphertext, locally-generated pad) file pair under `~/.aloo/otp_mail/`
until the user removes it: anyone with filesystem access to that
directory can XOR the two files together, exactly as they could already
read `~/.aloo/downloads` or the OTP keychain itself - local disk access
remains out of scope (see above). Mail storage is also unbounded on the
server beyond a per-mail size cap: an *authenticated* client can grow the
mail directory at will, the same server-operator-trust boundary the relay
already has - the users registry (§5.1) is the control.

**A running daemon's attach channel is a live handle on the whole session.**
Background mode (`aloo --daemon`, `docs/SPEC.md` "Running in background
mode") leaves a local channel for a terminal to attach through: a Unix
domain socket at `~/.aloo/daemon.sock`, or, on Windows (which has no Unix
domain sockets), a named pipe scoped by username
(`\\.\pipe\aloo-daemon-<user>`). Anyone who can reach it does not merely
read stored secrets the way `~/.aloo/settings` leaks them — they get the
*live* session: every message in it, and the ability to send text, files
and voice as you, to anyone you can reach. Local disk/session access is
already out of scope above, but this is worth stating separately because
it is a strictly larger capability than reading files, and because it
exists only while a daemon is running.

What holds that line is the transport's own access control, and nothing
else — achieved by different means on each platform, since neither Unix
file permissions nor Windows ACLs exist on the other OS:

- **Unix**: the socket is created `0600`, and `connect` refuses one that
  is not owned (by uid) by the user running it. The usual caveats apply
  with more force than usual: another process running as your user, a
  permissive `umask` on a filesystem that ignores the `chmod`, or an
  `ALOO_HOME` pointed somewhere world-writable all defeat it.
- **Windows**: the pipe is created with a DACL (SDDL `D:(A;;GA;;;OW)`)
  granting access to its own creator alone — the OS default for a named
  pipe with no explicit security descriptor instead grants *read* access
  to every local account, which this deliberately overrides — and
  `connect` refuses a pipe whose owning process's token names a different
  user's SID. The closer analogue of the Unix caveats above is a pipe
  name some other, unrelated program claimed first, before this account's
  own daemon ever started; another process already running as your own
  user is an equivalent hole on both platforms.

There is no authentication on the channel itself and no encryption over
it, on either platform. That is a deliberate choice rather than an
omission — a credential would have to be stored somewhere the same local
attacker could read, so it would add ceremony without moving the boundary.
If you do not want that exposure, do not run a daemon; a foreground
client opens no channel at all.

## Assurance: how much of this is checked

**Machine-checked.** Every requirement in `requirements/requirements.toml`
traces to at least one executable test (`cargo trace` fails the build
otherwise). At the time of writing that is 31 user stories, 129 acceptance criteria
and 168 technical behaviours, covered by 180 acceptance scenarios and 571
Rust tests - including real ML-DSA-87 / ML-KEM-1024 / RSA-4096 key
generation in the `cargo slow` set.

**Test vectors.** The constructions aloo defines itself — the key-wrap
combiner, send commitments, chunk nonces, control-channel key derivation,
safety phrases — are pinned by committed known answers, so an independent
implementation can check itself and the wire format cannot drift silently.
They are reproduced in full under "Test vectors" below.

**Robustness.** `test/robustness_test.rs` throws seeded random bytes,
truncations and bit flips at every decode path reachable by a remote peer
or a local file, asserting none of them panics. This found a real remote
denial of service during Phase 6: bincode reserves whatever a length prefix
claims, so a dozen crafted bytes could abort the process on a failed
allocation before any field was read. Fixed by capping the decoder at
`MAX_FRAME_LEN`.

**Primitives.** ML-KEM-1024, ML-DSA-87, AES-256-GCM, HKDF-SHA256, RSA and
X25519 come from the RustCrypto and dalek ecosystems and are tested against
the standard vectors upstream. aloo does not reimplement any of them.

### What is not checked

- **No independent review or audit.** The constructions here are
  conventional in shape, but "looks conventional" is not a security
  argument. This is the single biggest thing missing.
- **No structured fuzzing.** The robustness tests are a seeded
  approximation that runs on every commit; they are not a substitute for
  coverage-guided fuzzing. The targets worth pointing `cargo-fuzz` at are
  `proto::decode`, `crypto::pq::{load_public_bundle, load_private_bundle}`,
  `SendSetup`/`PqRotation` parsing, `IdStore::load`, `IdentityCard`
  parsing, and the ARQ reassembly in `client::p2p_reliable`.
- **No formal analysis.** Nothing here has been modelled in Tamarin,
  ProVerif or anything comparable. MLS, by contrast, has been.
- **No side-channel work.** Constant-time comparison is used for
  credentials (`crypto::constant_time_eq`), but no timing analysis of the
  wider code has been done.

## Test vectors

Known answers for aloo's **own** constructions — the layer built on top of
the standard primitives. An independent implementation that matches these
will interoperate; one that does not will fail in ways that are hard to
diagnose from the outside, because everything still *looks* encrypted.

These deliberately do not restate the NIST FIPS 203/204 vectors for
ML-KEM-1024 and ML-DSA-87. The `ml-kem` and `ml-dsa` crates are tested
against those upstream, and copying them here would prove nothing about
this codebase. What no upstream crate can check is how aloo combines the
two shared secrets, exactly which bytes a signature covers, and how a nonce
is derived — which is what follows.

Every value here is asserted by `test/vectors_test.rs`. If one of those
tests fails, the wire format has changed: possibly on purpose, never by
accident.

All byte strings are lowercase hex.

### Chunk nonce

`chunk_nonce(send_id, seq)` — the AES-256-GCM nonce for one chunk of a
send. `send_id` big-endian (8 bytes), then `seq` big-endian (4 bytes).

| `send_id` | `seq` | nonce |
|---|---|---|
| 0 | 0 | `000000000000000000000000` |
| 1 | 0 | `000000000000000100000000` |
| 0 | 1 | `000000000000000000000001` |
| `0x0102030405060708` | `0x090a0b0c` | `0102030405060708090a0b0c` |
| `u64::MAX` | `u32::MAX` | `ffffffffffffffffffffffff` |

No randomness is involved: a fresh `k_data` per send is what keeps the
nonce unique, not the nonce itself.

### Key-wrap combiner

`hkdf_combine(kem_shared, classical_shared)` =
`HKDF-SHA256(ikm = kem_shared ++ classical_shared, info = "aloo/pq-hybrid/v2/key-wrap")`,
32 bytes out. `classical_shared` is an X25519 exchange (§13.10).

| `kem_shared` | `classical_shared` | wrap key |
|---|---|---|
| `11` × 32 | `22` × 32 | `ae7d19601a44a54105e83a3b82ee0304e308fede5e2e049775fb7d14fab0d7bf` |

The order matters: feeding the same two secrets in the opposite order gives
a different key, which is checked rather than assumed.

### Send commitment

`send_commitment(binding, k_data)` — the exact bytes both the ML-DSA-87 and
the RSA-PSS signature cover for a send.

Layout: `"aloo/pq-hybrid/v2/send"` ++ `bincode(SendBinding)` ++ `k_data`.

For `SendBinding { recipient_fp: aa×32, channel: None, send_id: 1 }` and
`k_data = bb×32`:

```
616c6f6f2f70712d6879627269642f76322f73656e64
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0001
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

Reading the middle: `00` is `Option::None` for `channel`, `01` is the
varint `send_id`. A channel send, a different recipient, or a different
`send_id` each produce different bytes — which is the whole point of the
binding, and is asserted individually.

### Sealed chunk

`seal_chunk(k_data, send_id, seq, plaintext)` — AES-256-GCM under the nonce
above, ciphertext with its 16-byte tag appended.

| `k_data` | `send_id` | `seq` | plaintext | sealed |
|---|---|---|---|---|
| `42` × 32 | 7 | 0 | `hello aloo` | `28a135e1f244540831e19b02cf68cfea51a6350cda3e77bcac8d` |

This is the one fully deterministic end-to-end step of a send, so it is the
best single check of another implementation's AES-GCM wiring.

### Control-channel keys

`derive(secret)` — the two directional keys for the encrypted control
channel (§1.3), both `HKDF-SHA256` over the transported secret:

- client→server: info `"aloo/control/v1/client-to-server"`
- server→client: info `"aloo/control/v1/server-to-client"`

For `secret = 33 × 32`:

| direction | key |
|---|---|
| client→server | `de690a94c27db09c2bf69fcd349863415d873378e39b3ece4c132bdc84a159e4` |
| server→client | `c180b4f467ad13ebe1e47ba832e9e4126bb66f7d356b506dd049918d02d9fe6d` |

They must differ, or a captured frame could be reflected back at its
sender.

### Safety phrases

`safety::phrase(fingerprint)` — the first 8 bytes of an identity
fingerprint, one word per byte, from the 256-word list in
`src/crypto/safety.rs`.

| fingerprint (first 8 bytes) | phrase |
|---|---|
| `00 00 00 00 00 00 00 00` | `acid acid acid acid acid acid acid acid` |
| `00 01 02 03 04 05 06 07` | `acid acorn album alien amber anchor angle apple` |
| `ff ff ff ff ff ff ff ff` | `lattice lattice lattice lattice lattice lattice lattice lattice` |

The word list's order is load-bearing: changing it changes every phrase
this app has ever shown, and would silently invalidate every verification a
user has already done.

## Reporting something

This is not a hosted service; there is no disclosure process to speak of.
If you find something, open an issue or contact the maintainer directly. If
it is serious, say so in the first line and leave the details for a private
channel.
