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
that painless, §12.7), not an automatic ratchet. MLS-style group ratcheting
heals from compromise on its own; this does not. This is the largest
remaining gap.

**Forward secrecy starts at the first rotation.** The bootstrap encryption
key lives in the keybundle file, so the very first message of a
relationship — sent before either side has rotated — is recoverable from
that file. Every message after the first rotation is not.

**A first contact is trust-on-first-use.** With no prior pin and no
identity card, there is nothing to check a stranger's identity against.
Safety phrases and identity cards (§12.7) exist to close this, but they
require the user to do something out of band. No protocol can fix this
without an anchor outside itself.

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
