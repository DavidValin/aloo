# Testing

aloo's suite is organised around an explicit requirement model: every
requirement traces to the test(s) that prove it, and every test traces to the
requirement(s) it proves. A machine-checked gate (`cargo trace`) enforces
that link on every run, so this document and the code cannot silently drift
apart.

## Index

1. [Layout](#layout)
2. [The two test layers](#the-two-test-layers)
3. [Running the tests](#running-the-tests)
4. [The requirement model](#the-requirement-model)
5. [Adding or changing a user story](#adding-or-changing-a-user-story)
6. [Adding or changing a requirement (AC / TB)](#adding-or-changing-a-requirement-ac--tb)
7. [Adding or changing a Gherkin scenario](#adding-or-changing-a-gherkin-scenario)
8. [Linking a test to a requirement](#linking-a-test-to-a-requirement)
9. [What the traceability gate enforces](#what-the-traceability-gate-enforces)
10. [Changing a feature: where to look first](#changing-a-feature-where-to-look-first)
11. [Known coverage gaps](#known-coverage-gaps)
12. [CI](#ci)

## Layout

```
requirements/requirements.toml   what requirements exist: user stories (US),
                                  acceptance criteria (AC), technical
                                  behaviours (TB) — the single source of truth
        │
        ├── features/**/*.feature   Gherkin scenarios, tagged @AC-024 / @TB-051
        │       └── test/cucumber/  cucumber-rs runner + step definitions
        │
        └── test/*_test.rs      Rust tests, marked `/// @requirement TB-051`
        │
        ▼
test/traceability/               cross-checks all three, generates the reports
                                  under target/traceability/
```

| Path | What it is |
| --- | --- |
| `requirements/requirements.toml` | The requirement definitions: 16 user stories, 63 acceptance criteria, 115 technical behaviours, each with an `evidence` line naming where it was reconstructed from. Does **not** list which tests cover what — that link lives with the code. |
| `features/` | Gherkin acceptance scenarios, one directory per story area (`channels/`, `connecting/`, `encryption/`, `help/`, `identity/`, `messaging/`, `presence/`, `voice/`). |
| `test/cucumber/` | The cucumber-rs runner (`main.rs`), the shared `World` (`world.rs`), rendering/keying helpers (`support.rs`), and the step definitions under `steps/` that implement the Given/When/Then lines. |
| `test/traceability/` | The gate itself: reads the three sources above, cross-checks them, and generates `target/traceability/` (`model.rs` builds the in-memory model, `validate.rs` runs the checks, `report.rs` writes the reports, `main.rs` wires it up as `cargo test --test traceability`). |
| `test/` | Ordinary Rust tests, one file per `src` module that has one (`crypto_test.rs` ↔ `src/crypto/`, `ui_test.rs` ↔ `src/client/tui/ui.rs`, etc. — test file names keep the flat module name, not the tier path — see [§10](#changing-a-feature-where-to-look-first)). |

## The two test layers

- **Acceptance** — Gherkin scenarios in `features/`, run by
  [cucumber-rs](https://github.com/cucumber-rs/cucumber) with step definitions
  in `test/cucumber/steps/`. These describe behaviour in the language of
  `docs/SPEC.md`, and are what `cargo bdd` runs.
- **Technical** — ordinary Rust tests under `test/`, including end-to-end
  tests that run the real async server over a loopback TCP socket. The
  client-side modules that need a live socket and an audio device to do
  anything (`connect.rs`, `session.rs`, `channel.rs`, `direct_message.rs`,
  `voice_stream.rs`) have no test file of their own; `test/ui_common.rs` is
  shared scaffolding rather than a test target itself.

Both layers link to `requirements/requirements.toml` — scenarios through
`@AC-024`-style tags, Rust tests through a `/// @requirement AC-024` marker.
`cargo trace` cross-checks them and fails if a requirement has no test, a
test names an id that does not exist, or an id is defined twice.

Deliberate overlap: every acceptance criterion has both a Gherkin scenario
and (usually) a Rust test exercising the same behaviour — the Rust test is
the fast technical check, the scenario states it in the specification's own
language. This is intentional, not duplication to be cleaned up.

## Running the tests

```sh
cargo trace     # requirement traceability gate + reports   (~0.1 s)
cargo bdd       # all Gherkin acceptance scenarios          (~3-5 s)
cargo test      # the whole suite: Rust tests + both of the above  (~15-35 s)
cargo slow      # the #[ignore]d RSA-4096/PQ-hybrid-key tests (~50-70 s)
```

These are aliases defined in `.cargo/config.toml` — shorthand for
`cargo test --test traceability`, `cargo test --test cucumber`, and
`cargo test --test crypto_test --test hybrid_crypto_test --test
connect_test -- --ignored`. `cargo slow` names its targets explicitly
rather than using `cargo test -- --ignored` because the cucumber target
supplies its own runner and rejects libtest flags (see below).

Runtimes assume dependencies have been built once, and are only this quick
because `[profile.dev.package."*"]` in `Cargo.toml` builds dependencies at
`opt-level = 3` — RSA key generation is pure Rust, and unoptimised it makes
the suite roughly sixty times slower.

As of writing: 16 stories, 64 acceptance criteria, 116 technical behaviours,
118 Gherkin scenarios (586 steps), and 341 Rust test functions (of which 12
carry `#[ignore]` — real RSA-4096 key generation, run by `cargo slow`). These
numbers drift as the suite grows; `cargo trace` regenerates the live count in
`target/traceability/traceability-matrix.md`.

### Running part of the suite

`cargo bdd` forwards anything after `--` to cucumber's own CLI. Because
scenarios are tagged with requirement ids, a tag filter reads as *"run
everything that proves this requirement"*:

```sh
cargo bdd -- -t "@AC-030"              # every scenario proving one requirement
cargo bdd -- -t "@US-014"              # everything under one user story
cargo bdd -- -t "@AC-052 or @AC-053"   # tag expressions
cargo bdd -- -n "offline"              # regex against the scenario name
cargo bdd -- -i "features/voice/*.feature"
cargo bdd -- -c 1                      # run serially, for debugging
cargo bdd -- -vv                       # dump the World on a failed step
cargo bdd -- --help                    # everything else
```

A filtered run also skips work it does not need: scenario RSA keys are
generated lazily per name, so a UI-only selection generates none at all.

The Rust layer is ordinary libtest:

```sh
cargo test --test crypto_test                  # one target
cargo test --test crypto_test fingerprint      # substring filter
cargo test --test voice_test -- --list         # what is in a target
cargo test --test ui_test -- --nocapture       # show println! output
```

Note the `--test <target>` in the last two. A bare `cargo test -- <flag>`
passes that flag to *every* target including cucumber, which rejects
libtest's flags — so `cargo test -- --nocapture`, `-- --ignored` and
`-- --list` all fail with `error: unexpected argument`. Either name a
target, or use `cargo slow` for the ignored tests.

### Manual multi-client testing (tmux)

None of the above replaces actually running the app — some behavior
(real UDP hole punching, real audio devices, the full `/otp` mutual-consent
flow) can only be checked by driving two live clients, and tmux (one pane
per client, `cargo run` in each) is the ordinary way to do that on a single
machine before ever involving a second one.

**Give each client its own `ALOO_HOME`.** Every piece of this app's local
state - `id_store`, the connect cache, `settings`, and the OTP layer's own
`otp_store`/`otp/.keychain/` - lives under one directory (`~/.aloo` by
default). Two clients on the same machine otherwise silently share that
directory: harmless for most of those stores, but it corrupts the OTP
layer specifically, since its keychain and per-contact ack-gate state are
each only ever meant to represent one party's own view. This is exactly
how a real, reported bug was first tracked down - a stuck OTP session that
only reproduced with two same-machine clients sharing one `~/.aloo`.

```sh
ALOO_HOME=/tmp/aloo-alice cargo run   # pane 1
ALOO_HOME=/tmp/aloo-bob   cargo run   # pane 2
```

`ALOO_HOME` is also mentioned in the app's own `Ctrl+H` help and in
`README.md`'s local-state section.

### Where the reports are written

Everything lands in **`target/traceability/`**, rewritten on every
`cargo trace` (and by `cargo test`, since the gate is part of the suite):

| File | What it is |
| --- | --- |
| `report.html` | Browsable user story → requirement → test tree, with search and PASS/FAIL/SKIPPED/MISSING filters |
| `traceability-matrix.md` | Requirement coverage table plus a full test index |
| `traceability.json` | The same model, machine-readable |
| `cucumber-results.txt` | Per-scenario outcomes, written by `cargo bdd` |

```sh
cargo trace && xdg-open target/traceability/report.html
```

By default every requirement shows `NOT RUN`, because the gate only reads
source — it cannot see the results of a run it is part of. To fold real
results in, point it at captured test output (`:`-separated):

```sh
cargo bdd
ALOO_TEST_RESULTS=target/traceability/cucumber-results.txt cargo trace

# or, with the full suite, including the ignored tests for a fully green model:
cargo test --no-fail-fast > full.txt 2>&1
cargo slow > ignored.txt 2>&1
ALOO_TEST_RESULTS=full.txt:ignored.txt:target/traceability/cucumber-results.txt cargo trace
```

Any captured `cargo test` output works, including a single target, so you
can also run just the part you are working on. Do **not** add
`--format terse`: it prints one character per test instead of
`test <name> ... ok`, so nothing can be matched back to a requirement and
every requirement stays `NOT RUN`.

## The requirement model

`requirements/requirements.toml` is TOML, with three record types. IDs are
flat and global (`US-xxx`, `AC-xxx`, `TB-xxx`), and are **never renumbered or
reused** — everything else points at them by id, so retire an id rather than
repurpose it.

```toml
[[user_story]]
id = "US-001"
title = "Connect to a server"
as_a = "user starting the client"
i_want = "to say where the server is, who I am, and how my key material is sourced"
so_that = "I can join a conversation on it"

[[user_story.acceptance_criteria]]
id = "AC-001"
description = "The connect form opens with the host field focused and a cursor sitting in it."
evidence = "docs/SPEC.md 'Not connected UI'; test popup_opens_with_the_cursor_focused_in_the_host_box"

[[user_story.technical_behavior]]
id = "TB-001"
description = "..."
evidence = "..."
```

- **User story** — a capability someone wants, not a module and not a
  function. Group by "what does the user want", never by source file.
- **Acceptance criterion (AC)** — observable by a user, an API consumer, or a
  peer implementation reading `docs/PROTOCOL.md`.
- **Technical behaviour (TB)** — an internal invariant the project
  deliberately protects, not directly observable by a user.
- **`evidence`** — required; the gate's own `every_requirement_cites_its_evidence`
  check fails the build on a blank one. Names the spec section, source
  contract, or test the requirement was reconstructed from. A requirement
  with no evidence is an invented one.

**AC vs. TB, when it's not obvious** — judge by the behaviour, not by where
the test happens to live. Precedent from borderline calls made so far:

- Encryption round trips are AC, not "just" `crypto.rs` unit tests: "a
  message can be read only by the person it was sent to" is the product's
  core promise. The OAEP-block-splitting *mechanism* underneath it is TB.
- A wire round trip is AC *only* insofar as `docs/PROTOCOL.md`'s audience
  (someone writing an interoperable client) can observe it — "every message
  survives the trip intact." Per-variant framing detail stays TB.
- The identity review popup's Accept/Reject default is AC despite being a
  purely local UI cue with no wire meaning, because it's on-screen and
  documented as user-facing. Which anchor verified a rotation is TB.
- Deduplicated `UserOffline` is TB: a user only notices their friend went
  grey, never that exactly one message was sent instead of one per shared
  channel.

## Adding or changing a user story

1. Add a `[[user_story]]` block to `requirements/requirements.toml` with the
   next unused `US-` id, a `title`, and `as_a` / `i_want` / `so_that`.
2. Give it at least one acceptance criterion or technical behaviour — the
   gate fails (`story-without-requirements`) on a story with nothing
   executable beneath it.
3. Run `cargo trace`.

## Adding or changing a requirement (AC / TB)

1. Add `[[user_story.acceptance_criteria]]` or `[[user_story.technical_behavior]]`
   under the right story, with a stable new id and a non-empty `evidence`
   line.
2. Link at least one test or scenario to it (see
   [Linking a test to a requirement](#linking-a-test-to-a-requirement)) — the
   gate fails (`requirement-without-test`) otherwise.
3. Run `cargo trace`.

Changing an existing requirement's wording: edit `description` in place: no
separate approval step, but keep `evidence` accurate and keep the id stable
even if the description changes materially.

Prefer naming a tunable constant over hardcoding its current value (e.g.
`TB-164`: *"bounded at `PQ_KEY_RETENTION`"*, not *"bounded at 8"*) — that way a
future change to the constant doesn't also require rewording the
requirement it's mentioned in.

## Adding or changing a Gherkin scenario

Feature files live under `features/<area>/*.feature`, grouped by story area
(`channels/`, `connecting/`, `encryption/`, `help/`, `identity/`,
`messaging/`, `presence/`, `voice/`). A feature-level tag applies to every
scenario in the file (cucumber's own inheritance rule):

```gherkin
@US-003
Feature: Claiming a unique nickname

  As a user joining a server
  I want my chosen nickname to be mine alone while I am connected
  So that other users can tell who they are talking to

  @AC-015 @AC-017
  Scenario: A nickname already in use is refused, and its holder is untouched
    Given a server that anyone may connect to
    And dave has connected
    When someone else tries to connect as "dave"
    Then the nickname is refused, naming "dave"
    And that connection is then closed by the server
    And dave is completely unaffected and can still join "general"
```

To add a scenario: write it in the language of `docs/SPEC.md`/`docs/PROTOCOL.md`,
tag it with the AC/TB id(s) it proves, and either reuse existing step
definitions or add new ones under `test/cucumber/steps/` (one file roughly
per story area: `channels.rs`, `connect.rs`, `encryption.rs`, `identity.rs`,
`messaging.rs`, `presence.rs`, `server.rs`, `voice.rs`, plus `ui_common.rs`
for shared rendering/keying helpers). Run `cargo bdd -- -n "<part of the
scenario name>"` to run just it while iterating.

Steps are many-to-many with requirements: one scenario may prove several
ids, and one id may be proven by several scenarios — don't duplicate a
scenario just to make the mapping one-to-one.

## Linking a test to a requirement

**Rust** — a marker comment directly above the test:

```rust
/// @requirement AC-041, TB-051
#[test]
fn long_message_is_split_into_multiple_blocks_and_reassembled() { /* ... */ }
```

**Gherkin** — tags on the scenario, or on the feature to apply to every
scenario in the file (see example above).

A comment marker rather than a `#[requirement(...)]` attribute is
deliberate: an attribute would need its own proc-macro crate, and a comment
cannot alter test semantics. The cost is that only the gate enforces the
pairing, which is why an unmarked test is *reported* (`test-without-requirement`,
a warning) rather than invisible.

## What the traceability gate enforces

Errors — fail the build:

| Rule | Meaning |
| --- | --- |
| `requirement-without-test` | An AC or TB nothing proves |
| `unknown-requirement-id` | A test or scenario references an id that is not defined |
| `duplicate-requirement-id` | One id defined twice |
| `duplicate-test-id` | Two tests resolving to the same `source::name` |
| `story-without-requirements` | A story with nothing executable under it |

Warnings — reported on every run, do not fail the build:

| Rule | Meaning |
| --- | --- |
| `test-without-requirement` | A test that declares no requirement |
| `acceptance-criterion-without-scenario` | An AC covered only by Rust tests |
| `covered-only-by-ignored-tests` | Covered, but skipped by a default `cargo test` |

Warnings are non-blocking because every current instance is a documented,
accepted trade-off — see [Known coverage gaps](#known-coverage-gaps) — and a
gate that is red for known reasons trains people to ignore it.

## Changing a feature: where to look first

1. **Find the requirement.** Search `requirements/requirements.toml` for the
   behaviour (by keyword, or by id if you already have one from a report or
   a code comment).
2. **Find the scenario(s).** `grep -rl '@AC-030' features/` (or the story's
   own directory) to find the Gherkin coverage.
3. **Find the step definitions.** The scenario's Given/When/Then lines are
   implemented in `test/cucumber/steps/<area>.rs`.
4. **Find the Rust tests.** `grep -rl '@requirement.*AC-030' test/` , or go
   straight to the file matching the `src` module (`src/crypto/` ↔
   `test/crypto_test.rs`, `src/client/tui/ui.rs` ↔ `test/ui_test.rs`, etc. — see
   `test/traceability/model.rs` if the mapping is ever unclear).
5. **Change the implementation** under `src/`.
6. **Update `requirements/requirements.toml`** if the contract itself
   changed (new/changed AC or TB, updated `description`/`evidence`).
7. **Verify**: `cargo trace && cargo bdd && cargo test`.

## Known coverage gaps

Documented behaviour with no automated test, and why:

| Behaviour | Documented in | Why untested |
| --- | --- | --- |
| Per-stream 5-second idle timeout finalising an unterminated voice stream | `docs/PROTOCOL.md` §7.3 | `voice_stream.rs` needs a live socket and audio device |
| Jitter buffer and mixing of simultaneous incoming streams | `docs/SPEC.md` #4 | needs a real output device |
| PulseAudio device preference over raw ALSA on Linux | `docs/SPEC.md` #4 | needs a real device; noted in README "Known limitations" |
| End-of-message chime playing on both send and receive | `docs/SPEC.md` #4 | the decode half is tested; the playback half needs a real output device |
| The bell chime on every decision popup's arrival (identity review, OTP session invite/generate-confirm, file offer, incoming OTP mail) | `docs/SPEC.md` "Identity review popup" | same real-output-device reason as the chime row above; the popup-opening logic each chime sits beside is covered directly at the `UiState` level, and the chime call sites are one-liners in `session.rs`/`client/otp.rs`/`client/otp_mail.rs` immediately after those covered pushes |
| The nickname-rejection flow returning to the popup with fields preserved and focus on nickname | `docs/SPEC.md` #5 | lives inside `run_client_inner`'s loop over a real `Terminal<CrosstermBackend<Stdout>>`; testing it needs a real refactor, not just a new test |
| A trust-gated sender's live voice stream is decrypted/accumulated but never forwarded to the mixer | `docs/PROTOCOL.md` §12.4 | the suppression itself (`voice_stream::spawn_stream_decrypt_worker`'s `suppress_playback` flag) needs a real output device to observe, same as the jitter buffer above; the *held-and-revealed* text/voice-entry side of "hold and reveal" is covered at the `UiState` level (`test/ui_test.rs`'s `accepting_an_identity_review_clears_it_and_reveals_held_messages`/`rejecting_...`) |
| `AcceptIdentity`/`RejectIdentity`'s network-facing side effects (`id_store` persist, queued-send flush) | `docs/PROTOCOL.md` §12.4 | lives in `session.rs::handle_ui_action`, which - like the rest of `session.rs` - has no test file of its own (needs a live socket); the pure `UiState` bookkeeping half (`resolve_identity_accept`/`resolve_identity_reject`) is covered directly |
| AC-094 (server settings persisted to and reloaded from `~/.aloo/settings` across a flag-less restart) | `docs/SPEC.md` "Server startup" | inherently a CLI/process/filesystem behavior (real `--server` flags, a real `$HOME`, a real restart), exercised in `test/main_test.rs` by spawning the compiled binary directly - the cucumber layer's steps all drive in-process `UiState`/`ConnectPopupState`/`Registry` structs and none of them spawn the real binary, so there's no existing seam to reuse instead of adding a new one for a single AC |
| Real cross-NAT UDP hole punching (two clients on genuinely different networks, symmetric NATs, restrictive firewalls) | `docs/PROTOCOL.md` §7.1 | `test/p2p_test.rs`/the cucumber direct-link steps only ever punch over loopback (`127.0.0.1`), which trivially succeeds with no real NAT involved - they prove the protocol mechanics (candidate exchange, `Ping`/`Pong`, reliable delivery, punch-timeout failure), not real-world traversal success rate; that needs manual verification on two actually-separate networks |
| A single transient UDP receive error doesn't end the whole client session (`p2p::spawn_receive_loop` logs and keeps listening rather than exiting its loop) | `src/client/p2p.rs` `spawn_receive_loop` | the actual OS-level trigger (e.g. Windows' well-documented `WSAECONNRESET` delivered to an *unconnected* UDP socket after an ICMP port-unreachable from an earlier `send_to` a candidate nobody answered) doesn't reproduce portably - confirmed on this project's Linux dev environment that an unconnected socket's `recv_from` simply times out rather than erroring after sending to a dead port, so a real regression test would only exercise the platforms it's run on, not the one it's for; the fix (never let one bad datagram end the loop) is defensive regardless of which platform actually triggers it |
| A `pq_hybrid` voice/file chunk staying under `p2p_proto::SAFE_DATAGRAM_BYTES` (TB-148 only covers the RSA-family case) | `docs/PROTOCOL.md` §13.3 | the hybrid scheme repeats a multi-kilobyte `HybridStreamKeySetup` (ML-KEM ciphertext + ML-DSA and RSA signatures) on *every* chunk regardless of plaintext size, so no `CHUNK_INTERVAL`/`FILE_CHUNK_BYTES` choice can bring a `pq_hybrid` chunk under the safe budget - this is a pre-existing property of the §13 wire format that predates the direct peer-to-peer transport, not a regression introduced by it; fixing it for real would mean either fragmenting oversized reliable frames or redesigning §13 to stop repeating the key-setup per chunk, both bigger changes than a chunk-size tweak |
| `session.rs`'s `UserJoined` handler actually calling `ensure_link` the moment a peer is learned about (TB-149) | `docs/PROTOCOL.md` §7.1 "Trigger" | lives in `session::handle_server_message`, which - like the rest of `session.rs` - has no test file of its own (needs a live socket, see the top of this document); the mechanism it relies on (a pre-warmed link failing silently when nothing is pending) is covered directly at the `PeerLinkManager` level by `punch_timeout_with_nothing_pending_fails_silently`, but the wiring that actually calls `ensure_link` from `UserJoined` in production is only exercised indirectly, by the app actually working when manually tested with two clients |
| `session.rs`'s `PeerCandidates` handler actually consulting `shares_a_joined_channel` before calling into `PeerLinkManager` (TB-155) | `docs/PROTOCOL.md` §7.1.2 | same gap as the `UserJoined` row above and for the same reason (`session.rs` needs a live socket); the decision predicate itself is fully covered directly against `UiState` (`shares_a_joined_channel_is_true_for_a_member_of_a_joined_channel`, `_is_false_for_a_stranger`, `_is_false_once_the_channel_is_left`, and the `p2p_trust_boundary.feature` scenarios), but the call site that actually gates on it in production is only exercised indirectly |
| `session.rs`'s `handle_leave`/`UserLeft` call sites actually invoking `PeerLinkManager::forget` once `has_reason_to_keep_link` fails (TB-158) | `docs/PROTOCOL.md` §7.1.3 | same gap as the two rows above and for the same reason; the decision predicate itself is fully covered directly against `UiState` (`has_reason_to_keep_link_is_true_for_a_shared_channel`, `_is_true_for_dm_history`, `_is_false_with_neither`), but the call sites that actually act on it in production are only exercised indirectly |
| File/voice content actually flowing end-to-end under an active OTP session - offer (its own pad spend, AC-148), accept/auto-accept, a second independent content-phase pad spend, chunked transport, whole-content decrypt, and each phase's own resulting ack (AC-146) | `docs/PROTOCOL.md` §16.2 | `client::otp::send_file_offer`/`on_file_offer`/`start_outgoing_file_content`/`finish_incoming_file`/`send_voice_offer`/`on_voice_offer` and their `session.rs` call sites (`accept_file_offer`, `handle_file_event`, `handle_p2p_event`'s `FileAccepted`/`FileRejected`/`OtpFileContentSeq` arms) all take a live `SessionState`/`ControlSink`/spawned worker threads and need a real socket to exercise meaningfully, the same reason the three rows above do; the mechanism each piece relies on *is* covered directly - small-blob `otp --encrypt`/`--decrypt` round-tripping (`a_message_encrypted_by_alice_decrypts_to_the_same_bytes_for_bob`, the same path the offer rides), whole-file `otp --encrypt`/`--decrypt` round-tripping without buffering (`encrypt_file_and_decrypt_file_round_trip_without_buffering_in_memory`), and failing closed on a second encrypt without proof of delivery (`decrypt_file_without_assume_delivered_twice_fails_closed_on_the_second_call`) - so what's untested is specifically the wiring that calls these at the right moments, and in the right order (offer's own ack must close its slot before the content phase may open a second one); verified manually with two clients (large file over an OTP session arrives with the shield prefix and is byte-identical to the source once downloaded; holding Space to an OTP-active peer records silently with no live playback on the peer's end, and the clip appears as one finished, playable entry on both sides after release) |
| A recovery-resend actually firing on `LinkStatusChanged`'s `Active` transition and reaching the right peer (AC-147) | `docs/PROTOCOL.md` §16.4 | `client::otp::recover_and_resend` and its `session.rs` call site (`handle_p2p_event`'s `LinkStatusChanged` arm) need a live link transition to exercise - same live-socket reason as the row above; the mechanism it relies on *is* covered directly - `otp --recover-last` replaying the exact last-sent ciphertext without spending key, both in-memory and file-to-file (`recover_last_sent_replays_without_consuming_key`, `recover_last_file_replays_the_last_sent_ciphertext_without_consuming_key`), the pending-send descriptor round-tripping through the store file (`pending_content_round_trips_through_save_and_load`), and - the property that makes any of this safe to attempt at all - a resend of an already-accepted sequence being rejected before `otp --decrypt` ever runs on it again (`is_next_expected_rejects_a_resend_of_an_already_accepted_sequence`); verify manually by restarting one client mid-conversation, right after a send, before its ack could arrive, and confirming the message resends automatically on reconnect using the recovered ciphertext rather than a fresh encode |
| A nickname freeing on `HEARTBEAT_TIMEOUT` with no clean disconnect (AC-152) | `docs/PROTOCOL.md` §4.1 | proven fast and deterministically at the Rust layer (`heartbeat_timeout_frees_the_nickname_without_a_clean_disconnect`, `ordinary_traffic_resets_the_heartbeat_timeout_clock`) against `server::serve_with_heartbeat_timeout`, a test-only entry point that overrides the real 30s `HEARTBEAT_TIMEOUT` down to tens of milliseconds; the cucumber layer's shared server spawner (`test/cucumber/steps/server.rs` `spawn_server`) always uses the production constant, so a scenario proving the same thing there would have to actually wait out 30 real seconds per run - reused as-is that would push `cargo bdd`'s whole-suite runtime (normally ~3-5s) past what it's meant to stay under, for a mechanism the Rust tests already prove end to end over a real socket |
| The client-side OTP mail orchestration actually running end to end in a live session - `handle_send`'s encrypt-reserve-persist-upload sequence, `resend_pending` firing after the connect-time `OtpMailFetch`, `on_mail_result`/`on_mail_delivered` clearing the shared gate and draining one queued P2P send, and `on_mail_deliver`'s full decrypt/verify/re-pad/ack pipeline (AC-159, AC-160, AC-161, TB-193, TB-194) | `docs/PROTOCOL.md` §17.2-§17.4 | `client::otp_mail`'s handlers and their `session.rs` call sites (`handle_ui_action`'s mail arms, `handle_server_message`'s `OtpMailResult`/`OtpMailDeliver`/`OtpMailDelivered` arms, `run_connected_session`'s fetch-on-connect block) all take a live `SessionState`/`ControlSink`, the same live-socket reason every `session.rs` row above gives; every mechanism each handler composes *is* covered directly - the seal/recover/decrypt round trip against the real binary (`a_mails_last_sent_copy_replays_byte_identically_for_retry` and the 'A retry re-uploads the recovered ciphertext' scenario), the pre-decrypt gate (`mail_gate_*`), the identity signature (`sign_mail_verifies_and_rejects_a_flipped_payload`), both stores' full lifecycles (`otp_mail_store_test.rs`, `server_mail_test.rs`), the server routing over real sockets (the three mail-server scenarios), and the whole compose/confirm surface (`ui_otp_mail_test.rs`) - so what's untested is specifically the wiring that calls these in order from a live session |
| A mail voice attachment actually recording through the accumulate worker into the compose form (`VoiceTarget::MailAttachment` spawning `spawn_record_accumulate_worker`, the `OwnStreamTarget::MailAttachment` done-arm calling `otp_mail_add_voice`) (AC-157) | `docs/PROTOCOL.md` §17.1 | the worker needs a real input device, same as every other recording row here; the key-handling half (Space in the attachments pane producing `VoiceRecordStart(MailAttachment)`/`VoiceRecordStop`) and the budget-refusal half (`otp_mail_add_voice` cancelling an oversized recording) are covered directly at the `UiState` level (`space_in_the_attachments_pane_drives_a_mail_recording`, `a_voice_recording_larger_than_the_remaining_key_is_cancelled`) |

These are candidate requirements, not requirements — adding one means
writing the test first, otherwise the model would claim coverage that
doesn't exist.

## CI

`.github/workflows/tests.yml` runs, in order: `cargo trace` (fails fast on a
broken requirement link), `cargo bdd`, the full `cargo test --no-fail-fast`
(output captured to a file), `cargo slow` (also captured), then
`cargo trace` again with `ALOO_TEST_RESULTS` pointing at both captures so
the uploaded report shows real PASS/FAIL instead of `NOT RUN`. Reports are
uploaded as a build artifact on every run (`if: always()`), and a summary of
the traceability matrix is appended to the job summary.
