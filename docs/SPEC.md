# Application specification

- language: rust
- ui framework: ratatui
- other packages: crossterm, tokio, serde + bincode (v2 — the crates.io `bincode 3.0.0` is a squatted placeholder, not a real release), rsa, rand_core + rand_chacha (RSA key generation needs `rand_core` 0.6's `CryptoRngCore`; deterministic password-derived keys use `rand_chacha`), sha2 (pinned to 0.10 to match `rsa`'s `digest` version), pbkdf2 + hmac, cpal (raw PCM, no opus), clap (CLI parsing), thiserror (error types), sysinfo (cross-platform CPU usage for the header's `CPU:<pct>%` indicator)

This application is a terminal communication tool that supports text / voice channels.
The `main.rs` file acts as the CLI entry point. When run without parameters, it runs the client (with terminal UI).
When run with `--server`, it starts a server instead.

## Files

`src/` is organized in tiers: `server/` (everything server-side), `client/`
(everything client-side, non-UI), `client/tui/` (the terminal UI), and a
handful of genuinely shared modules at the `src/` top level that both the
server and the client compile against (the wire protocol, crypto,
validation rules, settings).

```
src/
src/lib.rs              <-- library root: the module list `main.rs` and the tests build against
src/main.rs             <-- CLI entry point: arg parsing, client/server mode dispatch
src/proto.rs        <-- implements the communication protocol (shared: both sides of the wire)
src/p2p_proto.rs     <-- wire format for the direct P2P link + client<->server UDP rendezvous (shared)
src/validation.rs     <-- channel-name/password rules the client and server must agree on (shared)
src/crypto/            <-- handles encryption / decryption (mod.rs: RSA/AES; pq.rs: PQ-hybrid; otp.rs: one-time-pad layer glue + mail payloads) (shared)
src/settings.rs         <-- ~/.aloo/settings store: client prefs + persisted server bind/port/auth (shared)
src/platform.rs          <-- cross-platform ~/.aloo home-directory resolution (shared)
src/server/mod.rs       <-- the server; contains a simple protocol for operations
src/server/mail.rs       <-- disk-backed OTP mail storage + routing (docs/PROTOCOL.md section 17), Functionality #13
src/client/mod.rs        <-- the `client` module list (no logic of its own)
src/client/connect.rs      <-- client bootstrap: ConnectRequest types, auth + identify handshake, local store loading
src/client/session.rs       <-- the live connected session: event loop, session state, key rotation / identity pinning
src/client/channel.rs        <-- channel-addressed send/receive handling for the session
src/client/direct_message.rs  <-- DM-addressed send/receive handling for the session
src/client/envelope.rs         <-- builds outgoing proto::Envelopes (session-state-free crypto+proto glue)
src/client/keymode_policy.rs    <-- client-side KeyMode policy predicates (addressability, identity pinning)
src/client/voice_stream.rs       <-- live voice streaming plumbing shared by channels and DMs
src/client/voice_call.rs          <-- live, continuous, multi-user voice calls: roster convergence, the capture/decrypt workers, Functionality #14
src/client/file_transfer.rs       <-- consent-gated, streamed file transfer: FileOfferPayload shape, chunking/filename constants, download dir, send/receive workers, Functionality #9
src/client/file_browser.rs   <-- fs-backed directory-listing model with back/forward history (rendering lives in tui/)
src/client/voice.rs           <-- handles capture / live playback (mixer)
src/client/voice_pulse.rs      <-- musl-only PulseAudio backend replacing voice.rs's cpal path
src/client/rekey.rs             <-- freshness/queueing for a peer whose key rotates (currently pq_hybrid only)
src/client/p2p.rs                <-- UDP hole punching and the direct peer link
src/client/p2p_reliable.rs        <-- seq/ack/retransmit state machine for the P2P link
src/client/idstore.rs        <-- identity-pinning store (nickname -> public key), Functionality #8
src/client/otp.rs         <-- one-time-pad layer orchestration over pq_hybrid (docs/PROTOCOL.md section 16)
src/client/otp_cli.rs      <-- async subprocess wrapper around the real `otp` command (the only spawn site)
src/client/otp_store.rs     <-- per-contact OTP ack-gate/sequence state on disk
src/client/otp_mail.rs        <-- OTP mail orchestration: recipient checks, send/retry, deliver/read/delete (docs/PROTOCOL.md section 17), Functionality #13
src/client/otp_mail_store.rs   <-- OTP mail state on disk: sent references + received (ciphertext, pad) blob pairs, Functionality #13
src/client/global_ptt.rs       <-- OS-level global push-to-talk hotkey
src/client/sysstats.rs          <-- CPU usage sampling for the header's CPU:<pct>% indicator
src/client/netstats.rs           <-- connection-speed statistic for the header's Conn:<quality> indicator
src/client/tui/mod.rs            <-- the `tui` module list (no logic of its own)
src/client/tui/terminal.rs        <-- terminal I/O: raw mode + alternate screen setup/restore, blocking input-reader thread
src/client/tui/ui_connect_popup.rs  <-- the connect popup
src/client/tui/ui.rs           <-- the UI once the user is connected: shared state, key handling, log/input rendering
src/client/tui/channel.rs       <-- channel-tab state and rendering (adds `impl UiState` on top of `ui.rs`)
src/client/tui/direct_message.rs <-- private-room (DM) state and rendering (likewise)
src/client/tui/file_send.rs      <-- /file send flow: browse + confirm state and rendering (likewise), Functionality #9
src/client/tui/otp_mail.rs        <-- /mail //mailbox OTP mail surface: compose view, mailbox popup, reader (likewise), Functionality #13
```

The client half is split by *conversation type* on both sides of the network/UI
boundary: `client/channel.rs`/`client/direct_message.rs` handle the wire side
(encrypt, send, apply incoming), `client/tui/channel.rs`/`client/tui/direct_message.rs`
the presentation side. Both pairs are thin layers over shared plumbing
(`client/session.rs`, `client/voice_stream.rs`, `client/tui/ui.rs`) rather than
independent stacks.

Tests live under `./test/`, one file per `src` module that has one (`test/crypto_test.rs` for `src/crypto/`, `test/ui_test.rs` for `src/client/tui/ui.rs`, etc. — test file names keep the flat module name, not the tier path), wired up as explicit `[[test]]` targets in `Cargo.toml`. Two exceptions: the client-side modules that need a live socket and audio device (`main.rs`, `client/connect.rs`, `client/session.rs`, `client/channel.rs`, `client/direct_message.rs`, `client/voice_stream.rs`) have no test file of their own — their testable logic is exercised through `test/server_test.rs`'s end-to-end tests and the UI tests; and `test/ui_common.rs` is shared scaffolding for the three UI test files (included via `#[path] mod ui_common;`), not a `[[test]]` target.

Two further `[[test]]` targets sit alongside the per-module ones and don't follow the one-file-per-module rule, because neither tests a single module:

- `test/cucumber/main.rs` (`harness = false`) — a behaviour-driven acceptance layer running the Gherkin scenarios under `features/` via cucumber-rs, grouped by capability (`channels/`, `connecting/`, `encryption/`, `help/`, `identity/`, `messaging/`, `presence/`, `voice/`) rather than by source file.
- `test/traceability/main.rs` — validates the requirement model in `requirements/requirements.toml` against the suite and generates the traceability report, so the model can't silently drift from the tests it claims are covering it.

## Server startup

The server is started as:

- `aloo --server` — no auth, open to anyone.
- `aloo --server --enc rsa <keyfile>` — server holds an RSA keypair loaded from `<keyfile>`; clients authenticate/encrypt against it.
- `aloo --server --password <MYPASSWORD>` — server checks a single shared password against every connecting client.

Other server flags: `--bind <ADDR>` (default `0.0.0.0`), `--port <PORT>` (default `7878`). The server always seeds one default public channel, `the-hall`, so a freshly started server has something for the first-connected client to join.

Every server start persists its resolved `--bind`/`--port`/auth choice to `~/.aloo/settings` (`server_bind`, `server_port`, `server_auth_type` + its one associated value). Any of `--bind`, `--port`, `--enc`, `--password` given on the command line wins and gets persisted; whichever of these flags is *not* given falls back to what's already in `~/.aloo/settings`. So `aloo --server` alone reuses this machine's last server configuration in full - including auth - and a supervisor that restarts a crashed server with the exact same bare `aloo --server` command comes back up listening the same way, without needing to remember or re-pass the original flags.

## UI

### Not connected UI

A modal is shown, 64 columns wide - clamped to the terminal's own width if it's narrower than that, so this is a target rather than an absolute floor - centered vertically and horizontally, containing the details to connect. Either way it's noticeably wider than the original 50-column box it replaced. Focus defaults to the **host** field the moment the popup opens, with a blinking text cursor at the end of its (initially empty) value — same as every other text field once it's focused (see below).

- **host / ip**, **port**, **nickname** — each its own titled, bordered box (not just a plain label/value line).
  - **nickname** — the display name used in channels and DMs; must be unique among currently connected clients (see Functionality below), capped at 10 characters (typing beyond the limit is a no-op), no whitespace allowed.
- **id_store** — its own titled, bordered box, same as host/port/nickname — the file path for the local identity-pinning store (see Functionality #8 below). Prefilled with `idstore::default_path()`'s result: always `~/.aloo/ids_store` — the app never reads or writes a loose file in the current working directory of its own accord. A plain editable text field — any path is accepted, and it doesn't need to exist yet, so a user who deliberately wants it somewhere else (including a local file) can still type one in.
- **server_key** (2 fields wrapped in a border) — this key is used to authenticate to the server
  - type: `rsa` / `password` / `none`
  - if `rsa`: a file field, selected via the in-TUI file browser
  - if `password`: a text input field for the password
  - if `none`: no additional field
- **my_key** (2 fields wrapped in a border) — this key is used to decrypt messages addressed to the user
  - type: `password` / `none` / `pq_hybrid` (defaults to `pq_hybrid` — this app's strongest identity, quantum-resistant and hedged with classical RSA-4096. Its `file_pub`/`file_priv` fields never start blank: they're prefilled - from `~/.aloo/.cache`'s most-recently-used entry if one exists (`docs/PROTOCOL.md` §13.9's connect-popup cache), or otherwise a freshly-assigned, not-yet-generated location under `~/.aloo/` - and connecting auto-generates the actual keys there if they don't exist yet, so this default never blocks on manual preparation either — see Functionality #10)
  - if `password`: a text input field for the password
  - if `none`: no additional field
  - if `pq_hybrid`: `file_pub` and `file_priv` fields, pointing at a keybundle (prefilled/auto-generated as above, or overridable by hand, including pointing at one `aloo --keygen-pq-hybrid <prefix>` produced externally - there's no `openssl`-equivalent for ML-DSA-87/ML-KEM-1024, but running it yourself is no longer required). See Functionality #10 and `docs/PROTOCOL.md` §13, §13.9.
- **Connect button** — a bordered button below the fields, highlighted when focused. The highlight (solid background) fills only the button's interior; its border keeps its own plain/focus style rather than being swallowed into the highlighted fill, consistent with every other bordered/focusable element in this app. Tab cycles through every field in order and wraps around to this button; pressing Enter while it's focused validates the form and, if valid, connects. Pressing Enter on it with an invalid/incomplete form shows a validation error below instead (e.g. "host is required", "nickname is required").

Every focused text field (host/port/nickname, and a `password`-type `server_key`/`my_key` value) shows a blinking cursor at the end of its current value, not just a reversed-color highlight.

The `my_key` type controls how the user's own key material is sourced/protected locally. Every type but `pq_hybrid` uses an RSA keypair for actual channel/DM encryption — the public-key exchange that happens on joining a channel (see below) always applies; `pq_hybrid` instead uses the hybrid scheme in Functionality #10, including its own ongoing key-rotation behavior for the rest of the session.

**File browser**: a custom in-TUI widget (not an OS dialog) that supports back/forward navigation through directories and file selection. Reused as-is for the `/file` send flow's own browser (`docs/SPEC.md` Functionality below). The visible list scrolls to keep the selected entry on screen, so a directory with more entries than fit in the popup's height can still be navigated all the way to its last entry with Up/Down, not just the ones that happen to fit on first open.

**Nickname rejection**: if the server rejects the nickname as already taken, the client returns to this popup with an error message shown and focus already on the nickname field — every other field (host, port, keys) is preserved, so the user only needs to change the nickname and press Connect again.

### Connected UI

The UI is composed of:

- **Top area** (full width) — tabs with the channels the user has joined (one tab selected at a time), each prefixed with an emoji naming its kind at a glance — 🌍 for public, 🔒 for private — followed right-aligned at the end of the tab row by, in order: a **Conn:`<-|BAD|NORMAL|GOOD>`** indicator, two spaces, a **CPU:`<pct>`%** indicator, two spaces, the **Ctrl+H: Help** hint (Functionality #6). Borderless.
  - **CPU:`<pct>`%** — this client's own system-wide CPU usage, resampled roughly every 300ms. Rendered green below 25%, red at 25% and above.
  - **Conn:`<-|BAD|NORMAL|GOOD>`** — a rough read on how lively the connection feels, resampled once a second from the average gap between the last 1-3 protocol messages actually seen moving over the socket in either direction (there is no ping/pong in the wire protocol, so this is message cadence, not a true round-trip time). `-` (white) before any message has been exchanged yet this session; otherwise `BAD` (red), `NORMAL` (yellow) or `GOOD` (green) by how short that average gap is.
- **Left area / sidebar** (20% wide) — list of users in the selected channel, each shown with an encryption tag next to their name (position depends on `my_key` type — see below; a narrow terminal clips this like any other overlong sidebar entry). Each connected user is coloured by whether messages can actually reach them — that is, by the state of the direct peer-to-peer link to them (`docs/PROTOCOL.md` §7.1.4), not merely by their being connected to the server: **green** once that link is up, **red** once it is lost (it keeps being retried in the background), and **yellow** while it is still being established, which is also how someone is shown before any link to them exists yet. Being present in the channel is not the same as being reachable, and this is where the difference shows. Two states override that colour: a user who has gone offline but is kept listed (Functionality #7) is rendered in soft gray, and a user whose identity hasn't been verified yet, or was explicitly rejected (Functionality #8), is rendered in red regardless of anything else — the most urgent of the three.
- **Identity review popup** — a centered, bordered popup that opens automatically (announced with the same bell chime an incoming file offer plays — every popup that lands asking for a decision chimes: identity review, OTP session invites and generate-confirms, file offers, incoming OTP mail), on top of whatever else is on screen (even the help overlay). Messaging with the mismatched peer is blocked the instant their identity fails to check out (Functionality #8), but the popup itself is briefly withheld — until this specific connection's own address/device id are known, usually a second or two later — so it can show both sides of the comparison instead of just two fingerprints. Names the peer, explains the specific mismatch plus the last-known and new address/device id, and offers two buttons, **Accept** and **Reject** (`Reject` focused by default); `Left`/`Right`/`Tab` move focus between them, `Enter` confirms - no other key does anything while it's open, and there's no Esc-to-dismiss, since the whole point is an explicit decision rather than a wait-and-see banner. If more than one peer's identity is unresolved at once, only the oldest unshown one is displayed; resolving it (either button) reveals the next.
- **Call invite popup** — same shape as the file-offer popup below (centered, chimed, **Accept** focused by default), titled `Voice call incoming from <nickname>` — see Functionality #14.
- **Permanent call indicator** — while on a call, a red bordered box in the top-right corner (just above where the status notice would show) reads `🔴 On a call [in #<channel>] (<n> connected)`, with ` 🔇 muted` appended while muted. Unlike the status notice, it never times out on its own — it's cleared only by leaving the call (Functionality #14).
- **Main area** (80% wide) — messages in the selected channel.
- **Bottom bar** (full width) — text input where the user composes and sends a message; the cursor blinks at the end of the typed text whenever this bar is focused (the default focus on connecting). While viewing a private room whose peer is offline, this bar instead shows `(user offline)` in red and refuses all typing (Functionality #7).

The private-message room (Functionality #3) titles itself the same way: `Private: ` followed by the same tagged-name form.

**OTP session header.** While a mutual-consent OTP session (`docs/PROTOCOL.md` §16) is active with a private room's peer, a 1-line header renders above that room's message log: `OTP SESSION with <nickname> - Receive Key (dec): <Seq> <Offset> <remaining>MB - Send Key (enc): <Seq> <Offset> <remaining>MB`. `OTP SESSION` is highlighted, `<nickname>` is yellow, each direction's `Seq`/`Offset` are grey, and `remaining` is green at or above 0.5MB, red below it. The figures come from the real `otp` command (`otp --show-contact`) and stay live: fetched once immediately when the session starts, again the instant this contact's pad is actually spent by a genuine send or receive in either direction, and roughly once a second besides as a safety net for as long as that room stays open (`docs/PROTOCOL.md` §16.5).

**Encryption tag convention** (`aloo::proto::KeyMode::label`/`format_with_name`) — one of three, based on the `my_key` type that user connected with (see Functionality #10 for `pq_hybrid`'s wire implications):

| `my_key` type | Tag | Position |
| --- | --- | --- |
| `password` | `🚨 PWD` | after the name: `name 🚨 PWD` |
| `none` | `🚨 PLAIN` | after the name: `name 🚨 PLAIN` |
| `pq_hybrid` | `🛡️ PQH` | after the name: `name 🛡️ PQH` |

Every tag is unbracketed and trails the name, reading as an annotation on it - one shared convention across all three `my_key` types. 🚨 flags the two less-durable sourcings (`password`-derived, `none`/auto-generated) that don't carry an identity across separate connections; 🛡️ is `pq_hybrid`'s own icon — a file-backed, durable *identity*, marked as the strongest tier: quantum-resistant signing hedged with RSA-4096, and quantum-resistant key exchange hedged with X25519 whose keys rotate per peer as messages are exchanged, so a stolen keybundle does not open past traffic (`docs/PROTOCOL.md` §13, §13.10). Every tag still means real per-recipient encryption (Functionality #1, #10); the icon is about identity durability, not "unencrypted".

A border wraps the sidebar, the main area, and the bottom bar. Whichever of the three currently holds keyboard focus is highlighted with a yellow border so it's clear where input goes; the bottom bar overrides this with a red border while actively recording a voice message.

**The message log (both the channel view and the private-message room) is scrollable.** While it has focus: `Up`/`Down` move the selection one message at a time, `PageUp`/`PageDown` jump by 10, and `Home`/`End` jump straight to the oldest/newest message — all clamped at the ends of the history rather than wrapping around. Opening a channel or a private room starts scrolled to its newest message; a new incoming or outgoing message pulls the view along with it only if it was already showing the newest message, so scrolling back through history to read isn't interrupted by new traffic arriving.

## Channels

Channels are dynamic:

- **Public channels** are broadcast by the server and appear automatically as tabs for all connected clients — both the initial snapshot at connect time and, live, the moment anyone creates a new one afterward (no reconnect needed).
- **Private channels** are joined by pressing **Ctrl+J**, which opens a popup to type the channel name, choose Public or Private, and — while Private is selected — optionally set a password.

A channel name is limited to letters, digits, and `-`, up to 21 characters (`CHANNEL_NAME_MAX_LEN`) — enforced both as the user types and, independently, by the server. A private channel's optional password is limited to letters, digits, and a documented set of basic symbols, up to 50 characters (`CHANNEL_PASSWORD_MAX_LEN`), likewise enforced on both sides (`docs/PROTOCOL.md` §6.1/§6.5).

When connected, the server sends the list of available (public) channels, which render as top tabs (no border on this tab row); the first tab is selected and immediately joined automatically (no dwell delay for this first, automatic join — the 3-second dwell only applies to later `[`/`]` switches, see Functionality #2).

When a tab is selected, the user joins that channel. The join is broadcast to all users already in the channel, and each of those users sends their public key to the newly joined user, who stores it in memory (used to encrypt messages sent to them). In practice this key exchange is relayed through the server as part of channel membership events (the server already knows every connected client's public key from `Identify`), not a direct peer-to-peer transfer — the server still never decrypts or reads message content, only relays already-public identity metadata.

**Password-protected private channels.** Joining an existing private channel that was created with a password, without supplying one or with the wrong one, opens a dedicated password-entry popup naming the channel — blank for "you need a password", or showing "wrong password" for a retry — letting the user type one and resubmit. More than 7 wrong attempts against one channel from one address bans further attempts against that channel for 2 hours, reported distinctly ("too many attempts") rather than as another wrong-password message (`docs/PROTOCOL.md` §6.5/§6.6).

**Leaving a channel.** Typing `/leave` and pressing Enter leaves whichever channel tab is currently selected (no argument — it's never a different one). Leaving a private channel removes its tab entirely — it was never re-advertised, so there's nothing to reconnect a stale tab to. Leaving a public channel keeps its tab, but selecting it now shows a single centered screen — *"You left this public channel. Do you want to join?"* — instead of the usual sidebar/messages/compose view; pressing Enter there rejoins it. Dwelling on a left channel (`[`/`]`) never silently rejoins it the way a never-joined one does — only that explicit Enter does. Every channel other than the default (`the-hall`) is unregistered from the server the instant its last member leaves it, public or private alike; `the-hall` itself is never removed, even with no members — a client that dwells onto a stale tab for a since-deleted channel simply recreates it fresh (`docs/PROTOCOL.md` §6.2).

## Functionality

1. **Send a text message to the channel.** The message is encrypted separately for each recipient, using that recipient's RSA public key — no AES/hybrid encryption is used. Note: since raw RSA only encrypts small fixed-size blocks (190 bytes of plaintext per block with a 2048-bit key under OAEP/SHA-256 — `256 - 2*32 - 2`, see `crypto::max_chunk_len` and `docs/PROTOCOL.md` §8.1), longer payloads are split into multiple blocks, each encrypted per recipient.

2. **Join a different channel.** Press `]` to move to the next channel or `[` for the previous one; after remaining on that tab for 3 seconds, the user joins it. (Ctrl+J opens a popup to join or create a channel by name — Tab cycles between the name field, a Public/Private selector, and, while Private is selected, an optional password field; Left/Right toggles the selector.)

3. **Send a private message to a user.** Move through the list of users in a channel and press Enter to open a full-screen private room with that user. Press Escape to return to the channel view. Messages exchanged remain in memory for the session. The private room can be reopened by selecting the same user again and pressing Enter.
   - In the channel view, a user is preceded by an envelope emoji once there's at least one message (sent or received) in their private room — not merely because that room was opened; opening an empty DM and leaving it again shows no envelope until an actual message exists. The envelope stays visible (solid) for the rest of the session once earned, whether the messages in it have been read or not, including after the room is reopened and marked read.
   - If there are unread messages from that user, the envelope blinks instead of staying solid; reopening their room (marking it read) stops the blinking but does not remove the envelope, since there's still history.
   - Outgoing DM messages are encrypted with the receiver's public key; incoming DM messages are decrypted with the user's own private key.

4. **Send a voice message** by holding Space (while focus is not on the compose bar - Space there just types a literal space) and releasing it to stop, up to `voice::MAX_RECORDING_SECS` (4 minutes) long. Voice is streamed live, not recorded-then-sent: while Space is held, captured audio is chunked (`voice::CHUNK_INTERVAL`, 15ms) and sent to the network as it's captured, and the receiving side plays each chunk as it arrives, rather than waiting for the whole message. While recording, a 🎤 "recording..." indicator appears inline at the end of the input bar and the bar's border turns red.
   - **Live appearance and finalization.** Both directions show the in-progress message immediately (a pulsing "streaming..." block in the log) and it turns into a normal, replayable voice block only once the stream ends. The user can replay a finished voice message later by scrolling through the channel/DM history and pressing Enter on it, which renders in bold red, marked with a 🔴 and labeled with its actual recorded duration, e.g. `🔴 voice (12sec)` — the duration shown always reflects the real length of that specific message, not a fixed value. Any partial second rounds up (1ms shows as `1sec`, 1001ms as `2sec`), except a genuinely instantaneous 0ms recording, which shows `0sec` rather than rounding up to `1sec`. **While a replay is playing, pressing Escape stops it** immediately, instead of Escape's usual meaning of closing the current private room — Escape reverts to that usual meaning again the moment nothing is being replayed.
   - **Release detection** works on any terminal. At startup the client queries whether the terminal actually supports the Kitty keyboard protocol's release reporting (`crossterm::terminal::supports_keyboard_enhancement`, not just whether enabling it succeeded — a terminal can accept the escape sequence without honoring it). If it does, stopping relies solely on that genuine `Release` event: recording continues through any pause or silence for as long as Space is physically held, and only stops when it's actually released. If it doesn't, there is no way to observe a release directly, so the app falls back to watching for the OS's keyboard auto-repeat (a steady stream of `Press` events roughly every 30-50ms once repeating, after an initial OS repeat-delay commonly in the 500-650ms range) and treats ~900ms of silence since the last one as "released" — an approximation, used only when nothing better is available. Both stopping mechanisms are no-ops when nothing is actually being recorded: a `Release` event with no matching prior `Press` (e.g. one delivered right as a channel switch or DM close ends a recording some other way) does nothing, and so does the idle-timeout check firing with no recording in progress.
   - **Length cap.** A recording that reaches `voice::MAX_RECORDING_SECS` (4 minutes) stops itself automatically — the indicator clears and the end-of-message chime plays, exactly as if Space had just been released, whether or not it's still actually held. This is a client-side courtesy limit on the *sending* side; the receiving side independently enforces the identical cap regardless of what the sender did (`docs/PROTOCOL.md` §7.3) — an incoming stream is force-finalized with whatever arrived once it reaches 4 minutes of audio, so a modified or misbehaving peer can never make a receiver accept, or keep decrypting, a longer one.
   - **Failure handling.** If starting the recorder fails (e.g. no microphone), or if Space is pressed with nowhere to address the stream to (not joined to any channel, no active DM), the indicator clears immediately (or never starts) rather than continuing to claim a recording is happening. The failure reason is tracked internally but deliberately not rendered on screen - this kind of environment tends to surface plenty of transient, self-recovering audio errors (buffer under/overruns, PulseAudio status-query hiccups) that aren't worth interrupting the display for.
   - **Encryption and cost.** Each chunk is encrypted the same way as text (per-recipient RSA, chunked into RSA-OAEP blocks) - live streaming multiplies the message rate, not the total RSA work per second of audio, which is purely a function of bytes-of-audio regardless of chunking.
   - **Jitter and mixing.** On the receiving end, a jitter buffer (a small per-source prebuffer before playback starts) absorbs ordinary arrival jitter between chunks so normal network/CPU timing variance doesn't produce audible gaps; multiple simultaneous incoming streams (two people talking near-simultaneously) are mixed together rather than queued one behind another.
   - **End-of-message chime.** A short "message ended" sound (`assets/end.wav`) plays through the same mixer both when the sender releases Space and when an incoming stream finishes, so both ends of a voice message get the same audible cue. Bundled as WAV rather than the project's original `assets/end.mp3` so it can be decoded (`voice::decode_wav_to_mono`) without an MP3 crate dependency - a WAV's PCM payload is read directly.
   - **Device handling.** Multi-channel input (an input device negotiating stereo-or-more, common even for a physically mono mic) is downmixed to a single mono sample per moment in time as it's captured, before anything else touches it. On Linux, capture/playback prefers a device routed through PulseAudio over whatever the raw ALSA host reports as default, when one is available - the plain ALSA host normally requires each process to have exclusive access to a device, which would otherwise make it impossible for two `aloo` clients on the same machine (the normal way to test a channel/DM locally) to both use the mic/speaker at once.
   - **Global push-to-talk.** A second trigger, bound to **Ctrl+Alt+P** by default, does the same thing as holding Space - starts a live stream to whatever channel/DM was last active and stops it on release - but works even while `aloo` isn't the focused window, so speaking doesn't require switching back to the terminal first. Configurable in `~/.aloo/settings` (created with these defaults on first run if missing): `global_ptt_enabled` (`true`/`false`) and `global_ptt_shortcut` (any combo `global_hotkey::hotkey::HotKey` parses, e.g. `ctrl+alt+p`, `shift+F1`) - an unparseable shortcut falls back to the default with a startup warning rather than failing to start. Space and the global shortcut can never stop a recording the other one started; a global recording is never subject to Space's idle-silence auto-stop guess, since the OS always reports its release for real. Like Space, the end-of-message chime (above) plays only once, on release - there's no visible "recording..." indicator while the app isn't focused, but the chime firing mid-recording on press was found more confusing than helpful and was removed. **Platform support:** Windows and macOS, and Linux under X11 only - Wayland compositors have no equivalent capability at all, so aloo detects this at startup and prints a one-line warning instead of registering (Space still works normally while the app is focused).

5. **Choose a nickname and have it enforced as unique.** The nickname is set in the connect popup (prefilled from the OS username, editable, no whitespace allowed, capped at 10 characters). On connecting, the server rejects the `Identify` request and closes the connection if that nickname is already in use by another currently-connected client; the client then returns to the popup with the error shown, ready to retry with a different nickname. The check is race-free: two simultaneous connection attempts for the same nickname can't both succeed. A nickname is freed again as soon as its holder disconnects — including when the disconnect was never clean (a crash, a lost network, a sleeping laptop): the client sends a heartbeat every 10 seconds, and the server frees the nickname if 30 seconds pass with nothing received from it at all (`docs/PROTOCOL.md` §4.1), so a vanished client is never squatting on a name forever.

6. **In-app help, toggled with Ctrl+H** (Escape closes it too). Works from any view or mode — the channel view, an open private room, mid-recording, even with the join-private-channel popup already open — and takes priority over everything else, since it's checked before any other key handling. A hint (`Ctrl+H: Help`) is shown at the top right of the screen, past the end of the channel tabs, as a reminder that it's always available.
   - Pressing it opens a centered popup covering how to join a hidden (private) channel, how to send a voice message, how to send/receive a file (Functionality #9), what each of the three encryption tags means, and a general keybinding reference — everything in this document's Functionality section, condensed.
   - The popup's content is taller than fits most terminal windows, so it scrolls: `Up`/`Down` move one line, `PageUp`/`PageDown` jump by `HELP_SCROLL_PAGE` lines, and `Home`/`End` jump straight to the top/bottom — clamped so it can't scroll past either end. It always reopens scrolled to the top, never wherever it was left last time.
   - While the popup is open, every other key is absorbed (no typing leaks into the compose bar, no navigation happens underneath) except Ctrl+H itself, which closes it again and returns to exactly whatever was showing before, and the scroll keys above. Esc does not close it — only Ctrl+H does, since Esc already means something else (close the current private room) when help isn't open, and the popup deliberately doesn't try to disambiguate the two.

7. **Offline users.** When a user's connection closes entirely (as opposed to them leaving one channel while staying connected elsewhere — Functionality #2), every peer who shared a channel with them is notified (`docs/PROTOCOL.md` §6.4). What each peer's client does with that depends on whether it has private-message history with the now-offline user:
   - **With at least one message (sent or received) in that user's private room:** they're kept listed in every channel they'd joined, rather than removed, with their name rendered in soft gray instead of their usual direct-link colour (see "Connected UI" above) — so their history stays reachable (reopen their private room the same way as any other user, Functionality #3) without pretending they're still around.
   - **With no private-message history:** they're removed from the channel's user list exactly as if they'd explicitly left it (Functionality #2) — there's nothing to keep them around for.
   - **Opening (or already having open) an offline user's private room** replaces the compose bar's contents with `(user offline)` in red, and the compose bar stops accepting keystrokes entirely — no typing, no sending — for as long as that user stays offline. This applies regardless of whether they were kept listed in any channel, since it's driven by "is this specific peer offline right now", not by the retention rule above. This is scoped to that one peer's room only, not a global switch: the channel compose bar and any other, still-online peer's private room keep working normally the whole time, including one reopened for a peer who went offline earlier and is back.
   - **Voice recording (Functionality #4) ignores an offline direct-message target.** Holding Space while viewing an offline user's private room does nothing — no recorder is started, nothing is sent — the same as pressing Space with no channel joined and no private room open. A channel voice recording is unaffected by one of its members being offline: it's simply excluded from that recording's recipients, same as any other member the sender doesn't currently have a way to reach.
   - A user going offline is permanent for the rest of the session from every other client's point of view — a `UserId` is never reassigned (`docs/PROTOCOL.md` §3), so the same person reconnecting is always a brand new identity, never a transition back to "online" for the old one.
   - Going offline also logs a yellow presence notice — see Functionality #12.

8. **Identity pinning (`id_store`): deciding whether to trust a nickname that reconnects under a different key.** Full model in `docs/PROTOCOL.md` §12; from the user's point of view:
   - The client keeps a small local file — set via the connect popup's `id_store` field — that remembers each nickname's **full public key** (hex-encoded, not just a hash of it) from the last time it was seen, for the `password` and `pq_hybrid` `my_key` types. Storing the whole key (not a fingerprint) means a pinned entry can be verified against an actual key file, not just trusted as "some hash matched" — a fingerprint is still computed on the fly for display in the review popup below.
   - `password`/`pq_hybrid` are checked by simple comparison — that key is never supposed to change, so any difference at all is the signal. Only `none` is entirely untracked — that key is freshly autogenerated every session with no continuity mechanism at all, nothing to verify against.
   - The first time a nickname is ever seen, or when it's seen again with the same (or provably continuing) key as before, nothing happens — this is invisible in normal use. A first sighting is still saved to disk immediately, so it's pinned for the next reconnect too.
   - If a nickname with a pinned key reconnects with a **different** key — a byte change (`docs/PROTOCOL.md` §12.4) — messaging with them is gated immediately, and the **identity review popup** (see "Connected UI" above) opens as soon as this connection's own address/device id are known (below), naming the user and a short fingerprint of both the old and the new key. This can mean the person genuinely regenerated their key, or that someone else is now using that nickname — the app doesn't decide which; it puts the decision to the user via **Accept** or **Reject**, rather than guessing.
   - **Accept** trusts the new key from that point on: it's saved to disk immediately — synchronously, in real time, not batched or deferred — and any of that peer's channel/DM messages that arrived while the review was unresolved (held rather than shown, see below) are revealed into the log, in the order they arrived. **Reject** writes nothing to disk at all — the previous pin, if any, is left exactly as it was — and is never a permanent block: selecting that peer again (Enter on their sidebar entry) reopens the same popup for reconsideration, rather than staying silently stuck.
   - Until a peer's review is resolved (`Pending`), and for as long as it stays `Rejected`, messaging with them is gated: this client won't send them anything (excluded from a channel send, and their private room can't be opened or typed into at all), and anything they send is held rather than displayed — decrypted normally, since that only needs *this client's* own key, but not shown until they're `Accept`ed. Their sidebar entry renders red the whole time, taking priority over the offline-gray color. A channel message is otherwise unaffected: it still reaches every other, verified member.
   - Several peers can be unresolved at once; the popup shows one at a time, in the order their mismatches were detected — resolving the one showing (either button) opens the next automatically.
   - **Device id and last-seen address** (`docs/PROTOCOL.md` §12.7). Each installation generates a random 50-character id the first time it's needed (`~/.aloo/d_id`) and reuses it forever; it's sent to a peer as part of establishing the direct connection, purely so it can be shown in a review — it isn't checked against anything. Once a peer's direct connection is up, the address it was reached at and the device id it announced are remembered alongside their pinned key. The **identity review popup** shows both: `Last known from <addr> (device <id>)` — whatever was recorded the last time this nickname's *previous* key was connected, `unknown` if it never was — next to `Now connecting from <addr> (device <id>)` for this specific attempt, `unknown` if the direct connection couldn't be established at all. This is exactly why the popup itself waits a moment after the mismatch is first detected: without it, there would only be two fingerprints to go on.

9. **Send a file to a channel or a user, with the recipient's consent.** Type `/file` in the compose bar and press Enter (must be joined to a channel, or have a non-offline, verified DM room open — otherwise this does nothing and the typed `/file` stays put, same as Space with nowhere to record voice to). A popup file browser opens, centered on screen — the same in-TUI widget (`Up`/`Down` select, `Enter` open a directory or pick a file, `Left`/`Right` back/forward, `Esc` cancel) the connect popup's `rsa` server_key field already uses.
    - **Confirmation.** Selecting a file (Enter on it, not a directory) replaces the browser with a confirmation box: `Send "<filename>" to #<channel>?` or `Send "<filename>" to <username>?`, with two buttons, **Send file** and **Discard** — `Discard` focused by default, same reasoning as the identity review popup's `Reject`-first default (Functionality #8): sending should never be one accidental Enter away. `Left`/`Right`/`Tab` move focus, `Enter` confirms. Choosing **Discard** returns to the file browser at the same directory (not all the way back to the compose bar); pressing `Esc` on the confirmation box does the same. `Esc` on the browser itself cancels the whole `/file` flow. Filenames longer than 230 characters are cropped at the end before being offered (`docs/PROTOCOL.md`'s file transfer section) — the receiving client independently crops again on whatever it actually receives.
    - **Offering.** Choosing **Send file** sends an *offer* — filename and size, encrypted exactly like a text message (RSA-OAEP per recipient, split into blocks the same way, `docs/PROTOCOL.md` §8.1) — to every ready recipient; nothing is read from disk yet. There is no size cap: since the file itself is streamed in small chunks only once accepted (below), the old whole-file-in-one-message limit no longer applies. A channel send is one independent offer per member, each shown as its own row in your log (below) — one recipient accepting doesn't wait on, or get affected by, another rejecting.
    - **The recipient's popup.** Before any file bytes arrive, the receiving side sees a centered popup — accompanied by a chime (`assets/bell.wav`) — reading `<nickname> is sending "<filename>" (<size>) via #<channel>` (or "via a private message" for a DM). Two buttons, **Accept** and **Reject** — **Accept focused by default**, the opposite of this app's usual safety-first default (Functionality #8's identity review, this flow's own Discard-first confirmation above): accepting an incoming file is the common case here, so it shouldn't cost an extra keystroke. `Left`/`Right`/`Tab` move focus, `Enter` confirms. Several offers arriving close together queue and show one at a time, same as identity reviews.
    - **Appearance and progress.** Both sides render the message as a paperclip and the filename, e.g. `📎 report.pdf`, in the channel/DM log — a channel send's per-recipient rows also name who each is addressed to. Before a decision, the sender's row reads "(waiting for accept...)"; once **Accept**ed, the file streams in small chunks straight to `~/.aloo/downloads` (never held whole in memory on either side) and both sides' rows show a live progress bar and percentage until every byte has moved, at which point the row settles back to the plain paperclip-and-filename look. Choosing **Reject** ends it there — the sender's row shows "(rejected)" instead, so declining a file is as visible to them as accepting one.
    - **Trust gating and offline peers** work exactly like text (Functionality #7/#8): an offer from a `Pending`/`Rejected` sender is decrypted but held — no popup, no chime — until they're `Accept`ed, at which point it's queued for real; a gated or offline channel member is simply not offered the file at all, same as text/voice; an offline or gated DM peer's room can't receive one at all (same gate that already blocks `/file` from starting in the first place).

10. **`pq_hybrid`: a post-quantum hybrid encryption method** — ML-DSA-87+RSA4096 signing, ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption. Full model in `docs/PROTOCOL.md` §13; from the user's point of view:
    - Selected as the `my_key` type in the connect popup - and selected by default. Unlike every other type, its keys aren't generated fresh in-process at connect time; they live in a keybundle file pair (`file_pub`/`file_priv`). You don't have to prepare that pair yourself: the popup prefills the fields (from `~/.aloo/.cache`'s most-recently-used entry for a server you've connected to before, or otherwise a freshly-assigned location under `~/.aloo/`), and connecting transparently generates the actual keys at that location the first time it's used, if they don't already exist (`docs/PROTOCOL.md` §13.9). `aloo --keygen-pq-hybrid <prefix>` (writes `<prefix>` and `<prefix>.pub`) is still there if you want to generate one yourself - e.g. to point both files at a specific, memorable location, or to produce one to move to another machine - but it's optional now, not required.
    - **The connect popup remembers your `pq_hybrid` identity per server.** After connecting (attempted or not - whichever files were used to try), `~/.aloo/.cache` records that `(host, port)`'s `file_pub`/`file_priv`. Reopening the app, or returning to the same server later in one session, prefills the exact same identity automatically - a different server you haven't used before still gets its own freshly-assigned location the first time.
    - Text, file, and voice messages are all signed with **both** ML-DSA-87 and RSA-4096 before being encrypted — a receiver only accepts a message if **both** signatures check out, so a break in either primitive alone isn't enough to forge one. The bulk data is AES-256-GCM-encrypted once per send (not re-encrypted per recipient the way `password`/`none` are), and that one-time key is separately wrapped for each recipient by combining an ML-KEM-1024 exchange with a second, independent RSA-4096 encryption — recovering it needs breaking both, not just one.
    - Its own encryption keys rotate every message, per peer relationship - a fresh ML-KEM-1024+X25519 pair each time, cheap enough to run inline with no visible delay. A message typed for a peer before their next fresh key arrives isn't dropped - it's held and sent automatically the moment that key shows up, in the order it was typed. See `docs/PROTOCOL.md` §13.10.
    - **Only another `pq_hybrid` user can send to a `pq_hybrid` user.** Producing a valid message to a `pq_hybrid` recipient needs the *sender's* own ML-DSA-87/RSA-sign identity, which no other `my_key` type has — a channel member using `password`/`none` simply can't reach a `pq_hybrid` peer, the same silent exclusion as any other unreachable recipient (an offline member). A `pq_hybrid` user can still message everyone else normally.
    - Voice messages work the same way as text — the expensive signing/key-exchange work happens once per recording, not per 15ms chunk, so holding Space to talk feels identical to any other method.
    - Its identity is static (loaded from the keybundle file, not regenerated every session) and file-backed, so it's pinned in `id_store` exactly like `password` (Functionality #8) — a `pq_hybrid` nickname reconnecting under a different keybundle triggers the same identity review popup a changed `password` key would.

11. **Leave a channel with `/leave`.** Type it in the compose bar and press Enter — no argument, it always targets the currently selected channel tab (must actually be joined, same "leaves the typed command in place if it can't act" behavior as `/file`). Leaving a private channel removes its tab outright; leaving a public channel keeps the tab but marks it not-joined, and selecting it now shows a centered rejoin prompt instead of the usual view (Enter there re-requests joining). The dwell timer (Functionality #2) never silently rejoins a channel left this way. Full model in `docs/PROTOCOL.md` §6.2/§7.1.3.

12. **Presence notices in the message log.** A peer joining, leaving, or disconnecting logs a plain, app-generated line into the message log — `<local time> <name> joined`/`left`/`disconnected`, rendered in yellow (`MessageBody::Presence` — distinct from the gray/italic `MessageBody::System` OTP's own narration uses, and, like it, never given the OTP shield prefix). The local time is this client's own wall clock, `HH:MM:SS`.
    - **Joined** — logged into a channel's own log the moment someone joins it, but only for a genuine live join: the existing-member snapshot a client's own first join into that channel receives (Functionality #2, `docs/PROTOCOL.md` §6.1) is silent, since it isn't really anyone joining, just being introduced to who's already there. A duplicate join for someone already listed logs nothing either.
    - **Left** — logged into a channel's own log the moment a member leaves it (Functionality #2).
    - **Disconnected** — a full disconnect (Functionality #7) is not scoped to one channel, so it's logged into every channel the departing user was a member of, and into an already-open private room with them, all before any of that connection's membership bookkeeping runs — so the notice still lands even for a peer with no DM history, who is then dropped from the channel's member list in the same call.

13. **OTP mail: write someone a mail that waits, one-time-pad encrypted, on the server until they connect.** Full model in `docs/PROTOCOL.md` §17; from the user's point of view:
    - **`/mail`** in the compose bar opens a **full-screen compose view** — a command rather than a key chord, since the natural chord (Ctrl+M) and Enter are the same byte on terminals without the kitty keyboard protocol: From (fixed to your own nickname), To, Subtext (the subject line), a multi-line Content box, and an attachments pane. Tab/Shift+Tab cycle the fields; they can be filled independently, in any order. Esc discards the draft and returns to whatever view was underneath.
    - **The To field validates as you type**, on every keystroke: a valid recipient — a pinned user with that nickname (Functionality #8) whose pin is a `pq_hybrid` identity, an `otp` keychain contact for the pair, and a key strictly longer than the whole mail — renders green with a ✅; anything else renders red with a ❌ and the specific reason inline. The verdict is live in both directions: typing enough content to outgrow the pad flips a valid recipient back to ❌.
    - **The remaining key, in MB, sits in the top right** of the screen once the nickname has validated, and updates in realtime as content is typed and attachments are added or removed.
    - **Attachments** reuse the existing machinery: in the attachments pane, `a` opens the same in-TUI file browser `/file` uses, and holding **Space** — only while the attachments pane is focused; in every other field Space just types — records a voice message with the same hold-to-record flow as Functionality #4, accumulated for the mail instead of live-streamed. **Enter** on an attached voice recording replays it through the normal mixer, and **Esc** during that playback stops it (and nothing else — the compose view stays), exactly as replaying a logged voice message works. An attachment (file or finished recording) larger than the remaining key **cancels the operation** outright, with a notice; `d` removes the selected attachment, after a confirm popup whose default is Cancel.
    - **Ctrl+S sends — only through a confirm popup** (Cancel focused by default). On confirm the whole mail (fields, voice PCM, attachment bytes) is encoded, signed with your durable identity, sealed through `otp --encrypt`, and uploaded; a local reference (never the content) is stored under `~/.aloo/otp_mail/`. The server's acknowledgement moves it to "on server"; if that acknowledgement never arrives, the next connect re-uploads the exact ciphertext recovered from the keychain's `.last_sent` copy under the same mail id — never a fresh encode, never a second pad spend.
    - **`/mailbox` opens the mailbox popup**, laid over the mail view it opens as its backdrop (Esc out of the popup closes an untouched backdrop with it): every sent mail with its delivery status (`awaiting server` / `on server` / `delivered ✓` / `failed` — status only, never content) and every received mail. **Enter on a received mail reads it**: the payload is decrypted in memory only and shown full-screen — Subtext, Content, voice parts playable through the normal mixer (Enter), attachments savable to `~/.aloo/downloads` (Enter). `d` removes a mail (confirm popup): removing a received mail overwrites and deletes its stored ciphertext **and** pad, destroying the content for good; removing a sent mail drops only the local status reference.
    - **Receiving**: a client with the `otp` binary asks the server for its mail right after connecting; each delivered mail is decrypted through the keychain exactly once, its identity signature checked against the pinned sender, then immediately re-encrypted under a fresh local one-time pad and stored as that (ciphertext, pad) file pair — plaintext is never at rest. A notice (with the file-offer chime) announces new mail; the sender is told when their mail was genuinely delivered, on their next connect if offline at the time.

14. **Live voice calls: a continuous, multi-user conversation, distinct from a voice message (Functionality #4).** Full model in `docs/PROTOCOL.md` §7.7; from the user's point of view:
    - **`/call`** in the compose bar starts one, addressed to whatever's currently in view — the selected channel, or an open private room — same "nowhere to send it" no-op as Space (Functionality #4) if neither applies. Refused, with a status notice, while already on a call, while a push-to-talk recording is in progress, and — DM only — while an OTP session (`docs/PROTOCOL.md` §16) is active with that peer, since that layer has no live-streaming concept at all; a channel call simply leaves out any member under one, the same silent exclusion an unreachable member already gets elsewhere (Functionality #7/#8).
    - **Every reachable member/the peer sees a popup** — chimed, like a file offer — reading `Voice call incoming from <nickname>`, with **Accept**/**Reject** buttons, **Accept focused by default** (same reasoning as the file-offer popup, Functionality #9). A caller already on a different call is answered automatically with a decline, no popup shown - the reference client supports one active call at a time. Several invites queue and show one at a time, same as file offers; one from a not-yet-trusted identity (Functionality #8) is held, not shown, until that identity is `Accept`ed.
    - **Accepting joins.** Once joined, the microphone stays open continuously - not push-to-talk, no 4-minute cap - and stays that way for as long as the call runs. Every participant who accepts hears every other one; there is no server and no single participant's connection the others depend on staying up (`docs/PROTOCOL.md` §7.7's roster-convergence rule).
    - **A permanent red indicator** (see "Connected UI" above) marks the whole time a call is active, naming how many other participants are currently connected and whether the microphone is muted.
    - **`/mute`** silences the microphone without ending the call or telling anyone else - captured audio is simply never sent while muted, so every other participant just hears silence, same as an ordinary pause in talking. `/mute` again resumes. Refused, with a notice, while not on a call.
    - **`/endcall`** leaves the call: every other participant is told and stops hearing from us. Refused, with a notice, while not on a call. The call itself has no separate "end" beyond that - it is, at any moment, simply whichever participants haven't yet left.
    - **Mutually exclusive with push-to-talk.** Space and the global shortcut (Functionality #4) do nothing while on a call - the microphone is already spoken for - and `/call` cannot be run mid-recording either.

## Protocol terms, and what implements them

`docs/PROTOCOL.md` describes the protocol without naming a single Rust
item, so that a second implementation never has to read this codebase.
This is the bridge back: every term that document uses, against the thing
here that implements it. If a name changes on one side, it changes on both.

| Protocol term (PROTOCOL.md) | Implemented by |
|---|---|
| Framing, `MAX_FRAME_LEN` | `proto.rs` `frame`, `parse_frame`, `MAX_FRAME_LEN` |
| Encoding rules (§2) | `proto.rs` `encode`, `decode`, `bincode_config` (capped at `MAX_FRAME_LEN` — see TB-172) |
| `ClientMessage`, `ServerMessage`, `Envelope`, `UserInfo`, `KeyMode` | `proto.rs` |
| Control channel (§1.3) | `control.rs` `ControlOffer`, `ControlAccept`, `accept_offer`, `open_accept`, `derive`, `ControlWriter`/`ControlReader`/`ControlEndpoint`, `ControlSink` |
| Connection lifecycle (§4), auth (§5) | `server/mod.rs` `handle_connection`, `AuthConfig`; `client/connect.rs` `connect_and_handshake` |
| Liveness, `Heartbeat` (§4.1) | `proto.rs` `HEARTBEAT_INTERVAL`, `HEARTBEAT_TIMEOUT`, `ClientMessage::Heartbeat`; `server/mod.rs` `client_loop`; `client/session.rs` `run_connected_session` |
| Registration, nicknames (§5.4) | `server/mod.rs` `Registry::try_register` |
| Channels (§6), password bans (§6.6) | `server/mod.rs` `Registry::{join_channel, leave_channel, unregister, channel_list, channel_password_attempts}`; `validation.rs` |
| Direct link, candidates, punching (§7.1) | `client/p2p.rs` `PeerLinkManager`; `p2p_proto.rs` `PunchDatagram`, `RendezvousMessage`, `SAFE_DATAGRAM_BYTES` |
| Reliable layer (§7.1.1) | `client/p2p_reliable.rs` `ArqSender`, `ArqReceiver` |
| `P2pPayload` variants (§7.2/§7.3/§7.6/§7.7) | `p2p_proto.rs` `P2pPayload` |
| Per-recipient OAEP, chunking (§8/§8.1) | `crypto/mod.rs` `encrypt_chunked`, `decrypt_chunked`, `max_chunk_len` |
| Password-derived keys (§8.3) | `crypto/mod.rs` `KeyPair::from_password` |
| RSA-PSS signing (§8.4) | `crypto/mod.rs` `sign`, `verify` |
| Rotating-key freshness/queueing (§11) | `client/rekey.rs` `RemoteKeys`, `QueuedOutbound` |
| Identity pinning (§12) | `client/idstore.rs` `IdStore`, `Trust`, `IdCheck`; `client/session.rs` `check_identity` |
| Safety phrases (§12.6) | `crypto/safety.rs` `phrase`, `WORDS` |
| Continuity certificates (§12.6) | `crypto/pq.rs` `ContinuitySig`, `sign_continuity`, `verify_continuity`; `main.rs` `run_rekey_pq_hybrid` |
| Identity cards (§12.6) | `crypto/pq.rs` `IdentityCard`, `make_identity_card`, `open_identity_card`; `main.rs` `run_export_identity_card` |
| Key bundles (§13.2) | `crypto/pq.rs` `PqPublicBundle`, `PqPrivateBundle`, `PqEncapKeys`, `PqDecapKeys`, `generate_bundle` |
| `SendBinding`, `SendSetup`, sealed sends (§13.3) | `crypto/pq.rs` `SendBinding`, `SendSetup`, `HybridSend`, `seal_setup`, `seal_send`, `seal_chunk` |
| Opening a send (§13.4) | `crypto/pq.rs` `open_setup`, `open_send`, `open_chunk`; `client/session.rs` `decrypt_own_envelope` |
| Replay refusal (§13.4) | `client/replay.rs` `ReplayGuard` |
| Addressing rule (§13.6) | `client/keymode_policy.rs` `can_address` |
| Encryption-key rotation (§13.10) | `client/pq_rekey.rs` `PqOwnKeys`, `PqPeerKeys`, `PQ_KEY_RETENTION`; `crypto/pq.rs` `PqRotation`, `sign_rotation`, `verify_rotation` |
| Fingerprints (§12.6/§13.3) | `crypto/pq.rs` `bundle_fingerprint`, `fingerprint_of_encoded` |
| Wire-contract constants pinned by vectors | `crypto/pq.rs` `chunk_nonce`, `hkdf_combine`, `send_commitment`; `control.rs` `derive` — see `docs/SECURITY.md`, "Test vectors" |
| One-time-pad layer (§16), `contact_name_for` | `crypto/otp.rs` `contact_name_for`, `OtpKeySetupPayload`, `OtpSessionRequestPayload`, `OtpKeySetupAckPayload` |
| `otp` command subprocess wrapper (§16) | `client/otp_cli.rs` `OtpCliConfig`, `encrypt`, `decrypt`, `status`, `has_contact`, `new_key_pair`, `add_contact`, `binary_available` |
| Per-contact OTP state, ack gate (§16.2) | `client/otp_store.rs` `OtpStore`, `OtpContactState`; `client/otp.rs` `OtpOutQueue`, `send_or_queue`, `on_delivery_ack` |
| Turning the layer on, mutual consent (§16.1) | `client/otp.rs` `handle_otp_command`, `detect_or_adopt_existing`, `initiate_provisioning`, `confirm_generate`, `cancel_generate`, `apply_incoming_setup`, `accept_invite`, `reject_invite`, `on_key_setup_ack`, `commit_pending_setup`, `discard_pending_setup`, `resend_pending_setups` |
| Chunked key-setup transfer (§16.1) | `crypto/otp.rs` `OtpKeySetupChunk`, `OtpKeySetupReassembly`; `client/otp.rs` `send_key_setup_chunked`, `on_key_setup`, `OTP_SETUP_CHUNK_BYTES`; `client/session.rs` `SessionState.otp_incoming_setup` |
| OTP session popups and status notice | `client/tui/ui.rs` `PendingOtpGenerate`, `PendingOtpInvite`, `UiAction::RequestOtpSession`/`ConfirmOtpGenerate`/`CancelOtpGenerate`/`AcceptOtpInvite`/`RejectOtpInvite` |
| `OtpEnvelope`/`OtpFileOffer`/`OtpFileContentSeq`/`OtpVoiceOffer`/`OtpDeliveryAck` (§16) | `p2p_proto.rs` `P2pPayload` |
| File content under the pad, two independent pad spends per file - offer and content (§16.2) | `client/otp_cli.rs` `encrypt_file`, `decrypt_file`, `encrypt_file_retrying`, `decrypt_file_retrying`, `FileCliOutcome`; `client/otp.rs` `send_file_offer`, `on_file_offer`, `start_outgoing_file_content`, `finish_incoming_file`, `temp_content_path`, `secure_remove_file`; `client/file_transfer.rs` `OwnFileTarget.otp`, `OtpIncomingFileReceive`, `OtpIncomingKind`; `client/session.rs` `SessionState.otp_send_temp_files`/`otp_incoming_file_receives`, `accept_file_offer`, `handle_file_event`, `handle_p2p_event`'s `FileAccepted`/`FileRejected`/`OtpFileContentSeq` arms |
| Voice content under the pad, recorded fully then sent once (§16.2) | `proto.rs` `Content::VoiceOffer`; `client/file_transfer.rs` `VoiceOfferPayload`; `client/otp.rs` `send_voice_offer`, `on_voice_offer`; `client/voice_stream.rs` `OwnStreamTarget::DirectOtp`, `spawn_record_accumulate_worker`; `client/direct_message.rs` `handle_voice_record_start`'s OTP branch; `client/session.rs` `decrypt_voice_offer`, `handle_p2p_event`'s `OtpVoiceOffer` arm |
| Session visibility in the DM log (§16.3) | `client/tui/ui.rs` `MessageBody::System`, `otp_active_peers`, `mark_otp_active`, `is_otp_active`, `render_messages` (shield prefix); `client/tui/direct_message.rs` `push_otp_system_message`; `client/otp.rs` `notify` |
| Asymmetric-provisioning recovery (§16.1) | `client/otp.rs` `NO_MATCHING_KEY_REASON`, `accept_invite`, `on_key_setup_ack`; `client/otp_cli.rs` `remove_contact`; `client/otp_store.rs` `OtpStore::forget` |
| Failed DM send shown in red (§16.3) | `client/tui/ui.rs` `LogEntry.failed`, `UiAction::SendDirectText.log_index`, `render_messages` (red styling); `client/tui/direct_message.rs` `push_outgoing_dm`, `mark_dm_message_failed`; `client/otp.rs` `PendingOtpSend::Direct.log_index`, `send_now`, `send_or_queue` |
| User-chosen pad size, shown to the peer (§16.1) | `crypto/otp.rs` `OTP_SIZE_MB_MIN`, `OTP_SIZE_MB_MAX`, `otp_size_mb_in_range`; `client/tui/ui.rs` `otp_size_input`, `UiAction::ConfirmOtpGenerate.size_mb`, `PendingOtpInvite.pad_size_mb`, `render_otp_size_popup`; `client/otp.rs` `confirm_generate` |
| Recovering a stuck send via `otp --recover-last`, never re-encoding (§16.4) | `client/otp_cli.rs` `recover_last`, `recover_last_file`, `RecoverDirection`; `client/otp_store.rs` `OtpContactState.pending_content`, `PendingOtpContent`, `OtpStore::pending_sends`; `client/otp.rs` `recover_and_resend`, `recover_and_resend_text`, `recover_and_resend_file`, `recover_and_resend_voice`, `peer_for_contact_name`; `client/session.rs` `handle_p2p_event`'s `LinkStatusChanged` arm |
| Rejecting a resent ciphertext before it touches the pad a second time (§16.4) | `client/otp_store.rs` `OtpStore::is_next_expected`; `client/otp.rs` `on_message` |
| Live key-metadata header (§16.5) | `client/otp_cli.rs` `ContactDetail`, `show_contact`, `parse_show_contact`; `client/otp.rs` `refresh_otp_key_status`, `poll_key_status`; `client/tui/ui.rs` `UiState.otp_key_status`, `set_otp_key_status`, `otp_key_status_for`; `client/tui/direct_message.rs` `render_private_room`, `render_otp_header`, `push_otp_key_spans`, `OTP_KEY_LOW_THRESHOLD_BYTES`; `client/session.rs` tick loop |
| OTP mail payload, ids, sealed shape (§17.1/§17.2) | `crypto/otp.rs` `OtpMailPayload`, `OtpMailVoice`, `OtpMailFile`, `OtpMailSealed`, `new_mail_id`, `mail_id_is_valid`, `OTP_MAIL_MAX_BYTES` |
| Mail identity signature over a malleable pad (§17.2) | `crypto/pq.rs` `sign_mail`, `verify_mail` |
| Mail wire messages (§17.2/§17.3) | `proto.rs` `ClientMessage::{OtpMailSend, OtpMailFetch, OtpMailAck, OtpMailDeliveredAck}`, `ServerMessage::{OtpMailResult, OtpMailDeliver, OtpMailDelivered}` |
| Server-side mail storage and routing (§17.2/§17.3) | `server/mail.rs` `MailStore`, `StoredMail`, `DeliveredReceipt`, `on_mail_send`, `on_mail_fetch`, `on_mail_ack`, `on_mail_delivered_ack`; `server/mod.rs` `Registry::id_by_name`, `client_loop`'s mail arms |
| Compose view, recipient check, live key budget (§17.1) | `client/tui/otp_mail.rs` `OtpMailState`, `ComposeState`, `MailAttachment`, `MailboxRow`, `ReaderState`; `client/otp_mail.rs` `RecipientCheck`, `check_recipient`, `MAIL_OVERHEAD_ESTIMATE`; `client/tui/ui.rs` `UiAction::{CheckOtpMailRecipient, OpenOtpMailbox, SendOtpMail, ReadOtpMail, DeleteOtpMail, SaveOtpMailAttachment}`, `VoiceTarget::MailAttachment`; `client/voice_stream.rs` `OwnStreamTarget::MailAttachment` |
| Mail send, gate sharing, `.last_sent` retry (§17.2) | `client/otp_mail.rs` `handle_send`, `resend_pending`, `on_mail_result`; `client/otp_store.rs` `PendingOtpContent::Mail`; `client/otp.rs` `flush_one_queued` |
| Mail delivery, pre-decrypt gate, re-pad storage (§17.3) | `client/otp_mail.rs` `on_mail_deliver`, `on_mail_delivered`, `MailGate`, `mail_gate`, `handle_read`, `handle_delete`; `client/otp_mail_store.rs` `OtpMailStore`, `SentMailRef`, `ReceivedMailRef`, `SentMailStatus`; `crypto/otp.rs` `repad`, `xor_pad` |

## Encryption: how each method actually works

Implementation map for the three `my_key` methods and the two things they
encrypt (text and voice), across both destinations (channel and DM). Wire-level
rules live in `docs/PROTOCOL.md`; this section is the "where is it in the code"
index. Entries reference file + function name (no line numbers - they rot
on every refactor; the name is the stable handle).

### One primitive, two key sourcings — plus `pq_hybrid`'s own

Two of the three methods share **one** encryption algorithm: RSA-OAEP with
SHA-256, applied once per recipient. No AES, no hybrid scheme, no shared
session key (Functionality #1). Because raw RSA only takes a fixed-size
block, anything longer is split into several blocks and each is encrypted
independently. `pq_hybrid` (Functionality #10) is the exception - its own
primitives live in `crypto/pq.rs`, covered in its own subsection below.

| Step | Where |
| --- | --- |
| Bytes-per-block for a key | `crypto/mod.rs` `max_chunk_len` |
| Encrypt (splits into blocks) | `crypto/mod.rs` `encrypt_chunked` |
| Decrypt (rejoins blocks) | `crypto/mod.rs` `decrypt_chunked` |
| Wire shape of one encrypted body | `proto.rs` `Envelope` |

The two RSA-based `my_key` methods differ **only in where the RSA keypair
comes from**. `none` is not plaintext despite its `[🚨 PLAIN]` tag — see the
tag table above. The single branch point is `connect.rs` `resolve_my_keypair`
(which also has `pq_hybrid`'s own arm, loading a keybundle instead of a
plain RSA keypair - see below):

| Method | Keypair | Where |
| --- | --- | --- |
| `none` | fresh 2048-bit from OS randomness, kept for the session | `crypto/mod.rs` `KeyPair::generate` |
| `password` | 2048-bit, deterministically derived: PBKDF2-HMAC-SHA256 (100k rounds, fixed salt) seeds a ChaCha20 RNG, so the same password always rebuilds the same key | `crypto/mod.rs` `KeyPair::from_password` |

The choice is announced to peers as `proto.rs` `KeyMode` in `Identify`, which
is what drives the encryption tag.

After key sourcing, **the two static RSA methods are indistinguishable in
code**: `session.rs` (`run_connected_session`) stores whichever private key
was produced directly in `SessionState::own_keys` (a plain
`Option<RsaPrivateKey>`) regardless of method, decrypted against directly via
`crypto::decrypt_chunked`. `pq_hybrid` instead populates
`SessionState::own_pq_private` and leaves `own_keys` as `None` (`session.rs`,
around the `ResolvedIdentity` match in `run_connected_session`) - see
`session::decrypt_envelope_for` for the resulting branch.

### Text messages

| | Channel | DM |
| --- | --- | --- |
| Send | `channel.rs` `handle_send_text` | `direct_message.rs` `handle_send_text` |
| Encrypt (RSA methods) | `channel.rs` `encrypt_for_each` — loops recipients | `envelope.rs` `encrypt_for_one` — one recipient |
| Encrypt (`pq_hybrid`) | same `encrypt_for_each`, dispatching via `envelope.rs` `encrypt_envelope_for` to `encrypt_hybrid_envelope_for` per `pq_hybrid` recipient | `direct_message.rs` `encrypt_for_recipient`, same dispatch |
| Wire message | `P2pPayload::Envelope { channel: Some(_), .. }`, one per member | `P2pPayload::Envelope { channel: None, .. }` |
| Delivery | direct peer-to-peer link, one per recipient (`docs/PROTOCOL.md` §7.1/§7.2) — the server relays only the initial candidate exchange, never the message itself | same |
| Receive + decrypt | `session.rs` `decrypt_envelope_for` → `crypto::decrypt_chunked` against `SessionState::own_keys` (RSA) or `crypto/pq.rs` `open_send` (`pq_hybrid`, dispatched by *our own* `own_key_mode`, then the binding's channel and `ReplayGuard` are checked) | same |

A channel message is therefore encrypted N times for N members and delivered
over N independent direct links — the server never sees any of them.
`pq_hybrid` recipients that a non-`pq_hybrid` sender can't address at all
(`keymode_policy.rs` `can_address`) are excluded before encryption even starts -
see "What `pq_hybrid` adds" below.

### Voice messages

Voice is streamed live, not recorded-then-sent (Functionality #4), so
encryption happens per 15ms chunk (`voice.rs` `CHUNK_INTERVAL`) on a
dedicated thread — never on the async event loop.

| Stage | Where |
| --- | --- |
| Recipients' public keys parsed **once** at record-start | `channel.rs` `parse_recipients` / `direct_message.rs` `handle_voice_record_start` |
| Record + encrypt loop (own thread) | `voice_stream.rs` `spawn_record_stream_worker` |
| Encrypt a chunk — channel (per recipient) | `voice_stream.rs` `build_chunk_recipients` → `p2p::P2pOutbound::ChannelVoiceChunk` |
| Encrypt a chunk — DM | same, → `p2p::P2pOutbound::DirectVoiceChunk` |
| Delivery | direct peer-to-peer link, unreliable/unordered per chunk (`docs/PROTOCOL.md` §7.1/§7.3) — never touches the server |
| Receiving: pick the private key **once** for the whole stream | `voice_stream.rs` `resolve_incoming_key`, cloning `SessionState::own_keys` |
| Decrypt loop (one thread per incoming stream) | `voice_stream.rs` `spawn_stream_decrypt_worker`, decrypt in `ChunkDecryptor::decrypt` |

Each incoming stream gets its own decrypt thread because RSA private-key
decrypt is much costlier than public-key encrypt — one shared thread would fall
behind real time with two or three simultaneous speakers.

### File transfer

Consent-gated and streamed (Functionality #9, `docs/PROTOCOL.md`'s file
transfer section) - the offer is sent/encrypted like text, then an accepted
transfer's bytes move like voice's chunk stream, except always
point-to-point (never a channel broadcast) since accept/reject/progress is
inherently per-recipient. `file_transfer.rs`'s workers mirror
`voice_stream.rs`'s plumbing but move bytes to/from disk instead of the
audio mixer, reusing its RSA/PQ dispatch types directly rather than
duplicating them.

| Stage | Where |
| --- | --- |
| Offer, one per ready recipient — channel | `channel.rs` `handle_send_file` |
| Offer — DM | `direct_message.rs` `handle_send_file` |
| Delivery (offer, accept/reject, chunks, end) | direct peer-to-peer link, reliable (`docs/PROTOCOL.md` §7.1.1/§7.6) — the server is never involved, not even for an existence check |
| Incoming offer: decrypt, trust-gate, queue + bell | `session.rs` `decrypt_file_offer`, `handle_incoming_file_offer` |
| Accept: spawn the receive worker, log the row | `session.rs` `accept_file_offer` |
| Sender learns of Accept: spawn the send worker | `session.rs` (`P2pEvent::FileAccepted` arm) |
| Send worker — reads/encrypts/sends one chunk at a time | `file_transfer.rs` `spawn_send_file_worker` |
| Receive worker — decrypts/writes one chunk at a time | `file_transfer.rs` `spawn_receive_file_worker` |
| Forward an incoming chunk/end to its worker | `file_transfer.rs` `forward_chunk`/`end_incoming_transfer`, called from `session.rs` |
| Progress/completion/failure → log row | `session.rs` `handle_file_event` → `UiState::set_file_progress`/`set_file_completed`/`set_file_rejected`/`set_file_failed` |

### Live voice calls

Continuous and multi-user (Functionality #14, `docs/PROTOCOL.md` §7.7) -
distinct from a voice message (above) in transport shape too: no
`StreamStart`/`StreamEnd`, no `MAX_RECORDING_SECS` cap, and a dynamic,
live-changing recipient set instead of one resolved once at record-start.
Reuses `voice_stream.rs`'s per-chunk RSA/PQ dispatch (`resolve_direct_key`,
`resolve_incoming_key`, `encrypt_direct_chunk`, `ChunkDecryptor`) directly
rather than duplicating it - a call chunk's plaintext is exactly as
payload-agnostic to those functions as a voice message's or a file
chunk's already is.

| Stage | Where |
| --- | --- |
| Start our own call (initiator or accepter) | `voice_call.rs` `begin_own_call` |
| Invite fan-out - channel / DM | `channel.rs` `handle_start_call` / `direct_message.rs` `handle_start_call` |
| Roster convergence (broadcast on join, reply to a newcomer) | `voice_call.rs` `accept_invite`, `on_call_accept`, `add_participant` |
| Continuous capture + dynamic per-recipient fan-out (own thread) | `voice_call.rs` `spawn_call_audio_worker`, `CallRecorderCmd` |
| Decrypt loop (one thread per participant's incoming audio) | `voice_call.rs` `spawn_call_decrypt_worker` |
| Telling a call chunk/setup apart from a voice message's, sharing the same wire events | `voice_call.rs` `is_call_stream`; `session.rs` `handle_p2p_event`'s `StreamChunk`/`StreamKeySetup` arms |
| Muting (purely local, no wire message) | `voice_call.rs` `toggle_mute`, `CallRecorderCmd::SetMuted` |
| Leaving, tearing down every participant | `voice_call.rs` `end_own_call`, `remove_participant` |
| Invite/accept/reject popup + permanent indicator | `client/tui/ui.rs` `PendingCallInvite`, `CallUiState`, `push_call_invite`/`call_invite_open`/`take_call_invite`, `begin_call`/`end_call`/`set_call_muted`, `UiAction::StartCall`/`AcceptCallInvite`/`RejectCallInvite`/`ToggleCallMute`/`EndCall` |

### What `pq_hybrid` adds

`pq_hybrid` is a second *static* identity (like `password`/`none`), with
different key material and a different, self-contained primitive set - but
it's the only method whose *encryption* keys rotate during the session, so
it reuses `rekey.rs`'s generic `RemoteKeys` for freshness/queueing (§11)
even though its rotation signing/verification is entirely its own
(`pq_rekey.rs`, `crypto/pq.rs`). Full model in `docs/PROTOCOL.md` §13.

Voice is exempt from per-chunk rotation (§11.2): one key snapshot covers a
whole stream (`voice_stream.rs`), and a recipient without a fresh key (or
whose direct link isn't `Active` yet, `docs/PROTOCOL.md` §7.1/§7.3) is
dropped from that stream (`channel.rs` in `handle_voice_record_start`) or
the DM recording is refused outright (`direct_message.rs`).

| Piece | Where |
| --- | --- |
| Key bundle types + keygen | `crypto/pq.rs` `PqPublicBundle`, `PqPrivateBundle`, `generate_bundle` (`generate_bundle_with_bits` for tests, which need real identities but not RSA-4096 keygen) — the durable signing half plus one bootstrap encryption pair |
| Rotating encryption keys (forward secrecy) | `crypto/pq.rs` `PqEncapKeys`, `PqDecapKeys`, `generate_encryption_keys`; `client/pq_rekey.rs` `PqOwnKeys` (ours, per peer, with `PQ_KEY_RETENTION` superseded keys kept), `PqPeerKeys` (theirs, with rotation generations) |
| Offer/accept a rotation | `crypto/pq.rs` `PqRotation`, `sign_rotation`, `verify_rotation` (signed by the durable identity, not the key replaced); `session.rs` `request_rotation` (the one trigger every send/receive path calls), `handle_pq_key_rotated` |
| Safety phrase (eight words from a fingerprint) | `crypto/safety.rs` `phrase`, `WORDS` |
| Encrypted control channel | `control.rs` `ControlOffer`/`ControlAccept` (handshake), `accept_offer`/`open_accept` (key transport, reusing `crypto::pq`'s hybrid wrap), `ControlWriter`/`ControlReader` (split, for the live client and server), `ControlEndpoint` (sequential, with `client_handshake`), `ControlSink` (the seam send paths take) |
| Server proving its identity | `control.rs` `make_offer`/`verify_offer`; `server/mod.rs` `AuthConfig::signing_key` — signed only when the deployment has an RSA server key |
| How much a pin is worth | `client/idstore.rs` `Trust` (`tofu`/`verified`), `check_and_pin_with`, `mark_verified`, `trust` — third column of the store file |
| Retire an identity for a new one | `crypto/pq.rs` `ContinuitySig`, `sign_continuity`, `verify_continuity`, `PqPublicBundle::with_continuity`; `main.rs` `run_rekey_pq_hybrid` (`--rekey-pq-hybrid`); `session.rs` `continuity_proven` — a proven change re-pins with a status note instead of a review |
| Identity card (pin before first contact) | `crypto/pq.rs` `IdentityCard`, `make_identity_card`, `open_identity_card`, `save_identity_card`, `load_identity_card`; `main.rs` `run_export_identity_card` (`--export-identity-card`) |
| Save/load bundle files (private one `0o600` on unix) | `crypto/pq.rs` `save_public_bundle`, `load_public_bundle`, `save_private_bundle`, `load_private_bundle` |
| CLI keygen (no `openssl` equivalent exists) | `main.rs` `run_keygen_pq_hybrid`, `--keygen-pq-hybrid` |
| Key bundle fingerprint (identity, stable across reconnects) | `crypto/pq.rs` `bundle_fingerprint`, `fingerprint_of_encoded` |
| Seal one send's key, bound to recipient/room/counter | `crypto/pq.rs` `SendBinding`, `SendSetup`, `seal_setup` (ML-KEM-1024 + ephemeral X25519 wrap, then ML-DSA-87 + RSA-PSS over the commitment) |
| Open a send's key, verifying both signatures and the binding | `crypto/pq.rs` `open_setup` (refuses a setup sealed for anyone but us) |
| Seal/open one chunk (any content type) | `crypto/pq.rs` `seal_chunk`, `open_chunk`, `chunk_nonce` (deterministic `send_id`+`seq`) |
| One-chunk send (text, file offer) | `crypto/pq.rs` `HybridSend`, `seal_send`, `open_send`; `client/envelope.rs` `encrypt_hybrid_envelope_for` |
| Stream setup on the wire, once per recipient | `p2p_proto.rs` `P2pPayload::StreamKeySetup`; `voice_stream.rs` `PqStreamOut::setups`, `forward_key_setup` |
| Hold chunks that outrun their setup, replay once it verifies | `voice_stream.rs` `ChunkDecryptor::install_setup`, `MAX_PENDING_CHUNKS` |
| Refuse a send that already arrived | `client/replay.rs` `ReplayGuard`; `session.rs` `decrypt_own_envelope` (also checks the binding's channel) |
| Own key material in the live session | `session.rs` `SessionState::own_pq_private` (mirrors `own_keys`, populated instead of it when `own_key_mode == PqHybrid`) |
| Who can be addressed | `keymode_policy.rs` `can_address` - a `pq_hybrid` recipient needs a `pq_hybrid` sender (their own ML-DSA-87/RSA-sign identity); everyone else is reachable by any sender, as always |
| `id_store` pinning | `keymode_policy.rs` `uses_byte_comparison_pinning` - `pq_hybrid` joins `password` on the plain-byte-comparison side |
| Auto-generate keys if missing | `crypto/pq.rs` `ensure_bundle_at`, called from `connect.rs` `resolve_my_keypair`'s `PqHybrid` arm (`docs/PROTOCOL.md` §13.9) |
| Connect-popup cache (`~/.aloo/.cache`) | `connect.rs` `ConnectCache`, `cache_path`, `random_prefix`, `fresh_pq_hybrid_paths_in`, `prefill_connect_defaults` |

### `server_key` — a separate axis

Authenticating *to the server* is unrelated to the message encryption above and
has only three options (`connect.rs` `ServerKeySelection`,
`proto.rs` `AuthKind`). Client side: `connect.rs` `build_auth_response`.
Server side: `server/mod.rs` `AuthConfig::verify`.

| Option | Check |
| --- | --- |
| `none` | passes unconditionally |
| `password` | sent as-is and compared byte-for-byte in constant time (`crypto/mod.rs` `constant_time_eq`) — it is **not** hashed |
| `rsa` | server sends a random nonce (`crypto/mod.rs` `random_bytes`, `server/mod.rs` `make_challenge`); client encrypts it with the server's public key; server decrypts and compares |

## Server responsibilities

The server is only a medium of connection *setup*: it manages client connections, channel membership/broadcast, relays public key exchange (join notifications), and relays the candidate exchange that lets two clients punch a direct peer-to-peer link to each other (`docs/PROTOCOL.md` §7.1). Text, voice, and file content travel only over that direct link once it's established — the server never sees any of it, not even as ciphertext. It does not persist anything — chat/DM history lives only in each client's memory for the session. It does enforce nickname uniqueness, since that's connection bookkeeping rather than message content. It distinguishes a client explicitly leaving one channel from its connection closing entirely (Functionality #7), notifying peers with a different message for each (`docs/PROTOCOL.md` §6.2, §6.4) — but the *decision* of whether to keep an offline user's name around (grayed out) or drop it is made entirely client-side, based on that client's own private-message history, which the server has no visibility into.
