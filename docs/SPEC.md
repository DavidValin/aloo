# Application specification

- language: rust
- ui framework: ratatui
- other packages: crossterm, tokio, serde + bincode (v2 — the crates.io `bincode 3.0.0` is a squatted placeholder, not a real release), rsa, rand_core + rand_chacha (RSA key generation needs `rand_core` 0.6's `CryptoRngCore`; deterministic password-derived keys use `rand_chacha`), sha2 (pinned to 0.10 to match `rsa`'s `digest` version), pbkdf2 + hmac, cpal (raw PCM, no opus), clap (CLI parsing), thiserror (error types), sysinfo (cross-platform CPU usage for the header's `CPU:<pct>%` indicator)

This application is a terminal communication tool that supports text / voice channels.
The `main.rs` file acts as the CLI entry point. When run without parameters, it runs the client (with terminal UI).
When run with `--server`, it starts a server instead.

## Files

```
src/
src/lib.rs              <-- library root: the module list `main.rs` and the tests build against
src/main.rs             <-- CLI entry point: arg parsing, terminal setup/teardown
src/connect.rs           <-- client bootstrap: connect popup, auth + identify handshake, local store loading
src/session.rs            <-- the live connected session: event loop, session state, key rotation / identity pinning
src/channel.rs             <-- channel-addressed send/receive handling for the session
src/direct_message.rs       <-- DM-addressed send/receive handling for the session
src/voice_stream.rs          <-- live voice streaming plumbing shared by channels and DMs
src/file_stream.rs            <-- consent-gated, streamed file transfer plumbing, Functionality #10
src/proto.rs        <-- implements the communication protocol
src/voice.rs         <-- handles capture / live playback (mixer)
src/crypto.rs         <-- handles encryption / decryption
src/rekey.rs           <-- rsa_per_msg per-peer key rotation state (pure logic, no I/O)
src/file_transfer.rs     <-- FileOfferPayload plaintext shape, chunking/filename constants, download dir, Functionality #10
src/idstore.rs          <-- identity-pinning store (nickname -> public key), Functionality #9
src/own_next_keys.rs     <-- this client's own per-peer continuity keys, Functionality #6/#9
src/platform.rs           <-- cross-platform ~/.aloo home-directory resolution, shared by idstore.rs/own_next_keys.rs
src/sysstats.rs            <-- CPU usage sampling for the header's CPU:<pct>% indicator
src/netstats.rs             <-- connection-speed statistic for the header's Conn:<quality> indicator
src/server.rs             <-- the server; contains a simple protocol for operations
src/ui/mod.rs            <-- the `ui` module list (no logic of its own)
src/ui/ui_connect_popup.rs  <-- the connect popup
src/ui/ui.rs           <-- the UI once the user is connected: shared state, key handling, log/input rendering
src/ui/channel.rs       <-- channel-tab state and rendering (adds `impl UiState` on top of `ui.rs`)
src/ui/direct_message.rs <-- private-room (DM) state and rendering (likewise)
src/ui/file_send.rs      <-- /file send flow: browse + confirm state and rendering (likewise), Functionality #10
```

The client half is split by *conversation type* on both sides of the network/UI
boundary: `channel.rs`/`direct_message.rs` handle the wire side (encrypt, send,
apply incoming), `ui/channel.rs`/`ui/direct_message.rs` the presentation side.
Both pairs are thin layers over shared plumbing (`session.rs`, `voice_stream.rs`,
`ui/ui.rs`) rather than independent stacks.

Tests live under `./test/`, one file per `src` module that has one (`test/crypto_test.rs` for `src/crypto.rs`, etc.), wired up as explicit `[[test]]` targets in `Cargo.toml`. Two exceptions: the client-side modules that need a live socket and audio device (`main.rs`, `connect.rs`, `session.rs`, `channel.rs`, `direct_message.rs`, `voice_stream.rs`) have no test file of their own — their testable logic is exercised through `test/server_test.rs`'s end-to-end tests and the UI tests; and `test/ui_common.rs` is shared scaffolding for the three UI test files (included via `#[path] mod ui_common;`), not a `[[test]]` target.

Two further `[[test]]` targets sit alongside the per-module ones and don't follow the one-file-per-module rule, because neither tests a single module:

- `test/cucumber/main.rs` (`harness = false`) — a behaviour-driven acceptance layer running the Gherkin scenarios under `features/` via cucumber-rs, grouped by capability (`channels/`, `connecting/`, `encryption/`, `help/`, `identity/`, `messaging/`, `presence/`, `voice/`) rather than by source file.
- `test/traceability/main.rs` — validates the requirement model in `requirements/requirements.toml` against the suite and generates the traceability report, so the model can't silently drift from the tests it claims are covering it.

## Server startup

The server is started as:

- `aloo --server` — no auth, open to anyone.
- `aloo --server --enc rsa <keyfile>` — server holds an RSA keypair loaded from `<keyfile>`; clients authenticate/encrypt against it.
- `aloo --server --password <MYPASSWORD>` — server checks a single shared password against every connecting client.

Other server flags: `--bind <ADDR>` (default `0.0.0.0`), `--port <PORT>` (default `7878`). The server always seeds one default public channel, `general`, so a freshly started server has something for the first-connected client to join.

Every server start persists its resolved `--bind`/`--port`/auth choice to `~/.aloo/settings` (`server_bind`, `server_port`, `server_auth_type` + its one associated value). Any of `--bind`, `--port`, `--enc`, `--password` given on the command line wins and gets persisted; whichever of these flags is *not* given falls back to what's already in `~/.aloo/settings`. So `aloo --server` alone reuses this machine's last server configuration in full - including auth - and a supervisor that restarts a crashed server with the exact same bare `aloo --server` command comes back up listening the same way, without needing to remember or re-pass the original flags.

## UI

### Not connected UI

A modal is shown, 64 columns wide - clamped to the terminal's own width if it's narrower than that, so this is a target rather than an absolute floor - centered vertically and horizontally, containing the details to connect. Either way it's noticeably wider than the original 50-column box it replaced. Focus defaults to the **host** field the moment the popup opens, with a blinking text cursor at the end of its (initially empty) value — same as every other text field once it's focused (see below).

- **host / ip**, **port**, **nickname** — each its own titled, bordered box (not just a plain label/value line).
  - **nickname** — the display name used in channels and DMs; must be unique among currently connected clients (see Functionality below), capped at 10 characters (typing beyond the limit is a no-op), no whitespace allowed.
- **id_store** — its own titled, bordered box, same as host/port/nickname — the file path for the local identity-pinning store (see Functionality #9 below). Prefilled with `idstore::default_path()`'s result: always `~/.aloo/ids_store` — the app never reads or writes a loose file in the current working directory of its own accord. A plain editable text field — any path is accepted, and it doesn't need to exist yet, so a user who deliberately wants it somewhere else (including a local file) can still type one in.
- **server_key** (2 fields wrapped in a border) — this key is used to authenticate to the server
  - type: `rsa` / `password` / `none`
  - if `rsa`: a file field, selected via the in-TUI file browser
  - if `password`: a text input field for the password
  - if `none`: no additional field
- **my_key** (2 fields wrapped in a border) — this key is used to decrypt messages addressed to the user
  - type: `rsa` / `password` / `none` / `rsa_per_msg` / `pq_hybrid` (defaults to `pq_hybrid` — this app's strongest identity, quantum-resistant and hedged with classical RSA-4096. Unlike a plain `rsa` file, its `file_pub`/`file_priv` fields never start blank: they're prefilled - from `~/.aloo/.cache`'s most-recently-used entry if one exists (`docs/PROTOCOL.md` §13.9's connect-popup cache), or otherwise a freshly-assigned, not-yet-generated location under `~/.aloo/` - and connecting auto-generates the actual keys there if they don't exist yet, so this default never blocks on manual preparation either — see Functionality #11)
  - if `rsa`: `file_pub` and `file_priv` fields, each selected via the in-TUI file browser
  - if `password`: a text input field for the password
  - if `none`: no additional field
  - if `rsa_per_msg`: an `own_next_keys` field (its own titled, bordered box, same as `id_store`) — see Functionality #6 and #9 below. The bootstrap keypair itself is still always freshly autogenerated in-process, but `own_next_keys` is where this client's own per-peer continuity keys are persisted so a peer can verify "it's still me" after a reconnect. Prefilled with `own_next_keys::default_path()`'s result: always `~/.aloo/own_next_keys`, same rule as `id_store` above.
  - if `pq_hybrid`: `file_pub` and `file_priv` fields, same shape as `rsa` — pointing at a keybundle (prefilled/auto-generated as above, or overridable by hand, including pointing at one `aloo --keygen-pq-hybrid <prefix>` produced externally - there's no `openssl`-equivalent for ML-DSA-87/ML-KEM-1024, but running it yourself is no longer required). See Functionality #11 and `docs/PROTOCOL.md` §13, §13.9.
- **Connect button** — a bordered button below the fields, highlighted when focused. The highlight (solid background) fills only the button's interior; its border keeps its own plain/focus style rather than being swallowed into the highlighted fill, consistent with every other bordered/focusable element in this app. Tab cycles through every field in order and wraps around to this button; pressing Enter while it's focused validates the form and, if valid, connects. Pressing Enter on it with an invalid/incomplete form shows a validation error below instead (e.g. "host is required", "nickname is required").

Every focused text field (host/port/nickname, and a `password`-type `server_key`/`my_key` value) shows a blinking cursor at the end of its current value, not just a reversed-color highlight.

The `my_key` type controls how the user's own key material is sourced/protected locally, and — for `rsa_per_msg` only — also switches on an ongoing key-rotation behavior for the rest of the session (Functionality #6). Every type but `pq_hybrid` uses an RSA keypair for actual channel/DM encryption — the public-key exchange that happens on joining a channel (see below) always applies; `pq_hybrid` instead uses the hybrid scheme in Functionality #11.

**File browser**: a custom in-TUI widget (not an OS dialog) that supports back/forward navigation through directories and file selection. Reused as-is for the `/file` send flow's own browser (`docs/SPEC.md` Functionality below). The visible list scrolls to keep the selected entry on screen, so a directory with more entries than fit in the popup's height can still be navigated all the way to its last entry with Up/Down, not just the ones that happen to fit on first open.

**Nickname rejection**: if the server rejects the nickname as already taken, the client returns to this popup with an error message shown and focus already on the nickname field — every other field (host, port, keys) is preserved, so the user only needs to change the nickname and press Connect again.

### Connected UI

The UI is composed of:

- **Top area** (full width) — tabs with the channels the user has joined (one tab selected at a time), followed right-aligned at the end of the tab row by, in order: a **Conn:`<-|BAD|NORMAL|GOOD>`** indicator, two spaces, a **CPU:`<pct>`%** indicator, two spaces, the **Ctrl+H: Help** hint (Functionality #7), and then a two-space gap and an animated key-regeneration spinner whenever `rsa_per_msg` is actively rotating a key in the background (Functionality #6). Borderless.
  - **CPU:`<pct>`%** — this client's own system-wide CPU usage, resampled roughly every 300ms. Rendered green below 25%, red at 25% and above.
  - **Conn:`<-|BAD|NORMAL|GOOD>`** — a rough read on how lively the connection feels, resampled once a second from the average gap between the last 1-3 protocol messages actually seen moving over the socket in either direction (there is no ping/pong in the wire protocol, so this is message cadence, not a true round-trip time). `-` (white) before any message has been exchanged yet this session; otherwise `BAD` (red), `NORMAL` (yellow) or `GOOD` (green) by how short that average gap is.
- **Left area / sidebar** (20% wide) — list of users in the selected channel, each shown with an encryption tag next to their name (position depends on `my_key` type — see below; a narrow terminal clips this like any other overlong sidebar entry). Connected users are rendered in green; a user who has gone offline but is kept listed (Functionality #8) is rendered in soft gray instead; a user whose identity hasn't been verified yet, or was explicitly rejected (Functionality #9), is rendered in red regardless of offline status — the more urgent of the two.
- **Identity review popup** — a centered, bordered popup that opens automatically the instant a peer's identity fails to check out (Functionality #9), on top of whatever else is on screen (even the help overlay). Names the peer, explains the specific mismatch, and offers two buttons, **Accept** and **Reject** (`Reject` focused by default); `Left`/`Right`/`Tab` move focus between them, `Enter` confirms - no other key does anything while it's open, and there's no Esc-to-dismiss, since the whole point is an explicit decision rather than a wait-and-see banner. If more than one peer's identity is unresolved at once, only the oldest unshown one is displayed; resolving it (either button) reveals the next.
- **Main area** (80% wide) — messages in the selected channel.
- **Bottom bar** (full width) — text input where the user composes and sends a message; the cursor blinks at the end of the typed text whenever this bar is focused (the default focus on connecting). While viewing a private room whose peer is offline, this bar instead shows `(user offline)` in red and refuses all typing (Functionality #8).

The private-message room (Functionality #3) titles itself the same way: `Private: ` followed by the same tagged-name form.

**Encryption tag convention** (`aloo::proto::KeyMode::label`/`format_with_name`) — one of five, based on the `my_key` type that user connected with (see Functionality #6 for `rsa_per_msg`'s wire implications, Functionality #11 for `pq_hybrid`'s):

| `my_key` type | Tag | Position |
| --- | --- | --- |
| `rsa_per_msg` | `🔒 RSAPM` | after the name: `name 🔒 RSAPM` |
| `rsa` | `🔒 RSA` | after the name: `name 🔒 RSA` |
| `password` | `🚨 PWD` | after the name: `name 🚨 PWD` |
| `none` | `🚨 PLAIN` | after the name: `name 🚨 PLAIN` |
| `pq_hybrid` | `🛡️ PQH` | after the name: `name 🛡️ PQH` |

Every tag is unbracketed and trails the name, reading as an annotation on it - one shared convention across all five `my_key` types, the way `rsa_per_msg`'s always has (its identity is a moving target, a new key every message). 🔒 marks a persistent or rotating RSA identity (`rsa` file, `rsa_per_msg`); 🚨 flags the two less-durable sourcings (`password`-derived, `none`/auto-generated) that don't carry an identity across separate connections; 🛡️ is `pq_hybrid`'s own icon — file-backed and durable like `rsa`, but marked as the strongest tier (quantum-resistant signing and key exchange, each hedged with RSA-4096 — `docs/PROTOCOL.md` §13). Every tag still means real per-recipient encryption (Functionality #1, #11); the icon is about identity durability, not "unencrypted".

A border wraps the sidebar, the main area, and the bottom bar. Whichever of the three currently holds keyboard focus is highlighted with a yellow border so it's clear where input goes; the bottom bar overrides this with a red border while actively recording a voice message.

**The message log (both the channel view and the private-message room) is scrollable.** While it has focus: `Up`/`Down` move the selection one message at a time, `PageUp`/`PageDown` jump by 10, and `Home`/`End` jump straight to the oldest/newest message — all clamped at the ends of the history rather than wrapping around. Opening a channel or a private room starts scrolled to its newest message; a new incoming or outgoing message pulls the view along with it only if it was already showing the newest message, so scrolling back through history to read isn't interrupted by new traffic arriving.

## Channels

Channels are dynamic:

- **Public channels** are broadcast by the server and appear automatically as tabs for all connected clients.
- **Private channels** are joined by pressing **Ctrl+J**, which opens a popup to type the channel name.

When connected, the server sends the list of available (public) channels, which render as top tabs (no border on this tab row); the first tab is selected and immediately joined automatically (no dwell delay for this first, automatic join — the 3-second dwell only applies to later `[`/`]` switches, see Functionality #2).

When a tab is selected, the user joins that channel. The join is broadcast to all users already in the channel, and each of those users sends their public key to the newly joined user, who stores it in memory (used to encrypt messages sent to them). In practice this key exchange is relayed through the server as part of channel membership events (the server already knows every connected client's public key from `Identify`), not a direct peer-to-peer transfer — the server still never decrypts or reads message content, only relays already-public identity metadata.

## Functionality

1. **Send a text message to the channel.** The message is encrypted separately for each recipient, using that recipient's RSA public key — no AES/hybrid encryption is used. Note: since raw RSA only encrypts small fixed-size blocks (190 bytes of plaintext per block with a 2048-bit key under OAEP/SHA-256 — `256 - 2*32 - 2`, see `crypto::max_chunk_len` and `docs/PROTOCOL.md` §8.1), longer payloads are split into multiple blocks, each encrypted per recipient.

2. **Join a different channel.** Press `]` to move to the next channel or `[` for the previous one; after remaining on that tab for 3 seconds, the user joins it. (Ctrl+J opens the popup to join/create a private channel by name.)

3. **Send a private message to a user.** Move through the list of users in a channel and press Enter to open a full-screen private room with that user. Press Escape to return to the channel view. Messages exchanged remain in memory for the session. The private room can be reopened by selecting the same user again and pressing Enter.
   - In the channel view, a user is preceded by an envelope emoji once there's at least one message (sent or received) in their private room — not merely because that room was opened; opening an empty DM and leaving it again shows no envelope until an actual message exists. The envelope stays visible (solid) for the rest of the session once earned, whether the messages in it have been read or not, including after the room is reopened and marked read.
   - If there are unread messages from that user, the envelope blinks instead of staying solid; reopening their room (marking it read) stops the blinking but does not remove the envelope, since there's still history.
   - Outgoing DM messages are encrypted with the receiver's public key; incoming DM messages are decrypted with the user's own private key.

4. **Send a voice message** by holding Space (while focus is not on the compose bar - Space there just types a literal space) and releasing it to stop. Voice is streamed live, not recorded-then-sent: while Space is held, captured audio is chunked (`voice::CHUNK_INTERVAL`, 100ms) and sent to the network as it's captured, and the receiving side plays each chunk as it arrives, rather than waiting for the whole message. While recording, a 🎤 "recording..." indicator appears inline at the end of the input bar and the bar's border turns red.
   - **Live appearance and finalization.** Both directions show the in-progress message immediately (a pulsing "streaming..." block in the log) and it turns into a normal, replayable voice block only once the stream ends. The user can replay a finished voice message later by scrolling through the channel/DM history and pressing Enter on it, which renders in bold red, marked with a 🔴 and labeled with its actual recorded duration, e.g. `🔴 voice (12sec)` — the duration shown always reflects the real length of that specific message, not a fixed value. Any partial second rounds up (1ms shows as `1sec`, 1001ms as `2sec`), except a genuinely instantaneous 0ms recording, which shows `0sec` rather than rounding up to `1sec`.
   - **Release detection** works on any terminal. At startup the client queries whether the terminal actually supports the Kitty keyboard protocol's release reporting (`crossterm::terminal::supports_keyboard_enhancement`, not just whether enabling it succeeded — a terminal can accept the escape sequence without honoring it). If it does, stopping relies solely on that genuine `Release` event: recording continues through any pause or silence for as long as Space is physically held, and only stops when it's actually released. If it doesn't, there is no way to observe a release directly, so the app falls back to watching for the OS's keyboard auto-repeat (a steady stream of `Press` events roughly every 30-50ms once repeating, after an initial OS repeat-delay commonly in the 500-650ms range) and treats ~900ms of silence since the last one as "released" — an approximation, used only when nothing better is available. Both stopping mechanisms are no-ops when nothing is actually being recorded: a `Release` event with no matching prior `Press` (e.g. one delivered right as a channel switch or DM close ends a recording some other way) does nothing, and so does the idle-timeout check firing with no recording in progress.
   - **Failure handling.** If starting the recorder fails (e.g. no microphone), or if Space is pressed with nowhere to address the stream to (not joined to any channel, no active DM), the indicator clears immediately (or never starts) rather than continuing to claim a recording is happening. The failure reason is tracked internally but deliberately not rendered on screen - this kind of environment tends to surface plenty of transient, self-recovering audio errors (buffer under/overruns, PulseAudio status-query hiccups) that aren't worth interrupting the display for.
   - **Encryption and cost.** Each chunk is encrypted the same way as text (per-recipient RSA, chunked into RSA-OAEP blocks) - live streaming multiplies the message rate, not the total RSA work per second of audio, which is purely a function of bytes-of-audio regardless of chunking.
   - **Jitter and mixing.** On the receiving end, a jitter buffer (a small per-source prebuffer before playback starts) absorbs ordinary arrival jitter between chunks so normal network/CPU timing variance doesn't produce audible gaps; multiple simultaneous incoming streams (two people talking near-simultaneously) are mixed together rather than queued one behind another.
   - **End-of-message chime.** A short "message ended" sound (`assets/end.wav`) plays through the same mixer both when the sender releases Space and when an incoming stream finishes, so both ends of a voice message get the same audible cue. Bundled as WAV rather than the project's original `assets/end.mp3` so it can be decoded (`voice::decode_wav_to_mono`) without an MP3 crate dependency - a WAV's PCM payload is read directly.
   - **Device handling.** Multi-channel input (an input device negotiating stereo-or-more, common even for a physically mono mic) is downmixed to a single mono sample per moment in time as it's captured, before anything else touches it. On Linux, capture/playback prefers a device routed through PulseAudio over whatever the raw ALSA host reports as default, when one is available - the plain ALSA host normally requires each process to have exclusive access to a device, which would otherwise make it impossible for two `aloo` clients on the same machine (the normal way to test a channel/DM locally) to both use the mic/speaker at once.
   - **Global push-to-talk.** A second trigger, bound to **Ctrl+Alt+P** by default, does the same thing as holding Space - starts a live stream to whatever channel/DM was last active and stops it on release - but works even while `aloo` isn't the focused window, so speaking doesn't require switching back to the terminal first. Configurable in `~/.aloo/settings` (created with these defaults on first run if missing): `global_ptt_enabled` (`true`/`false`) and `global_ptt_shortcut` (any combo `global_hotkey::hotkey::HotKey` parses, e.g. `ctrl+alt+p`, `shift+F1`) - an unparseable shortcut falls back to the default with a startup warning rather than failing to start. Space and the global shortcut can never stop a recording the other one started; a global recording is never subject to Space's idle-silence auto-stop guess, since the OS always reports its release for real. Like Space, the end-of-message chime (above) plays only once, on release - there's no visible "recording..." indicator while the app isn't focused, but the chime firing mid-recording on press was found more confusing than helpful and was removed. **Platform support:** Windows and macOS, and Linux under X11 only - Wayland compositors have no equivalent capability at all, so aloo detects this at startup and prints a one-line warning instead of registering (Space still works normally while the app is focused).

5. **Choose a nickname and have it enforced as unique.** The nickname is set in the connect popup (prefilled from the OS username, editable, no whitespace allowed, capped at 10 characters). On connecting, the server rejects the `Identify` request and closes the connection if that nickname is already in use by another currently-connected client; the client then returns to the popup with the error shown, ready to retry with a different nickname. The check is race-free: two simultaneous connection attempts for the same nickname can't both succeed. A nickname is freed again as soon as its holder disconnects.

6. **`rsa_per_msg`: a self-encryption mode that rotates your own key on every message.** Selected as the `my_key` type in the connect popup, instead of a static keypair that lasts the whole session. Full wire-level detail lives in `docs/PROTOCOL.md` §11; from the user's point of view:
   - A fresh RSA keypair is generated locally (never shelled out to an external command) for each peer relationship, and re-generated every time a message is sent to or received from that specific peer — so the key protecting any one already-exchanged message is retired shortly after and never reused. These keys are 4096 bits — larger than the 2048-bit keys every other `my_key` type uses — trading slower key generation for a bigger security margin per (typically short-lived) key.
   - Every rotation is signed with the key it replaces, so peers can tell a genuine new key from a forged one before trusting it; the very first key for a peer (announced on joining a channel, same as today) is trusted on first use, same as static mode.
   - This is invisible in the UI beyond ordinary send latency: if you send a message to someone using `rsa_per_msg` before their next fresh key has arrived, it isn't dropped — it's held in memory and sent automatically the moment that key shows up, in the order it was typed. There's no separate "pending" indicator; the message simply appears in the log once it goes out.
   - Live voice messages (Functionality #4) are exempt from per-chunk rotation (regenerating a 4096-bit RSA key fast enough for 100ms audio chunks isn't feasible) — an entire voice message counts as one exchange for rotation purposes, and a recipient without a ready key at the moment you start recording is simply not sent that particular voice message (same as the existing partial-delivery behavior when a client only has keys for some channel members).
   - Rotating a key doesn't freeze the UI: the actual key generation runs on a dedicated background thread (`docs/PROTOCOL.md` §11.10), not on the same task that redraws the screen and processes incoming messages. Ending a voice message addressed to several `rsa_per_msg` recipients, or sending a channel text message to several of them, queues one rotation per recipient on that background thread rather than generating them one after another in front of the UI.
   - **Regeneration spinner.** While at least one rotation is in flight on that background thread, an animated white ASCII spinner (`_ - \ | / -`, one frame advanced per UI tick) is shown at the top right of the screen, immediately after the `Ctrl+H: Help` hint (itself dimmed gray), separated from it by two spaces (`Ctrl+H: Help  _`). It disappears the instant no rotation is pending, and always starts again from the first frame (`_`) the next time one begins, rather than resuming mid-cycle. This is purely a client-local UI cue — it has no wire-protocol meaning and isn't sent to or expected from peers.
   - **Surviving a reconnect.** This client's current per-peer key for each `rsa_per_msg` relationship is also saved to the `own_next_keys` file (see "Not connected UI" above). If you disconnect and reconnect, the moment you see a peer you'd previously rotated with again, that same key is re-asserted to them automatically — before you've typed anything — so their client can recognize you as the same identity as before instead of a stranger who happens to share your nickname. See Functionality #9 for the receiving side of this.

7. **In-app help, toggled with Ctrl+H.** Works from any view or mode — the channel view, an open private room, mid-recording, even with the join-private-channel popup already open — and takes priority over everything else, since it's checked before any other key handling. A hint (`Ctrl+H: Help`) is shown at the top right of the screen, past the end of the channel tabs, as a reminder that it's always available.
   - Pressing it opens a centered popup covering how to join a hidden (private) channel, how to send a voice message, how to send/receive a file (Functionality #10), what each of the five encryption tags means, and a general keybinding reference — everything in this document's Functionality section, condensed.
   - The popup's content is taller than fits most terminal windows, so it scrolls: `Up`/`Down` move one line, `PageUp`/`PageDown` jump by `HELP_SCROLL_PAGE` lines, and `Home`/`End` jump straight to the top/bottom — clamped so it can't scroll past either end. It always reopens scrolled to the top, never wherever it was left last time.
   - While the popup is open, every other key is absorbed (no typing leaks into the compose bar, no navigation happens underneath) except Ctrl+H itself, which closes it again and returns to exactly whatever was showing before, and the scroll keys above. Esc does not close it — only Ctrl+H does, since Esc already means something else (close the current private room) when help isn't open, and the popup deliberately doesn't try to disambiguate the two.

8. **Offline users.** When a user's connection closes entirely (as opposed to them leaving one channel while staying connected elsewhere — Functionality #2), every peer who shared a channel with them is notified (`docs/PROTOCOL.md` §6.4). What each peer's client does with that depends on whether it has private-message history with the now-offline user:
   - **With at least one message (sent or received) in that user's private room:** they're kept listed in every channel they'd joined, rather than removed, with their name rendered in soft gray instead of the usual green (see "Connected UI" above) — so their history stays reachable (reopen their private room the same way as any other user, Functionality #3) without pretending they're still around.
   - **With no private-message history:** they're removed from the channel's user list exactly as if they'd explicitly left it (Functionality #2) — there's nothing to keep them around for.
   - **Opening (or already having open) an offline user's private room** replaces the compose bar's contents with `(user offline)` in red, and the compose bar stops accepting keystrokes entirely — no typing, no sending — for as long as that user stays offline. This applies regardless of whether they were kept listed in any channel, since it's driven by "is this specific peer offline right now", not by the retention rule above. This is scoped to that one peer's room only, not a global switch: the channel compose bar and any other, still-online peer's private room keep working normally the whole time, including one reopened for a peer who went offline earlier and is back.
   - **Voice recording (Functionality #4) ignores an offline direct-message target.** Holding Space while viewing an offline user's private room does nothing — no recorder is started, nothing is sent — the same as pressing Space with no channel joined and no private room open. A channel voice recording is unaffected by one of its members being offline: it's simply excluded from that recording's recipients, same as any other member the sender doesn't currently have a way to reach.
   - A user going offline is permanent for the rest of the session from every other client's point of view — a `UserId` is never reassigned (`docs/PROTOCOL.md` §3), so the same person reconnecting is always a brand new identity, never a transition back to "online" for the old one.

9. **Identity pinning (`id_store` / `own_next_keys`): deciding whether to trust a nickname that reconnects under a different key.** Full model in `docs/PROTOCOL.md` §12; from the user's point of view:
   - The client keeps a small local file — set via the connect popup's `id_store` field — that remembers each nickname's **full public key** (hex-encoded, not just a hash of it) from the last time it was seen, for the `rsa`, `password`, and `rsa_per_msg` `my_key` types. Storing the whole key (not a fingerprint) means a pinned entry can be verified against an actual key file, not just trusted as "some hash matched" — a fingerprint is still computed on the fly for display in the review popup below.
   - `rsa`/`password` are checked by simple comparison — that key is never supposed to change, so any difference at all is the signal. `rsa_per_msg` is checked differently, since its key legitimately changes on every rotation by design: a reconnecting `rsa_per_msg` peer is verified by signature instead — did the new key come with proof it was produced by whoever held the key you trusted for that nickname last time (`own_next_keys`, Functionality #6's "Surviving a reconnect")? A valid proof updates the pin silently, no popup. **Merely re-announcing a self-consistent key with no proof at all does not count** — a peer who never even attempts to prove continuity (rather than attempting and failing) is treated exactly as suspiciously as one who tried and failed, not as a fresh, unremarkable contact: an `rsa_per_msg` nickname that already has a key pinned from a previous session is gated the instant it's seen again, before any proof attempt, and only a valid proof (or a person's **Accept**) lifts that gate. Only `none` is entirely untracked — that key is freshly autogenerated every session with no continuity mechanism at all, nothing to verify against.
   - The first time a nickname is ever seen, or when it's seen again with the same (or provably continuing) key as before, nothing happens — this is invisible in normal use. A first sighting is still saved to disk immediately, so it's pinned for the next reconnect too.
   - If a nickname with a pinned key reconnects **without a verified proof of continuity** — a byte change for `rsa`/`password`, or, for `rsa_per_msg`, either a resume signature that doesn't check out against anything pinned for that nickname or no resume attempt at all — the **identity review popup** (see "Connected UI" above) opens automatically, naming the user. This can mean the person genuinely regenerated their key (or lost their `own_next_keys` file), or that someone else is now using that nickname — the app doesn't decide which; it puts the decision to the user via **Accept** or **Reject**, rather than guessing.
   - The two cases differ in what the popup shows and what happens to the pin, because they detect different things (`docs/PROTOCOL.md` §12.4 vs §12.6.3/§12.6.4):
     - **`rsa`/`password` (byte change):** the popup names a short fingerprint of both the old and the new key.
     - **`rsa_per_msg` (failed or missing resume proof):** there is no meaningful "old vs new" fingerprint pair to show — the key is *supposed* to change every rotation — so the popup names the user and says continuity hasn't been proven, worded differently depending on whether a proof attempt actually failed or simply never came.
   - **Accept** trusts the new key from that point on: it's saved to disk immediately — synchronously, in real time, not batched or deferred — and any of that peer's channel/DM messages that arrived while the review was unresolved (held rather than shown, see below) are revealed into the log, in the order they arrived. **Reject** writes nothing to disk at all — the previous pin, if any, is left exactly as it was — and is never a permanent block: selecting that peer again (Enter on their sidebar entry) reopens the same popup for reconsideration, rather than staying silently stuck.
   - Until a peer's review is resolved (`Pending`), and for as long as it stays `Rejected`, messaging with them is gated: this client won't send them anything (excluded from a channel send, and their private room can't be opened or typed into at all), and anything they send is held rather than displayed — decrypted normally, since that only needs *this client's* own key, but not shown until they're `Accept`ed. Their sidebar entry renders red the whole time, taking priority over the offline-gray color. A channel message is otherwise unaffected: it still reaches every other, verified member.
   - Several peers can be unresolved at once; the popup shows one at a time, in the order their mismatches were detected — resolving the one showing (either button) opens the next automatically.

10. **Send a file to a channel or a user, with the recipient's consent.** Type `/file` in the compose bar and press Enter (must be joined to a channel, or have a non-offline, verified DM room open — otherwise this does nothing and the typed `/file` stays put, same as Space with nowhere to record voice to). A popup file browser opens, centered on screen — the same in-TUI widget (`Up`/`Down` select, `Enter` open a directory or pick a file, `Left`/`Right` back/forward, `Esc` cancel) the connect popup's `rsa` key fields already use.
    - **Confirmation.** Selecting a file (Enter on it, not a directory) replaces the browser with a confirmation box: `Send "<filename>" to #<channel>?` or `Send "<filename>" to <username>?`, with two buttons, **Send file** and **Discard** — `Discard` focused by default, same reasoning as the identity review popup's `Reject`-first default (Functionality #9): sending should never be one accidental Enter away. `Left`/`Right`/`Tab` move focus, `Enter` confirms. Choosing **Discard** returns to the file browser at the same directory (not all the way back to the compose bar); pressing `Esc` on the confirmation box does the same. `Esc` on the browser itself cancels the whole `/file` flow. Filenames longer than 230 characters are cropped at the end before being offered (`docs/PROTOCOL.md`'s file transfer section) — the receiving client independently crops again on whatever it actually receives.
    - **Offering.** Choosing **Send file** sends an *offer* — filename and size, encrypted exactly like a text message (RSA-OAEP per recipient, split into blocks the same way, `docs/PROTOCOL.md` §8.1) — to every ready recipient; nothing is read from disk yet. There is no size cap: since the file itself is streamed in small chunks only once accepted (below), the old whole-file-in-one-message limit no longer applies. A channel send is one independent offer per member, each shown as its own row in your log (below) — one recipient accepting doesn't wait on, or get affected by, another rejecting.
    - **The recipient's popup.** Before any file bytes arrive, the receiving side sees a centered popup — accompanied by a chime (`assets/bell.wav`) — reading `<nickname> is sending "<filename>" (<size>) via #<channel>` (or "via a private message" for a DM). Two buttons, **Accept** and **Reject** — **Accept focused by default**, the opposite of this app's usual safety-first default (Functionality #9's identity review, this flow's own Discard-first confirmation above): accepting an incoming file is the common case here, so it shouldn't cost an extra keystroke. `Left`/`Right`/`Tab` move focus, `Enter` confirms. Several offers arriving close together queue and show one at a time, same as identity reviews.
    - **Appearance and progress.** Both sides render the message as a paperclip and the filename, e.g. `📎 report.pdf`, in the channel/DM log — a channel send's per-recipient rows also name who each is addressed to. Before a decision, the sender's row reads "(waiting for accept...)"; once **Accept**ed, the file streams in small chunks straight to `~/.aloo/downloads` (never held whole in memory on either side) and both sides' rows show a live progress bar and percentage until every byte has moved, at which point the row settles back to the plain paperclip-and-filename look. Choosing **Reject** ends it there — the sender's row shows "(rejected)" instead, so declining a file is as visible to them as accepting one.
    - **Trust gating and offline peers** work exactly like text (Functionality #8/#9): an offer from a `Pending`/`Rejected` sender is decrypted but held — no popup, no chime — until they're `Accept`ed, at which point it's queued for real; a gated or offline channel member is simply not offered the file at all, same as text/voice; an offline or gated DM peer's room can't receive one at all (same gate that already blocks `/file` from starting in the first place).

11. **`pq_hybrid`: a post-quantum hybrid encryption method** — ML-DSA-87+RSA4096 signing, ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption. Full model in `docs/PROTOCOL.md` §13; from the user's point of view:
    - Selected as the `my_key` type in the connect popup - and selected by default. Unlike every other type, its keys aren't generated fresh in-process at connect time; they live in a keybundle file pair (`file_pub`/`file_priv`, the same shape `rsa` uses). Unlike `rsa`, though, you don't have to prepare that pair yourself: the popup prefills the fields (from `~/.aloo/.cache`'s most-recently-used entry for a server you've connected to before, or otherwise a freshly-assigned location under `~/.aloo/`), and connecting transparently generates the actual keys at that location the first time it's used, if they don't already exist (`docs/PROTOCOL.md` §13.9). `aloo --keygen-pq-hybrid <prefix>` (writes `<prefix>` and `<prefix>.pub`, mirroring `openssl`'s `my_key`/`my_key.pub` convention for `rsa`) is still there if you want to generate one yourself - e.g. to point both files at a specific, memorable location, or to produce one to move to another machine - but it's optional now, not required.
    - **The connect popup remembers your `pq_hybrid` identity per server.** After connecting (attempted or not - whichever files were used to try), `~/.aloo/.cache` records that `(host, port)`'s `file_pub`/`file_priv`. Reopening the app, or returning to the same server later in one session, prefills the exact same identity automatically - a different server you haven't used before still gets its own freshly-assigned location the first time.
    - Text, file, and voice messages are all signed with **both** ML-DSA-87 and RSA-4096 before being encrypted — a receiver only accepts a message if **both** signatures check out, so a break in either primitive alone isn't enough to forge one. The bulk data is AES-256-GCM-encrypted once per send (not re-encrypted per recipient the way RSA methods are), and that one-time key is separately wrapped for each recipient by combining an ML-KEM-1024 exchange with a second, independent RSA-4096 encryption — recovering it needs breaking both, not just one.
    - **Only another `pq_hybrid` user can send to a `pq_hybrid` user.** Producing a valid message to a `pq_hybrid` recipient needs the *sender's* own ML-DSA-87/RSA-sign identity, which no other `my_key` type has — a channel member using `rsa`/`password`/`none`/`rsa_per_msg` simply can't reach a `pq_hybrid` peer, the same silent exclusion as any other unreachable recipient (an offline member, a channel member `rsa_per_msg` hasn't finished a key exchange with yet). A `pq_hybrid` user can still message everyone else normally.
    - Voice messages work the same way as text — the expensive signing/key-exchange work happens once per recording, not per 100ms chunk, so holding Space to talk feels identical to any other method.
    - Its identity is static (loaded from the keybundle file, not regenerated every session) and file-backed, so it's pinned in `id_store` exactly like `rsa`/`password` (Functionality #9) — a `pq_hybrid` nickname reconnecting under a different keybundle triggers the same identity review popup a changed `rsa` key would.

## Encryption: how each method actually works

Implementation map for the five `my_key` methods and the two things they
encrypt (text and voice), across both destinations (channel and DM). Wire-level
rules live in `docs/PROTOCOL.md`; this section is the "where is it in the code"
index. Line numbers are accurate as of the commit that added this section —
each entry names its function too, so a drifted line number still resolves.

### One primitive, four key sourcings — plus `pq_hybrid`'s own

Four of the five methods share **one** encryption algorithm: RSA-OAEP with
SHA-256, applied once per recipient. No AES, no hybrid scheme, no shared
session key (Functionality #1). Because raw RSA only takes a fixed-size
block, anything longer is split into several blocks and each is encrypted
independently. `pq_hybrid` (Functionality #11) is the exception - its own
primitives live in `crypto/pq.rs`, covered in its own subsection below.

| Step | Where |
| --- | --- |
| Bytes-per-block for a key | `crypto/mod.rs:187` `max_chunk_len` |
| Encrypt (splits into blocks) | `crypto/mod.rs:197` `encrypt_chunked` |
| Decrypt (rejoins blocks) | `crypto/mod.rs:221` `decrypt_chunked` |
| Wire shape of one encrypted body | `proto.rs:218` `Envelope` |

The four RSA-based `my_key` methods differ **only in where the RSA keypair
comes from**. `none` is not plaintext despite its `[🚨 PLAIN]` tag — see the
tag table above. The single branch point is `connect.rs:178` `resolve_my_keypair`
(which also has `pq_hybrid`'s own arm, loading a keybundle instead of a
plain RSA keypair - see below):

| Method | Keypair | Where |
| --- | --- | --- |
| `none` | fresh 2048-bit from OS randomness, kept for the session | `crypto/mod.rs` `KeyPair::generate` |
| `password` | 2048-bit, deterministically derived: PBKDF2-HMAC-SHA256 (100k rounds, fixed salt) seeds a ChaCha20 RNG, so the same password always rebuilds the same key | `crypto/mod.rs` `KeyPair::from_password` |
| `rsa` | 2048-bit, loaded from PKCS#8 PEM files | `crypto/mod.rs` `KeyPair::load_from_files` |
| `rsa_per_msg` | fresh **4096**-bit bootstrap key, then rotated per peer forever after | `crypto/mod.rs` `KeyPair::generate_with_bits` |

The choice is announced to peers as `proto.rs` `KeyMode` in `Identify`, which
is what drives the encryption tag and (for `PerMessage` only) rotation.

After key sourcing, **the three static RSA methods are indistinguishable in
code**: `session.rs` (`run_connected_session`) wraps whichever private key
was produced in `rekey::OwnKeys` regardless of method, and for static
methods its per-peer map stays empty so `rekey.rs` `decrypt_from` falls
straight through to that one key. `pq_hybrid` instead populates
`SessionState::own_pq_private` and leaves `own_keys` as `None` (`session.rs`,
around the `ResolvedIdentity` match in `run_connected_session`) - see
`session::decrypt_envelope_for` for the resulting branch.

### Text messages

| | Channel | DM |
| --- | --- | --- |
| Send | `channel.rs:31` `handle_send_text` | `direct_message.rs:37` `handle_send_text` |
| Encrypt (RSA methods) | `channel.rs:184` `encrypt_for_each` — loops recipients | `session.rs:533` `encrypt_for_one` — one recipient |
| Encrypt (`pq_hybrid`) | same `encrypt_for_each`, dispatching to `session.rs:546` `encrypt_hybrid_envelope_for` per `pq_hybrid` recipient | `direct_message.rs` `encrypt_for_recipient`, same dispatch |
| Wire message | `ClientMessage::SendChannel`, one `Envelope` per member | `ClientMessage::SendDirect`, one `Envelope` |
| Server relay (no decrypt) | `server.rs` `route_channel_message` | `server.rs` `route_direct_message` |
| Receive + decrypt | `session.rs:1052` `decrypt_envelope_for` → `rekey.rs` `decrypt_from` (RSA) or `crypto/pq.rs` `decrypt_hybrid` (`pq_hybrid`, dispatched by *our own* `own_key_mode`) | same |

A channel message is therefore encrypted N times for N members — the server
forwards each member only their own `Envelope` and cannot read any of them.
`pq_hybrid` recipients that a non-`pq_hybrid` sender can't address at all
(`channel.rs:79` `can_address`) are excluded before encryption even starts -
see "What `pq_hybrid` adds" below.

### Voice messages

Voice is streamed live, not recorded-then-sent (Functionality #4), so
encryption happens per 100ms chunk (`voice.rs:33` `CHUNK_INTERVAL`) on a
dedicated thread — never on the async event loop.

| Stage | Where |
| --- | --- |
| Recipients' public keys parsed **once** at record-start | `channel.rs:99` `parse_recipients` / `direct_message.rs:47` |
| Record + encrypt loop (own thread) | `voice_stream.rs:71` `spawn_record_stream_worker` |
| Encrypt a chunk — channel (per recipient) | `voice_stream.rs:101` → `StreamChannelChunk` |
| Encrypt a chunk — DM | `voice_stream.rs:110` → `StreamDirectChunk` |
| Server relay (no decrypt) | `server.rs:367`/`:395`/`:426` (channel), `server.rs:453`/`:467`/`:481` (DM) |
| Receiving: pick the private key **once** for the whole stream | `voice_stream.rs:199` → `rekey.rs:256` `current_private_for` |
| Decrypt loop (one thread per incoming stream) | `voice_stream.rs:144` `spawn_stream_decrypt_worker`, decrypt at `:158` |

Each incoming stream gets its own decrypt thread because RSA private-key
decrypt is much costlier than public-key encrypt — one shared thread would fall
behind real time with two or three simultaneous speakers.

### File transfer

Consent-gated and streamed (Functionality #10, `docs/PROTOCOL.md`'s file
transfer section) - the offer is sent/encrypted like text, then an accepted
transfer's bytes move like voice's chunk stream, except always
point-to-point (never a channel broadcast) since accept/reject/progress is
inherently per-recipient. `file_stream.rs` mirrors `voice_stream.rs`'s
plumbing but moves bytes to/from disk instead of the audio mixer, reusing
its RSA/PQ dispatch types directly rather than duplicating them.

| Stage | Where |
| --- | --- |
| Offer, one per ready recipient — channel | `channel.rs:95` `handle_send_file` |
| Offer — DM | `direct_message.rs:63` `handle_send_file` |
| Server relay (no decrypt, existence check only) | `server.rs` `route_file_offer`/`route_file_accept`/`route_file_reject`/`route_file_chunk`/`route_file_end` |
| Incoming offer: decrypt, trust-gate, queue + bell | `session.rs:1201` `decrypt_file_offer`, `session.rs:1228` `handle_incoming_file_offer` |
| Accept: spawn the receive worker, log the row | `session.rs:609` `accept_file_offer` |
| Sender learns of Accept: spawn the send worker | `session.rs:757` (`ServerMessage::FileAccepted` arm) |
| Send worker — reads/encrypts/sends one chunk at a time | `file_stream.rs:70` `spawn_send_file_worker` |
| Receive worker — decrypts/writes one chunk at a time | `file_stream.rs:124` `spawn_receive_file_worker` |
| Forward an incoming chunk/end to its worker | `file_stream.rs:183`/`:198` `forward_chunk`/`end_incoming_transfer`, called from `session.rs:778`/`:781` |
| Progress/completion/failure → log row | `session.rs:1254` `handle_file_event` → `UiState::set_file_progress`/`set_file_completed`/`set_file_rejected`/`set_file_failed` |

Line numbers are as of the commit that added this section; a drifted number
still resolves via the named function, same convention as the tables above.

### What `rsa_per_msg` adds on top

Everything above still applies unchanged; `rsa_per_msg` only changes *which*
key is current at each moment. Full model in `docs/PROTOCOL.md` §11.

| Piece | Where |
| --- | --- |
| Sign a new key with the key it replaces (PKCS#1 v1.5 + SHA-256) | `rekey.rs:38` `rotation_signing_payload`, `:46` `sign_rotation` → `crypto.rs:229` `sign` |
| Verify a peer's rotation | `rekey.rs:52` `verify_rotation`, `:59` `verify_and_parse_rotation` → `crypto.rs:237` `verify` |
| Keygen, off the event loop | `rekey.rs:134` `generate_and_sign_rotation`, run by `session.rs:142` `spawn_rotation_worker`, queued via `session.rs:755` |
| Own per-peer keys + retained old keys | `rekey.rs:161` `OwnKeys` (retention bound `rekey.rs:31`) |
| Is a peer's key fresh? queue if not | `rekey.rs:287` `RemoteKeys` — `try_use:313`, `enqueue:328`, `on_rotated:338` |
| Apply an incoming rotation, flush the queue | `session.rs:805` `handle_key_rotated` |
| Reconnect continuity (persisted keys) | `own_next_keys.rs` + `session.rs:689` `send_resume_rotation_if_available` (prove), `idstore.rs:158` `get` + `rekey.rs:106` `verify_with_fallback` (verify), both surfaced by `session.rs:805` `handle_key_rotated` — *and*, for a `PerMessage` nickname that already has a continuity key pinned, gated on sight by `check_identity` (`session.rs:613`) itself, before any rotation attempt (`docs/PROTOCOL.md` §12.6.3) |

Voice is exempt from per-chunk rotation (§11.6): one key snapshot covers a whole
stream (`voice_stream.rs:199`), and a recipient without a fresh key is dropped
from that stream (`channel.rs:73`) or the DM recording is refused outright
(`direct_message.rs:44`).

### What `pq_hybrid` adds

Unlike every RSA method, `pq_hybrid` doesn't reuse `rekey.rs`/`own_next_keys.rs`
at all - it's a second *static* identity (like `rsa`), just with different key
material and a different, self-contained primitive set. Full model in
`docs/PROTOCOL.md` §13.

| Piece | Where |
| --- | --- |
| Key bundle types + keygen | `crypto/pq.rs` `PqPublicBundle`, `PqPrivateBundle`, `generate_bundle` |
| Save/load bundle files (private one `0o600` on unix) | `crypto/pq.rs` `save_public_bundle`, `load_public_bundle`, `save_private_bundle`, `load_private_bundle` |
| CLI keygen (no `openssl` equivalent exists) | `main.rs` `run_keygen_pq_hybrid`, `--keygen-pq-hybrid` |
| Sign-then-encrypt-then-wrap (text/file) | `crypto/pq.rs` `encrypt_hybrid_body` (sign + AES-256-GCM, once), `wrap_key_for` (ML-KEM-1024 + RSA-4096, per recipient), `encrypt_hybrid_for_one` (both together) |
| Decrypt + dual-signature verify | `crypto/pq.rs` `decrypt_hybrid`, `unwrap_key`, `verify_body` |
| Voice: per-stream key + per-chunk cipher | `crypto/pq.rs` `fresh_data_key`, `wrap_key_for_stream` (signs `stream_id++k_data` once), `encrypt_hybrid_voice_chunk`/`decrypt_hybrid_chunk` (deterministic nonce from `stream_id`+`seq`), `unwrap_key_for_stream` (verified once, cached) |
| Own key material in the live session | `session.rs` `SessionState::own_pq_private` (mirrors `own_keys`, populated instead of it when `own_key_mode == PqHybrid`) |
| Who can be addressed | `channel.rs:79` `can_address` - a `pq_hybrid` recipient needs a `pq_hybrid` sender (their own ML-DSA-87/RSA-sign identity); everyone else is reachable by any sender, as always |
| `id_store` pinning | `session.rs:707` `uses_byte_comparison_pinning` - `pq_hybrid` joins `rsa`/`password` on the plain-byte-comparison side, unlike `rsa_per_msg`'s signature-based resume |
| Auto-generate keys if missing | `crypto/pq.rs` `ensure_bundle_at`, called from `connect.rs` `resolve_my_keypair`'s `PqHybrid` arm (`docs/PROTOCOL.md` §13.9) |
| Connect-popup cache (`~/.aloo/.cache`) | `connect.rs` `ConnectCache`, `cache_path`, `random_prefix`, `fresh_pq_hybrid_paths_in`, `prefill_connect_defaults` |

### `server_key` — a separate axis

Authenticating *to the server* is unrelated to the message encryption above and
has only three options (`ui_connect_popup.rs:130` `ServerKeySelection`,
`proto.rs:198` `AuthKind`). Client side: `connect.rs:169` `build_auth_response`.
Server side: `server.rs:54` `AuthConfig::verify`.

| Option | Check |
| --- | --- |
| `none` | passes unconditionally |
| `password` | sent as-is and compared byte-for-byte in constant time (`crypto.rs:253` `constant_time_eq`) — it is **not** hashed |
| `rsa` | server sends a random nonce (`crypto.rs:244` `random_bytes`, `server.rs:43` `make_challenge`); client encrypts it with the server's public key; server decrypts and compares |

## Server responsibilities

The server is only a medium of connections: it manages client connections, channel membership/broadcast, and relays encrypted blobs (join notifications, public key exchange, text/voice messages) between clients. It does not decrypt or persist message content — chat/DM history lives only in each client's memory for the session. It does enforce nickname uniqueness, since that's connection bookkeeping rather than message content. It distinguishes a client explicitly leaving one channel from its connection closing entirely (Functionality #8), notifying peers with a different message for each (`docs/PROTOCOL.md` §6.2, §6.4) — but the *decision* of whether to keep an offline user's name around (grayed out) or drop it is made entirely client-side, based on that client's own private-message history, which the server has no visibility into.
