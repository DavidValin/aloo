# Application specification

- language: rust
- ui framework: ratatui
- other packages: crossterm, tokio, serde + bincode (v2 — the crates.io `bincode 3.0.0` is a squatted placeholder, not a real release), rsa, rand_core (RSA key generation needs `rand_core` 0.6's `CryptoRngCore`), sha2 (pinned to 0.10 to match `rsa`'s `digest` version), cpal (raw PCM, no opus), clap (CLI parsing), thiserror (error types), sysinfo (cross-platform CPU usage for the header's `CPU:<pct>%` indicator)

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
aloo.service            <-- systemd **user** unit for background mode, installed to ~/.config/systemd/user/
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
src/client/voice_stream.rs       <-- live voice streaming plumbing shared by channels and DMs
src/client/voice_call.rs          <-- live, continuous, multi-user voice calls: roster convergence, the capture/decrypt workers, Functionality #14
src/client/file_transfer.rs       <-- consent-gated, streamed file transfer: FileOfferPayload shape, chunking/filename constants, download dir, send/receive workers, .txt preview staging dir and capped read, Functionality #9
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
src/client/global_notification.rs <-- desktop notifications for background mode (one API, three OS backends)
src/client/daemon.rs            <-- background mode: config resolution, backgrounding, single instance, the join/focus plan, serving attached terminals
src/client/daemon_ipc.rs         <-- the local socket an attaching terminal speaks over: wire types and framing
src/client/sysstats.rs          <-- CPU usage sampling for the header's CPU:<pct>% indicator
src/client/netstats.rs           <-- connection-speed statistic for the header's Conn:<quality> indicator
src/client/tui/mod.rs            <-- the `tui` module list (no logic of its own)
src/client/tui/terminal.rs        <-- terminal I/O: raw mode + alternate screen setup/restore, blocking input-reader thread
src/client/tui/surface.rs          <-- where a frame is drawn: a real terminal, nothing at all (detached), or an attached terminal over a socket
src/client/tui/ui_connect_popup.rs  <-- the connect popup
src/client/tui/ui.rs           <-- the UI once the user is connected: shared state, key handling, log/input rendering
src/client/tui/channel.rs       <-- channel state, the top row (both selectors) and its rendering (adds `impl UiState` on top of `ui.rs`)
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

The server is started as `aloo --server [--bind <ADDR>] [--port <PORT>]`
(defaults `0.0.0.0`/`7878`). There is no auth flag: every client logs in
with a nickname and password checked against the server's own users
registry (`~/.aloo/users`, docs/PROTOCOL.md §5.1) - accounts created
either directly on the server's machine (`aloo --register-user <nickname>
<password>`, active immediately; `aloo --change-password <nickname>
<password>` to change one) or, if `server_allow_registration=on`, by
anyone from the connect screen's Register button, activated with an
emailed code (§5.2, §5.3). TLS (`server_ssl`, §1.4), registration, and the
SMTP relay activation email goes out through are all settings-only - set
them in `~/.aloo/settings`, not on the command line. The server always
seeds one default public channel, `the-hall`, so a freshly started server
has something for the first-connected client to join.

Every server start persists its resolved `--bind`/`--port` to
`~/.aloo/settings` (`server_bind`, `server_port`). Either flag given on
the command line wins and gets persisted; whichever is *not* given falls
back to what's already in `~/.aloo/settings`. So `aloo --server` alone
reuses this machine's last bind address and port, and a supervisor that
restarts a crashed server with the exact same bare `aloo --server`
command comes back up listening the same way, without needing to
remember or re-pass the original flags. `server_ssl`/
`server_allow_registration`/`server_smtp_*` are written (even to an empty
value) on the very first start and never touched by a flag at all - an
operator edits them in the settings file directly.

Three more settings, all optional and all read only at startup, same as
the ones above (`docs/PROTOCOL.md` §5.5, §6.7, §6.8):

- **`server_allow_create_public_channels`** (default on) - when off, a
  user may still join an existing public channel or create/join a
  private one; only minting a brand-new public channel is refused.
- **`server_channel_deletion_unactivity_period`** (`30days`, `2weeks`,
  `1month`, ...; unset by default) - an empty channel is swept away only
  once nobody has (re)joined it for this whole period. Left unset, an
  empty channel simply persists forever, the same way the default
  channel `the-hall` always has.
- **`server_superadmin`** (one nickname per line, like `muted_voice`) -
  accounts that may run `/activate`, `/deactivate`, `/remove-account` and
  `/remove-channel` (Functionality #26) against anyone on this server,
  over the wire, without shell access to the machine it runs on.

## UI

### Not connected UI

A modal is shown, 64 columns wide - clamped to the terminal's own width if it's narrower than that, so this is a target rather than an absolute floor - centered vertically and horizontally, containing the details to connect. Either way it's noticeably wider than the original 50-column box it replaced. Focus defaults to the **host** field the moment the popup opens, with a blinking text cursor at the end of its (initially empty) value — same as every other text field once it's focused (see below).

- **host / ip**, **port**, **nickname**, **password** — each its own titled, bordered box (not just a plain label/value line).
  - **nickname** — the display name used in channels and DMs; must be unique among currently connected clients (see Functionality below), capped at 11 characters (typing beyond the limit is a no-op), no whitespace allowed.
  - **password** — the nickname's password on this server, checked against the users registry (docs/PROTOCOL.md §5.1). Rendered as asterisks; accepts any character; never remembered between runs, unlike every other field here.
- **email** and the **Register** button — always shown and always focusable, on every server. Whether *this* server actually takes registrations is not something the popup knows in advance — `server_allow_registration` lives in `~/.aloo/settings` on whichever machine runs `--server`, almost never the machine running the popup — so it is never hidden from; pressing **Register** validates the form locally (see below) and then makes the real attempt, which the server answers in its `Hello` (`registration_open`) before `Register` is even sent, refused inline, in red ("this server does not take registrations"), the same as any other failed submission. **email** is its own titled, bordered box, read only by Register - Connect never looks at it. Refuses whitespace while typing; must look like an email address to register with.
- there is no **ssl** field at all: like `server_ssl` on the server side, whether the control connection dials over TLS (docs/PROTOCOL.md §1.4) is settings-only (`connect_using_ssl` in `~/.aloo/settings` — the same one setting a daemon start reads too, with no CLI flag able to override it), captured silently once when the popup opens and carried into the connection, with no key anywhere in the popup able to change it. A connect that fails specifically because this doesn't match the server gets a red reason naming it, rather than a bare connection error.
- **my_key** — this key is used to decrypt messages addressed to the user. There is no type to choose: `pq_hybrid` is the only peer-to-peer scheme this app has (quantum-resistant, hedged with classical RSA-4096). Its two paths, `file_pub` and `file_priv`, are **never editable from this screen** — shown read-only, directly above `ALOO_HOME` in the same gray, centered, information-not-a-field style (below). They never start blank: they're prefilled — from `~/.aloo/.cache`'s most-recently-used entry if one exists (`docs/PROTOCOL.md` §13.9's connect-popup cache), or otherwise a freshly-assigned, not-yet-generated location under `~/.aloo/`, shown as `(not yet generated)` until then — and connecting auto-generates the actual keys there if they don't exist yet, so this never blocks on manual preparation. Pointing at a keybundle `aloo --keygen-pq-hybrid <prefix>` produced externally is done by placing it at that resolved path, not by typing or browsing here. See Functionality #10 and `docs/PROTOCOL.md` §13, §13.9.
- **ALOO_HOME** — a read-only line reading `ALOO_HOME=<path>`, drawn in gray and centered horizontally, directly below `file_pub`/`file_priv` - together one info block, set apart from the rest of the form by a blank line directly above `file_pub` and directly below `ALOO_HOME`, with no blank lines separating the three lines themselves - so the whole block reads as one note rather than three. It names the directory this client actually resolved (`platform::aloo_dir`), which every piece of local state lives under, including the identity-pinning store (`idstore::default_path()`, always `$ALOO_HOME/id_store` - there is no popup field for it; it is never user-editable), the connect cache, `settings`, and the OTP layer's `otp_store`/`otp/.keychain/`. It is spelled as the environment variable that sets it, so the line doubles as the answer to "how do I run a second client on this machine": `ALOO_HOME=/tmp/aloo-bob aloo`. Captured once when the popup opens, so rendering stays a pure function of the popup's own state.
- **Connect** and **Register** buttons, always both shown side by side — bordered, either one highlighted when focused. The highlight (solid background) fills only the button's interior; its border keeps its own plain/focus style rather than being swallowed into the highlighted fill, consistent with every other bordered/focusable element in this app. Tab cycles through every field in order (host, port, nickname, password, email, Connect, Register) and wraps around to the first. Enter on **Connect** validates host/port/nickname/password/my_key and, if valid, connects; on an incomplete form it shows a validation error below instead (e.g. "host is required", "password is required"). Enter on **Register** validates the same fields plus a plausible email and a registrable nickname (above), then makes the real attempt against the server, and on success opens the activation popup directly (below) instead of connecting - registering is never also a login. While either attempt's network round trip is in progress, the popup and the version title above it are hidden, the background animation keeps running, and a single centered yellow line takes their place - "connecting..." for Connect, "one moment..." for Register - surrounded by a real 3-row/3-column blank clearing where nothing else is drawn. The popup (with the error shown, if any) comes back the moment the attempt resolves, success or failure alike.
- **Background animation** — a dense "digital rain" fills the screen behind the popup (and, while "connecting..."/"one moment..." is showing, the whole screen): every column carries its own falling trail of `0`/`1` glyphs (white/bold at the head, green fading to dim further behind it), each drifting to a different pace and trail length every so often; the cells between trails are their own sparse field of independently flickering `0`/`1`s in the same dim green - texture, not just empty space between streaks.

The activation popup (docs/PROTOCOL.md §5.2) opens two ways: automatically
right after a successful Register ("Enter the activation code you
received by email"), or when a later login's credentials are right but
the account is still waiting on its emailed code ("`<nickname>` is
registered but not activated yet..."). Either way it is the same small
popup: a 12-digit numeric field, Enter to submit (a short code shows a
validation error instead), Esc to give up. Submitting retries the connect
with that code attached, as many times as it takes.

Every focused text field (host/port/nickname/password/email) shows a
blinking cursor at the end of its current value, not just a
reversed-color highlight. The keyboard-shortcut hint at the very bottom of
the popup - the last element in its layout - is centered horizontally too,
the same as the ALOO_HOME line above it.

`my_key` is the user's own key material, loaded from the keybundle pair the two fields name. It uses the hybrid scheme in Functionality #10, including its own ongoing key-rotation behavior for the rest of the session.

**File browser**: a custom in-TUI widget (not an OS dialog) that supports back/forward navigation through directories and file selection - not used on this screen any more (`my_key` is read-only here), but reused as-is wherever else the app needs to pick a file: the `/file` send flow (Functionality below) and `/contacts`' PQH "Create key" (Functionality #8). The visible list scrolls to keep the selected entry on screen, so a directory with more entries than fit in the popup's height can still be navigated all the way to its last entry with Up/Down, not just the ones that happen to fit on first open.

**The last connection is proposed again.** Every time this form is submitted, the host, port and nickname it was submitted with are recorded in `~/.aloo/settings` (`connect_host`, `connect_port`, `connect_nickname`) and prefill it next time — whether or not that connection then succeeded, since a wrong password or an unreachable host does not mean the nickname typed was wrong. The nickname lives only here: `~/.aloo/.cache` is keyed by `(host, port)` and holds keybundle paths, so it has no slot for the one field that is about the person rather than the server — without these keys the form would propose `$USER` every time however often someone connected as somebody else. Where both stores have an opinion about the host and port, settings win — a hand-edited `connect_host` is a deliberate answer to the same question — while the keybundle paths still come from the cache, which is the only store that has them per server. A `--no-server` start has no host to record and leaves the recorded one alone. The same three keys are what a bare `aloo --daemon` falls back to (see "Running in background mode").

**Nickname rejection**: if the server rejects the nickname as already taken, the client returns to this popup with an error message shown and focus already on the nickname field — every other field (host, port, keys) is preserved, so the user only needs to change the nickname and press Connect again.

### Connected UI

The UI is composed of:

- **Top area** (full width, three rows tall) — one blank line, then the row itself, then another blank line, with its content inset one column from each side, so it reads as sitting in the middle of its own band rather than pinned to the screen's edges. Borderless, and drawn identically over an open DM room, which is reached through it. That row opens with the **server state** indicator; then, starting at the column the message list below starts at (the sidebar's width — so the two line up), two selectors laid out as tabs, one focused at a time: the **channel selector** on the left and the **DM selector** on the right; followed right-aligned by, in order: the **⏺ Call Ctrl+R** indicator (only while on a call — Functionality #14), two spaces, a **`<active>/<total> direct punches, next try in <time> (Control+s)`** indicator (only when direct punching is actually configured — Functionality #23), two spaces, a **Conn:`<-|BAD|NORMAL|GOOD>`** indicator, two spaces, a **CPU:`<pct>`%** indicator, two spaces, the **Ctrl+H: Help** hint (Functionality #6).
  - **Server state** — the first thing on the row, and the only thing left of the selectors. Every state renders the same plain record-circle glyph (⏺, `ServerLinkState::ICON`) - never a multicolour emoji - so the colour shown is always exactly the one the header applies, never one baked into the character itself. One of, with a server (`docs/PROTOCOL.md` §4.2): **⏺ Connected to server!** in green; **⏺ Reconnecting...** in red while an attempt is actually in flight; **⏺ Reconnecting in `<n>`s...** in red while waiting for the next one, the number counting down live; and, once three attempts have failed, **⏺ Server down (reconnecting in `<n>` sec...)** in red, which keeps counting down and keeps retrying for as long as the session lasts. With `--no-server` (Functionality #18) it instead reads **⏺ No server mode** in white, or **⏺ No server mode (punching)** while a direct UDP punch is in flight — there is nothing to reconnect to, and punching is the only thing this client does to reach anybody. A label too long for the sidebar's width pushes the selectors right rather than being cut off: a countdown missing its number says nothing.
  - **Channel selector** — names the one joined channel currently on screen as `#<name>`, private ones prefixed `🔒 ` and public ones carrying no icon at all - a bare `#name` is itself the "this one is public" signal. That `#` is decoration — it is never stored and never sent on the wire — and typing it back in is fine (see "Channels" below). Then `+<n> more...` in grey for however many other channels the user is joined to. Only the named channel itself carries the focus highlight — the count, like the envelope below, is always drawn grey with nothing behind it. `[` opens its dropdown — hanging off the bottom of that three-row band, lined up under the selector it belongs to: every joined channel *except* the one named, public and private alike, each written the same way. Nothing to switch to means no dropdown opens. Either dropdown hangs directly beneath the selector it belongs to — lined up with that selector's own first column, not with the screen's left edge, which the server-state element occupies. A dropdown with more entries than the screen has rows below the header stops at the bottom edge and scrolls inside it rather than drawing rows nobody can see: the entries around the current selection are kept in view as Up/Down walk the list, and a one-column scrollbar is drawn down its right edge while — and only while — there is more list than viewport, exactly as the message log's own is.
  - **DM selector** — the same, for the private rooms the user has open: the nickname of the one it names (prefixed 💬), then the `🔑 OTP` tag if a one-time-pad session is open with that person (see the tag convention below), then `+<n> more...` in grey. Its dropdown rows carry that same tag, each on the row of the person it is about. Not rendered at all until a room has been opened; every open room counts, including one opened and never written in. `]` opens its dropdown: every open room except the one named. Focusing this selector opens the room it names in place of the channel view.
  - **Unread envelope** — ✉ (U+2709, the plain text-style glyph — never an emoji-presentation variant, so it draws as one flat character with no colour block behind it), blinking, on either selector while any channel or room behind it holds messages that have not been looked at yet. The focus highlight covers the selector's own name and stops before the envelope, so nothing paints a background around it; it keeps blinking until that channel or room is opened. While a selector's own dropdown is open the envelope moves onto the individual rows it belongs to, so it names *which* one is unread. Presence notices never raise one. On the DM selector — and on a DM row of an open dropdown — the envelope carries the same colour as the nickname beside it (the direct-link/presence colour the sidebar uses), not a colour of its own: it blinks directly against that name, and two colours on one name read as two separate facts rather than as one person with unread messages. The channel selector's is plain white: a channel is a room rather than a person, so its envelope has no reachability to report and says nothing about one.
  - **CPU:`<pct>`%** — this client's own system-wide CPU usage, resampled roughly every 300ms. Rendered green below 25%, red at 25% and above.
  - **Conn:`<-|BAD|NORMAL|GOOD>`** — a rough read on how lively the connection feels, resampled once a second from the average gap between the last 1-3 protocol messages actually seen moving over the socket in either direction (there is no ping/pong in the wire protocol, so this is message cadence, not a true round-trip time). `-` (white) before any message has been exchanged yet this session; otherwise `BAD` (red), `NORMAL` (yellow) or `GOOD` (green) by how short that average gap is.
- **Left area / sidebar** (20% wide) — list of users in the selected channel. Each row keeps the person on the **left** and their encryption tag flush against the sidebar's **right** edge, so the tags read as a column of their own rather than starting wherever each nickname happens to end. A sidebar too narrow to hold both keeps one space between them and clips at its right edge, like any other overlong sidebar entry. Each connected user is coloured by whether messages can actually reach them — that is, by the state of the direct peer-to-peer link to them (`docs/PROTOCOL.md` §7.1.4), not merely by their being connected to the server. It is a two-state answer, because that is the whole of what someone about to type needs: **green** once that link is up and what is typed reaches them, **gray** until it does. A punch still in flight, a link that has been lost and is being retried, and a connection that has closed entirely (Functionality #7) are all the same answer — no — and giving each its own colour only invites reading transport detail into a name. Being present in the channel is not the same as being reachable, and this is where the difference shows. One state overrides the colour: a user whose identity hasn't been verified yet, or was explicitly rejected (Functionality #8), is rendered in **red** regardless of anything else. That is not a reachability state at all but the one thing here with something to *do* about it (Enter opens the review). **Your own row is always last**, named plainly in green (you are always reachable to yourself) and suffixed ` (me)` in gray — that suffix's colour never follows whatever colour the name itself takes. Enter on it does nothing: there is no DM to open with yourself.
- **User-info popup** — `i` on a sidebar member (or `/info` inside an open DM room, for that room's peer) opens a small, read-only popup: the nickname, the device this connection actually announced (`(unbound)` if none is known), when they were last seen, and one row per key that genuinely exists for that `(nickname, device_id)` — PQH/OTP/OTP MAIL, each with the same ✅ icon and colour `/contacts`' own badges use (Functionality #8), followed by that key's id (PQH's fingerprint, OTP/OTP MAIL's contact name). A key that doesn't exist gets no row at all — unlike `/contacts`' own list, which always shows all three. If an `/otp` session is currently active with them, a final line says so. Never edits anything; `/contacts` is where keys are managed. Works for a trust-gated peer too, and never requires them to be online — it's a local lookup. `i` or `Esc` closes it, absorbing every other key while open, same as the message-details popup (Functionality #20).
- **Identity review popup** — a centered, bordered popup that opens automatically (announced with the same bell chime an incoming file offer plays — every popup that lands asking for a decision chimes: identity review, OTP session invites and generate-confirms, file offers, incoming OTP mail), on top of whatever else is on screen (even the help overlay). Messaging with the mismatched peer is blocked the instant their identity fails to check out (Functionality #8), but the popup itself is briefly withheld — until this specific connection's own address/device id are known, usually a second or two later — so it can show both sides of the comparison instead of just two fingerprints. Names the peer, explains the specific mismatch plus the last-known and new address/device id, and offers two buttons, **Accept** and **Reject** (`Reject` focused by default); `Left`/`Right`/`Tab` move focus between them, `Enter` confirms - no other key does anything while it's open, and there's no Esc-to-dismiss, since the whole point is an explicit decision rather than a wait-and-see banner. If more than one peer's identity is unresolved at once, only the oldest unshown one is displayed; resolving it (either button) reveals the next.
- **Call invite popup** — same shape as the file-offer popup below (centered, chimed, **Accept** focused by default), titled `Voice call incoming from <nickname>` — see Functionality #14.
- **Permanent call indicator** — while on a call, a red bordered box in the top-right corner (just above where the status notice would show) reads `⏺ On a call [in #<channel>] (<n> connected)`, with ` 🔇 muted` appended while muted. Unlike the status notice, it never times out on its own — it's cleared only by leaving the call (Functionality #14). The top row's own `⏺ Call Ctrl+R` marker is the separate, one-line reminder of the key that brings the call modal back once Escape has folded it away.
- **Main area** (80% wide) — messages in the selected channel.
- **Bottom bar** (full width) — text input where the user composes and sends a message; the cursor blinks at the end of the typed text whenever this bar is focused (the default focus on connecting). While viewing a private room whose peer is offline, this bar instead shows `(user offline)` in red and refuses all typing (Functionality #7).

The private-message room (Functionality #3) titles itself the same way: `Private: ` followed by the same tagged-name form.

**OTP session header.** While a mutual-consent OTP session (`docs/PROTOCOL.md` §16) is active with a private room's peer, a 1-line header renders above that room's message log: `OTP SESSION with <nickname> - Receive Key (dec): <Seq> <Offset> <remaining>MB - Send Key (enc): <Seq> <Offset> <remaining>MB`. `OTP SESSION` is highlighted, `<nickname>` is yellow, each direction's `Seq`/`Offset` are grey, and `remaining` is green at or above 0.5MB, red below it. The figures come from the real `otp` command (`otp --show-contact`) and stay live: fetched once immediately when the session starts, again the instant this contact's pad is actually spent by a genuine send or receive in either direction, and roughly once a second besides as a safety net for as long as that room stays open (`docs/PROTOCOL.md` §16.5).

**Encryption tag convention** (`aloo::proto::KeyMode::label`/`format_with_name`) — one of two, since `pq_hybrid` is the only `my_key` this app has (see Functionality #10 for its wire implications):

| `my_key` type | Tag | Position |
| --- | --- | --- |
| `pq_hybrid` | `🛡️ PQH` | after the name: `name 🛡️ PQH` |
| *(while a one-time-pad session is open with that person)* | `🔑 OTP` | after the name: `name 🔑 OTP` |

**`🔑 OTP` replaces, rather than joins, the tag above it.** While a pad session is open with someone (`/otp`, Functionality #15), the pad is what actually protects everything said to them — there is no way to send them a plain, non-pad-wrapped message in the meantime (`docs/PROTOCOL.md` §16.2) — so their row says so instead of naming the layer underneath. Whichever layer that is — a `pq_hybrid` envelope for the usual pairing, or nothing at all for a pad-only pair (`docs/PROTOCOL.md` §16.2) — the tag it displaces is `🛡️ PQH` either way, since that is the only `my_key` tag there is. It is drawn in the same cyan the room's own OTP session header uses.

🔑 is the **one** glyph a pad session is ever marked with, and deliberately **not** the 🛡️ shield `pq_hybrid` already carries: the pad runs *over* pq_hybrid, so sharing a glyph would make the marker for the extra layer and the marker for the layer under it the same character, in the very places whose job is telling them apart. It appears:

- as the full `🔑 OTP` tag, in place of that person's `my_key` tag, in the **channel user list**, on the **DM selector**, on their **DM dropdown row**, and in their **room's own title**;
- as the glyph alone, prefixing **every message in that room the pad protects**, and at the **start of the compose bar** those messages are typed into — the bar says what will happen to the next message, not only what happened to the last. The bar's own glyph is live state and disappears the moment the session ends (`/endotp`, Functionality #15); a message's glyph is a permanent fact about that one message and stays exactly as it was — ending the session changes nothing about how an already-logged message was actually protected.

The app's own narration lines and presence notices never carry it: it marks content, not the app talking about the session.

Both tags are unbracketed and trail the name, reading as an annotation on it. 🛡️ is `pq_hybrid`'s own icon — a file-backed, durable *identity*: quantum-resistant signing hedged with RSA-4096, and quantum-resistant key exchange hedged with X25519 whose keys rotate per peer as messages are exchanged, so a stolen keybundle does not open past traffic (`docs/PROTOCOL.md` §13, §13.10).

**Delivery acknowledgments** (Functionality #20, `docs/PROTOCOL.md` §7.2.1). A message the user sent — text, voice or a file transfer alike — reads `<nickname> -> <body>` rather than the `<nickname>: <body>` everything else uses, and that arrow is the indicator: it is drawn bold, in gray while no recipient has confirmed decrypting the message, orange while some of a channel's recipients have, and green once all of them have. A private room has one recipient, so its arrow is only ever gray or green. A message that was addressed to nobody at all keeps its gray arrow and is additionally **struck through**, drawn by following every character of the row with U+0336 COMBINING LONG STROKE OVERLAY (a terminal has no styling for this that can be relied on). Nothing incoming carries an arrow, nor do the app's own system/presence lines — those keep the plain `:` separator, since an incoming message needed no acknowledging. Where the OTP 🔑 prefix also applies (`docs/PROTOCOL.md` §16) it stays where it always was, at the very start of the row and never struck through.

Green is a statement about the recipient's own client, not about the network: it means that client decrypted the message and said so. For a file that is the *offer* opening — they know what is being sent — and for a voice message the stream ending with audio their end could decode. Either is a different statement from the sending row's own `📎 <filename>` completion, which is only about this side finishing sending.

Under an OTP session the arrow means something stronger. An ordinary acknowledgement is the recipient's unproven word — a small message naming which of yours it is about, which anyone on the link could send. A pad-protected one has to prove it: it carries a value that can only be derived by actually decrypting the message it names (see "Proving an acknowledgement" below). So on those rows the arrow ignores the ordinary acknowledgement entirely and stays gray until the proof arrives — green there means *this pad's holder* read it, not merely that someone said so.

**Message details popup.** `i`, with the message log focused, opens a centered, bordered popup on the selected message titled `Message details (i / Esc to close)`: `sent_at: <YYYY-MM-DD HH:MM:SS>` in bold, a blank line, the encryption block below, a blank line, then one line per user the message was sent to — the nickname on the left, and right-aligned against the popup's edge that user's own status, the same arrow in the same colours as the row it was opened from. Names are as they were at send time, so a recipient who has since left is still listed. On a row that tracks no delivery it reads `received_at:` instead, and says `no delivery information for this message` in place of the list. It absorbs every key while open; `i` or Escape closes it.

The popup, and only the popup, shows what a recipient did with the message beyond being able to read it (`docs/PROTOCOL.md` §7.2.1's receipt stages):

| Status | Colour | Means |
| --- | --- | --- |
| `-> UNDELIVERED` | gray | they have not decrypted it |
| `-> DELIVERED` | green | they decrypted it — for a file, the offer; for a voice message, the audio |
| `-> DELIVERED+LISTENED` | green | *(voice only)* they actually heard it — on arrival, or later if it was muted at the time and they replayed it |
| `-> DELIVERED+VIEWED` | green | *(`.txt` files only)* they opened it in the preview popup without saving it |
| `-> DELIVERED+SAVED` | green | *(files only)* they have the whole file on disk |

A text message never reaches a `+` state, having nothing further to do with it, and the log's own arrow is unmoved by any of this: it stays a three-state summary of who has the message, not of what they did with it. `DELIVERED+SAVED` always outranks `DELIVERED+VIEWED` once true, even if a `Viewed` receipt for the same file arrives afterward — a genuine save is never reported as merely previewed.

**How that message was encrypted.** Above the recipient list, the popup names what actually protected *this* row's content, as `label  value` lines in one column, in cyan:

| Line | Value |
| --- | --- |
| `encryption` | the scheme by its mechanism — `ML-KEM-1024 + RSA-4096 -> AES-256-GCM, ML-DSA-87 signed` for an ordinary send; under an OTP session, `one-time pad (XOR) inside the pq_hybrid envelope` when there is an envelope sealed around the pad, or `one-time pad (XOR), carrying the message directly` when there is not (§16.2's two framings — the popup names the one *this* message used, never assuming) (`docs/PROTOCOL.md` §13, §16) |
| `key` | *(not under OTP)* a short fingerprint of the public key it was sealed to — the first 16 hex characters of its SHA-256, the same short form an identity-mismatch warning uses. A channel send is sealed once per member with that member's own key, so it reads `one per recipient` instead |
| `key_seq` | *(OTP only)* which sequence of the pad this message is |
| `key_offset` | *(OTP only)* the pad offset its key bytes start at |
| `key_file` | *(OTP only)* the key file they came out of — `<contact>_enc.key` for a message sent, `<contact>_dec.key` for one received |

The scheme is named by its cipher rather than by the `my_key` tag the sidebar shows, which is about identity rather than about how a message was encrypted. The OTP figures are the pad's position *before* this message spent its own key, recorded on the row when it is logged: the pad walks forward with every message, so the live figures in the session header describe some later message by the time anyone presses `i`. A line this client wrote itself — a presence notice, the app's own narration of an OTP handshake — never travelled, and reads `encryption  not an encrypted message`.

**A popup replaces what is behind it.** Every popup in the connected UI — the identity review, a file offer, a call invite, the OTP prompts, the join/password/`/channels` modals, the file browser, the message details, the help overlay — owns the cells inside its own border: the view underneath is cleared there rather than composited through, so a busy message log never shows between a popup's words. Only the two non-modal banners are exempt, being banners rather than popups: the permanent call indicator and the status notice.

**Resizing the terminal repaints the whole screen.** A size change is answered by throwing away the frame laid out for the old size and drawing every cell again at the new one, rather than diffing the next frame against a window that no longer exists — a diff would leave whatever the old layout drew outside the new one on screen un-erased, showing as a torn header and half-drawn selectors. This is the same for the terminal this process owns and for one an attached viewer owns (see "Running in background mode").

A border wraps the sidebar, the main area, and the bottom bar. Whichever of the three currently holds keyboard focus is highlighted with a yellow border so it's clear where input goes; the bottom bar overrides this with a red border while actively recording a voice message.

**The message log (both the channel view and the private-message room) is scrollable.** While it has focus: `Up`/`Down` move the selection one message at a time, `PageUp`/`PageDown` jump by 10, and `Home`/`End` jump straight to the oldest/newest message — all clamped at the ends of the history rather than wrapping around. The four scroll keys also work straight from the compose bar, where focus starts and stays while typing: they scroll the log without moving focus and without typing into the message being composed (`Home`/`End` stay log-focus-only). Whenever the log is longer than its pane, a one-column scrollbar is drawn down the right edge of that pane, its thumb tracking the rendered viewport — top of the track on the oldest message, bottom on the newest; a log that fits shows no scrollbar and keeps the full width for text. Opening a channel or a private room starts scrolled to its newest message; a new incoming or outgoing message pulls the view along with it only if it was already showing the newest message, so scrolling back through history to read isn't interrupted by new traffic arriving.

## Channels

Channels are dynamic:

- **Public channels** are broadcast by the server to every connected client — both the initial snapshot at connect time and, live, the moment anyone creates a new one afterward (no reconnect needed). They appear in the `/channels` directory, not on the channel selector: that selector holds exactly the channels the user is actually a member of.
- **Private channels** are joined by pressing **Ctrl+J**, which opens a popup to type the channel name, choose Public or Private, and — while Private is selected — optionally set a password.

A channel is *shown* as `#<name>` — on the channel selector, in its dropdown, and in a call's title. The `#` is decoration only: it is never part of the name, never stored, and never sent on the wire. Because a channel is read that way, it may be typed that way too — a leading `#` in the Ctrl+J form's name field, in a `--channels` flag, or in a `daemon_channel` settings line is accepted and then ignored. Only a leading one: `#` is not in a channel name's charset, so anywhere else it is a genuine mistake and is refused as the keystroke is typed.

A channel name is limited to letters, digits, `-` and `_`, up to 30 characters (`CHANNEL_NAME_MAX_LEN`) — enforced both as the user types and, independently, by the server. A private channel's optional password is limited to letters, digits, and a documented set of basic symbols, up to 50 characters (`CHANNEL_PASSWORD_MAX_LEN`), likewise enforced on both sides (`docs/PROTOCOL.md` §6.1/§6.5).

When connected, the server sends the list of available (public) channels. Exactly one of them is joined automatically — the default channel `the-hall` — however many others are on offer; the rest are joined deliberately, from `/channels` or Ctrl+J. The top row (no border) names one joined channel at a time on its channel selector, and lists the rest in that selector's dropdown.

When a channel is joined, the join is broadcast to all users already in the channel, and each of those users sends their public key to the newly joined user, who stores it in memory (used to encrypt messages sent to them). In practice this key exchange is relayed through the server as part of channel membership events (the server already knows every connected client's public key from `Identify`), not a direct peer-to-peer transfer — the server still never decrypts or reads message content, only relays already-public identity metadata.

**Password-protected private channels.** Joining an existing private channel that was created with a password, without supplying one or with the wrong one, opens a dedicated password-entry popup naming the channel — blank for "you need a password", or showing "wrong password" for a retry — letting the user type one and resubmit. More than 7 wrong attempts against one channel from one address bans further attempts against that channel for 2 hours, reported distinctly ("too many attempts") rather than as another wrong-password message (`docs/PROTOCOL.md` §6.5/§6.6).

**The channel directory (`/channels`).** Typing `/channels` and pressing Enter opens a modal listing every public channel the server has announced, the ones the user is already in shown in yellow. Up/Down move the selection (wrapping at both ends), Enter joins the selected channel and closes the modal (on one already joined it just brings that channel to the front of the channel selector), Escape closes it without joining anything.

**Leaving a channel.** Typing `/leave` and pressing Enter leaves whichever channel the channel selector currently names (no argument — it's never a different one) and drops it from that selector, public or private alike: the selector holds exactly the channels the user is in. A public channel stays in the `/channels` directory, to rejoin from whenever. Emptying a channel no longer deletes it outright: it persists, with its admin, bans and join-lock all intact, until `server_channel_deletion_unactivity_period` elapses with nobody having (re)joined it in that time — or forever, if that setting is left unconfigured, the same way `the-hall` has always persisted while empty (`docs/PROTOCOL.md` §6.8). A channel does still disappear sooner if its admin runs `/delete-channel`, or a superadmin removes it - see "Channel ownership and moderation" below. Either way, a later `JoinChannel` for a since-removed channel simply recreates it fresh, with whoever joins first as its new admin.

**Channel ownership and moderation.** Whoever's join actually creates a channel - public or private - becomes its admin, shown in the message pane's title as `#name (admin: nickname)`, and marked with a leading ☀️ in that channel's own sidebar. `the-hall` is the one permanent exception: it has no admin, ever. The admin can:

- **`/delete-channel`** (no argument, targets the channel currently selected) - public channels only; a confirmation popup asks first. Every member is told it's gone and its tab disappears; the name is free to recreate immediately.
- **`/ban <nickname>`** / **`/unban <nickname>`** - force-removes a member and refuses their future joins until unbanned; both the banned person and everyone else in the channel are told.
- **`/lock-joins`** - opens a popup prefilled with the current members, editable as a specific allowlist or switched to "All users" to clear it. Applying takes effect immediately for *future* joins only: a current member is never evicted just because a narrower list no longer names them, and the admin can always rejoin their own channel regardless of the list.
- **`/assign-admin <nickname>`** - hands off admin to a fellow current member (who must already be a member) and releases the caller's own admin rights over it, behind a confirmation popup.

Pressing `i` on a channel's admin reports `☀️ admin of #<name>`, in addition to whatever the user-info popup already shows. Full model in `docs/PROTOCOL.md` §6.7.

**Server superadmins.** A short list of trusted accounts (`server_superadmin`) can act on any account or public channel, over the wire, without shell access to the server. Pressing `i` on a superadmin reports `<nickname> is a ⚡ superadmin`, and their name is marked with a leading ⚡ in every channel they're in - not just one they administer. Full model in `docs/PROTOCOL.md` §5.5, and Functionality #26.

## Functionality

1. **Send a text message to the channel.** The message is encrypted separately for each recipient, using that recipient's RSA public key — no AES/hybrid encryption is used. Note: since raw RSA only encrypts small fixed-size blocks (190 bytes of plaintext per block with a 2048-bit key under OAEP/SHA-256 — `256 - 2*32 - 2`, see `crypto::max_chunk_len` and `docs/PROTOCOL.md` §8.1), longer payloads are split into multiple blocks, each encrypted per recipient.
   - **Typed text is capped at 10,000 characters** (`proto::TEXT_MESSAGE_MAX_LEN`) — the compose bar simply stops accepting further keystrokes once reached, client-enforced only since the server never sees plaintext.
   - **Pasting into the compose bar sends it as one message immediately**, embedded newlines included, rather than fragmenting into a separate send per line or waiting in the bar for a manual Enter. A paste longer than 5,000 characters (`client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD`) is converted to a `.txt` file instead and sent through the same consent-gated file transfer Functionality #9 describes, rather than as a message. A pasted line break is normalized to `\n` regardless of whether the terminal delivered it as CRLF or a lone CR (`UiState::handle_paste`) - many terminals, including tmux's own paste, send `\r` for an embedded line break rather than `\n`.
   - **Pasting works everywhere else too, not only here.** Any text field in any popup (Direct Punches, `/mail`'s compose fields, the pre-session connect/register form, the activation-code popup, ...) accepts a paste as if it had been typed character by character into whichever field currently has focus - a field's own rules (a digits-only port, an activation code's digit-and-length cap) apply exactly as they would to real keystrokes. Only this compose bar has the file-conversion/send-immediately behavior above; everywhere else a paste is simply inserted.
   - **The message log renders a multi-line message across one row per line**, not squished onto a single row, while it stays exactly one selectable log entry: Up/Down moves by entry regardless of how many rows it takes on screen, and `i` opens the details of that one entry no matter which of its rows the cursor is drawn on.

2. **Move between channels and rooms, and join new channels.** `[` and `]` move between the top row's two selectors — `]` from the channel selector focuses the DM one, `[` from the DM selector focuses the channel one — without ever wrapping around from one end of the row to the other. At the outer end there is nothing further to step onto, so the key opens that selector's own dropdown instead: `[` on the channel selector, `]` on the DM selector. With a dropdown open, Up/Down pick another entry — switching the view behind it straight away, wrapping within that selector's own list — and Enter, Escape, Tab or the opposite key close it, keeping whatever was picked. Tab closes it rather than cycling focus underneath: its usual job (sidebar → messages → compose bar) is about the view behind the overlay, so reaching for it means being done with the dropdown. **An open dropdown also folds itself away after 30 seconds with nothing driving it** (`SELECTOR_DROPDOWN_IDLE_TIMEOUT`, the same span a status notice lasts) — it is an overlay over the conversation, not a modal, and one left open and forgotten would sit on top of the messages arriving underneath. Each Up/Down restarts that clock. Every entry is a channel already joined or a room already open, so switching never joins anything. **Joining lands you in the channel joined**: the moment the server confirms it, that channel is the one the selector names and the view below it, so the compose bar is already addressed to it (an open DM room closes with that, and stays on the DM selector). To join one: `/channels` lists the server's public channels (Enter joins the selected one), and Ctrl+J opens a popup to join or create a channel by name — Tab cycles between the name field, a Public/Private selector, and, while Private is selected, an optional password field; Left/Right toggles the selector.

3. **Send a private message to a user.** Move through the list of users in a channel and press Enter to open a full-screen private room with that user. Press Escape to return to the channel view. Messages exchanged remain in memory for the session. The private room can be reopened by selecting the same user again and pressing Enter.
   - The room also joins the top row's DM selector, which names one open room at a time and blinks an envelope while any other one has unread messages (see "Connected UI") — `]` from the channel selector goes to it, `[` comes back.
   - In the channel view, a user is preceded by an envelope emoji once there's at least one message (sent or received) in their private room — not merely because that room was opened; opening an empty DM and leaving it again shows no envelope until an actual message exists. The envelope stays visible (solid) for the rest of the session once earned, whether the messages in it have been read or not, including after the room is reopened and marked read.
   - If there are unread messages from that user, the envelope blinks instead of staying solid; reopening their room (marking it read) stops the blinking but does not remove the envelope, since there's still history.
   - Outgoing DM messages are encrypted with the receiver's public key; incoming DM messages are decrypted with the user's own private key.

4. **Send a voice message** by holding Space (while focus is not on the compose bar - Space there just types a literal space) and releasing it to stop, up to `voice::MAX_RECORDING_SECS` (4 minutes) long. Voice is streamed live, not recorded-then-sent: while Space is held, captured audio is chunked (`voice::CHUNK_INTERVAL`, 15ms) and sent to the network as it's captured, and the receiving side plays each chunk as it arrives, rather than waiting for the whole message. While recording, a blinking red ⏺ "recording..." indicator appears inline at the end of the input bar and the bar's border turns red.
   - **Live appearance and finalization.** Both directions show the in-progress message immediately (a blinking red ⏺ "voice (streaming...)" block in the log) and it turns into a normal, replayable voice block only once the stream ends. The user can replay a finished voice message later by scrolling through the channel/DM history and pressing Enter on it, which renders in bold red, marked with a 🔴 and labeled with its actual recorded duration, e.g. `🔴 voice (12sec)` — the duration shown always reflects the real length of that specific message, not a fixed value. Any partial second rounds up (1ms shows as `1sec`, 1001ms as `2sec`), except a genuinely instantaneous 0ms recording, which shows `0sec` rather than rounding up to `1sec`. **While a replay is playing, pressing Escape stops it** immediately, instead of Escape's usual meaning of closing the current private room — Escape reverts to that usual meaning again the moment nothing is being replayed.
   - **Release detection** works on any terminal. At startup the client queries whether the terminal actually supports the Kitty keyboard protocol's release reporting (`crossterm::terminal::supports_keyboard_enhancement`, not just whether enabling it succeeded — a terminal can accept the escape sequence without honoring it). If it does, stopping relies solely on that genuine `Release` event: recording continues through any pause or silence for as long as Space is physically held, and only stops when it's actually released. If it doesn't, there is no way to observe a release directly, so the app falls back to watching for the OS's keyboard auto-repeat (a steady stream of `Press` events roughly every 30-50ms once repeating, after an initial OS repeat-delay commonly in the 500-650ms range) and treats ~900ms of silence since the last one as "released" — an approximation, used only when nothing better is available. Both stopping mechanisms are no-ops when nothing is actually being recorded: a `Release` event with no matching prior `Press` (e.g. one delivered right as a channel switch or DM close ends a recording some other way) does nothing, and so does the idle-timeout check firing with no recording in progress.
   - **Length cap.** A recording that reaches `voice::MAX_RECORDING_SECS` (4 minutes) stops itself automatically — the indicator clears and the end-of-message chime plays, exactly as if Space had just been released, whether or not it's still actually held. This is a client-side courtesy limit on the *sending* side; the receiving side independently enforces the identical cap regardless of what the sender did (`docs/PROTOCOL.md` §7.3) — an incoming stream is force-finalized with whatever arrived once it reaches 4 minutes of audio, so a modified or misbehaving peer can never make a receiver accept, or keep decrypting, a longer one.
   - **Failure handling.** If starting the recorder fails (e.g. no microphone), or if Space is pressed with nowhere to address the stream to (not joined to any channel, no active DM), the indicator clears immediately (or never starts) rather than continuing to claim a recording is happening. The failure reason is tracked internally but deliberately not rendered on screen - this kind of environment tends to surface plenty of transient, self-recovering audio errors (buffer under/overruns, PulseAudio status-query hiccups) that aren't worth interrupting the display for.
   - **Encryption and cost.** Each chunk is sealed under the stream's already-established key (AES-256-GCM, no asymmetric crypto per chunk) - live streaming multiplies the message rate, not the per-second crypto cost, which is purely a function of bytes-of-audio regardless of chunking.
   - **Jitter and mixing.** On the receiving end, a jitter buffer (a small per-source prebuffer before playback starts) absorbs ordinary arrival jitter between chunks so normal network/CPU timing variance doesn't produce audible gaps; multiple simultaneous incoming streams (two people talking near-simultaneously) are mixed together rather than queued one behind another.
     - **The prebuffer adapts rather than being a fixed worst case.** It starts small (`voice.rs` `JITTER_PREBUFFER_MIN_MS`), grows a step on every underrun up to `JITTER_PREBUFFER_MAX_MS`, and gives a step back after each `JITTER_DECAY_INTERVAL` of clean playback. A clean path pays a small delay; only a path that genuinely stutters pays a large one.
     - **A live source's backlog is bounded, and audio past the bound is dropped rather than played late.** Whatever sits queued for a live source *is* the delay the listener hears, and it is otherwise monotonic — a network stall, a scheduling hiccup, or plain crystal drift between two machines' sound cards each add to it and nothing takes it away, so a long call drifts steadily further behind. Past the prebuffer target plus `JITTER_QUEUE_SLACK_MS`, the oldest audio is dropped to bring it back to target: a moment's artefact instead of a permanent delay.
     - **A recording is exempt from all of it** — a chime, a replayed voice message, an OTP clip: its queue is the message itself rather than accumulated delay, so it is never trimmed however long it is, never made to wait for a prebuffer however short it is, and plays in full. Which kind a source is is stated by whoever pushes it, not inferred from whether it has finished: a recording is handed over whole and finished only afterwards, so in that window it looks exactly like a live source with a big backlog.
   - **Wire coding.** A chunk travels coded (IMA/DVI ADPCM, 4 bits a sample) rather than as raw PCM — a quarter of the bytes, and what makes a multi-party call fit an ordinary uplink at all (`docs/PROTOCOL.md` §7.3 has the format and the reasoning). Each chunk decodes standalone, because chunks travel unreliably and a lost one must not corrupt the rest. What a receiver *accumulates* — the replayable message, what gets exported, what goes under one-time-pad framing — is decoded PCM; the coding exists only on the wire.
   - **Echo.** The microphone hears the speakers, so without something in the way, whoever else is talking gets their own voice sent back to them. Two things address it, in order of preference:
     - **A capture device that cancels echo itself is preferred** when one exists — PulseAudio/PipeWire's `module-echo-cancel` source, or a driver exposing a hardware-cancelled endpoint (`voice.rs` `is_echo_cancelling_device`, `voice_pulse.rs` `PULSE_ECHO_CANCEL_SOURCE`). This is real cancellation, it keeps the call full duplex, and when one is in use the ducking below is switched off as redundant.
     - **Otherwise the microphone is ducked** while remote audio is playing (`voice.rs` `EchoDucker`): attenuated by 18dB rather than gated, ramped in and out, so the echo path loses far more than it gains while someone deliberately talking over the other side is still heard. It needs no clock alignment, no adaptive filter and no native dependency, which is the trade — it is suppression, not cancellation. Applies to voice messages and live calls alike, since both capture through the same microphone while the same speakers play.
     - **Whether to duck is worked out from the audio, not asked** (`voice.rs` `EchoProbe`). Nobody has to declare whether they are on headphones. The microphone's own level is averaged separately over the moments the far end is talking and the moments they are not; on speakers the first average sits above the second because the microphone is picking their voice up, and on headphones the two match. Your own speech lands in both averages — you don't arrange your talking around theirs — so it cancels out of the difference. This is tractable in pure Rust precisely because *detecting* an echo path only needs the two loudness envelopes at chunk resolution, while *cancelling* one would need the playback signal aligned to the capture sample by sample across two independently-clocked devices. It starts out ducking (the assumption whose failure everyone else in the call hears, rather than only you), so headphones cost a second or two of ducking at the start of a call and speakers cost nothing; the engage and release thresholds differ so a borderline room can't flap; and it re-decides on its own when headphones come out mid-call, which no setting can do.
     - **`voice_echo_ducking` in `~/.aloo/settings`** is `auto` (the above) by default, with `on`/`off` to force it for a room the detector gets wrong — its blind spot is someone who only ever talks at the same time as the far end, which stops the two averages separating.
   - **End-of-message chime.** A short "message ended" sound (`assets/end.wav`) plays through the same mixer both when the sender releases Space and when an incoming stream finishes, so both ends of a voice message get the same audible cue. Bundled as WAV rather than the project's original `assets/end.mp3` so it can be decoded (`voice::decode_wav_to_mono`) without an MP3 crate dependency - a WAV's PCM payload is read directly.
   - **Device handling.** Multi-channel input (an input device negotiating stereo-or-more, common even for a physically mono mic) is downmixed to a single mono sample per moment in time as it's captured, before anything else touches it. On Linux, capture/playback prefers a device routed through PulseAudio over whatever the raw ALSA host reports as default, when one is available - the plain ALSA host normally requires each process to have exclusive access to a device, which would otherwise make it impossible for two `aloo` clients on the same machine (the normal way to test a channel/DM locally) to both use the mic/speaker at once.
   - **Global push-to-talk.** A second trigger, bound to **Ctrl+Alt+P** by default, does the same thing as holding Space - starts a live stream to whatever channel/DM was last active and stops it on release - but works even while `aloo` isn't the focused window, so speaking doesn't require switching back to the terminal first. Configurable in `~/.aloo/settings` (created with these defaults on first run if missing): `global_ptt_enabled` (`true`/`false`) and `global_ptt_shortcut` (any combo `global_hotkey::hotkey::HotKey` parses, e.g. `ctrl+alt+p`, `shift+F1`) - an unparseable shortcut falls back to the default with a startup warning rather than failing to start. Space and the global shortcut can never stop a recording the other one started; a global recording is never subject to Space's idle-silence auto-stop guess, since the OS always reports its release for real. Like Space, the end-of-message chime (above) plays only once, on release - there's no visible "recording..." indicator while the app isn't focused, but the chime firing mid-recording on press was found more confusing than helpful and was removed. **Platform support:** Windows and macOS, and Linux under X11 only - Wayland compositors have no equivalent capability at all, so aloo detects this at startup and prints a one-line warning instead of registering (Space still works normally while the app is focused).

5. **Choose a nickname and have it enforced as unique.** The nickname is set in the connect popup (prefilled from the OS username, editable, no whitespace allowed, capped at 11 characters). On connecting, the server rejects the `Identify` request and closes the connection if that nickname is already in use by another currently-connected client; the client then returns to the popup with the error shown, ready to retry with a different nickname. The check is race-free: two simultaneous connection attempts for the same nickname can't both succeed. A nickname is freed again as soon as its holder disconnects — including when the disconnect was never clean (a crash, a lost network, a sleeping laptop): the client sends a heartbeat every 10 seconds, and the server frees the nickname if 30 seconds pass with nothing received from it at all (`docs/PROTOCOL.md` §4.1), so a vanished client is never squatting on a name forever.

6. **In-app help, toggled with Ctrl+H** (Escape closes it too). Works from any view or mode — the channel view, an open private room, mid-recording, even with the join-private-channel popup already open — and takes priority over everything else, since it's checked before any other key handling. A hint (`Ctrl+H: Help`) is shown at the top right of the screen, past the end of the two selectors, as a reminder that it's always available. The overlay takes the whole frame — full width, from the row above the header down through the compose bar: it is a page to read, several screens long on a small terminal, and every column it does not take is a column its key table has to wrap in. Arrows/PageUp/PageDown scroll it.

    It is laid out in two columns. The first is reserved for keys and commands and is as wide as the longest one in the whole page, so every description in it starts in the same place. The second holds the descriptions, wrapped to whatever width the terminal leaves — and a description too long for one line continues in that same column rather than under the keys, so the page reads as two aligned columns at any width. Prose that belongs to a section rather than to one key sits in the description column too. Section headings are yellow, keys keep the bright default colour, descriptions are gray.
   - Pressing it opens a centered popup covering how to join a hidden (private) channel, how to send a voice message, how to send/receive a file (Functionality #9), what each of the two encryption tags means, and a general keybinding reference — everything in this document's Functionality section, condensed.
   - The popup's content is taller than fits most terminal windows, so it scrolls: `Up`/`Down` move one line, `PageUp`/`PageDown` jump by `HELP_SCROLL_PAGE` lines, and `Home`/`End` jump straight to the top/bottom — clamped so it can't scroll past either end. It always reopens scrolled to the top, never wherever it was left last time.
   - While the popup is open, every other key is absorbed (no typing leaks into the compose bar, no navigation happens underneath) except Ctrl+H itself, which closes it again and returns to exactly whatever was showing before, and the scroll keys above. Esc does not close it — only Ctrl+H does, since Esc already means something else (close the current private room) when help isn't open, and the popup deliberately doesn't try to disambiguate the two.

7. **Offline users.** When a user's connection closes entirely (as opposed to them leaving one channel while staying connected elsewhere — Functionality #2), every peer who shared a channel with them is notified (`docs/PROTOCOL.md` §6.4). What each peer's client does with that depends on whether it has private-message history with the now-offline user:
   - **With at least one message (sent or received) in that user's private room:** they're kept listed in every channel they'd joined, rather than removed, with their name rendered in soft gray instead of their usual direct-link colour (see "Connected UI" above) — so their history stays reachable (reopen their private room the same way as any other user, Functionality #3) without pretending they're still around.
   - **With no private-message history:** they're removed from the channel's user list exactly as if they'd explicitly left it (Functionality #2) — there's nothing to keep them around for.
   - **Opening (or already having open) an offline user's private room** replaces the compose bar's contents with `(user offline)` in red while nothing is typed, and refuses to send anything typed there, for as long as that user stays offline — `/endotp` (Functionality #15) included, which is refused with its own explanatory notice rather than silently, since ending a session is a two-party handshake an offline peer cannot confirm. The moment anything is typed it replaces the red notice; only actually sending it stays refused. This applies regardless of whether they were kept listed in any channel, since it's driven by "is this specific peer offline right now", not by the retention rule above. This is scoped to that one peer's room only, not a global switch: the channel compose bar and any other, still-online peer's private room keep working normally the whole time, including one reopened for a peer who went offline earlier and is back.
   - **Voice recording (Functionality #4) ignores an offline direct-message target.** Holding Space while viewing an offline user's private room does nothing — no recorder is started, nothing is sent — the same as pressing Space with no channel joined and no private room open. A channel voice recording is unaffected by one of its members being offline: it's simply excluded from that recording's recipients, same as any other member the sender doesn't currently have a way to reach.
   - A user going offline is permanent for the rest of the session *for that `UserId`* — one is never reassigned (`docs/PROTOCOL.md` §3), so the same person reconnecting always arrives as a brand new identity rather than the old one turning back on.
   - **They still take their own place back.** A peer who reconnects replaces their own row where it stands (and it counts as an arrival, so the join notice fires, in every channel they were in), and their private room — its whole history, its place on the DM selector, and any active one-time-pad session — moves onto the id they have now. So the conversation continues in the same window instead of a second one opening beside it. The match is on the **nickname**, the only thing about a person that survives a reconnect and already this app's continuity anchor (`id_store` pins by it, `/mute-voice` remembers by it), and only for a nickname this session actually saw go offline — one still known to be connected is somebody else's live row and is never taken over. What belonged to the connection that closed — an unanswered identity review, held messages, an offer in flight — is deliberately left behind, so the returning connection gets its own identity check (Functionality #8), which is what makes trusting the nickname here safe.
   - Going offline also logs a yellow presence notice — see Functionality #12.

8. **Identity pinning (`id_store`): deciding whether to trust a nickname that reconnects under a different key, and from a different device.** Full model in `docs/PROTOCOL.md` §12; from the user's point of view:
   - The client keeps a small local file — set via the connect popup's `id_store` field — that remembers each `(nickname, device_id)` pair's **full public key** (hex-encoded, not just a hash of it) from the last time it was seen, for the `password` and `pq_hybrid` `my_key` types. Storing the whole key (not a fingerprint) means a pinned entry can be verified against an actual key file, not just trusted as "some hash matched" — a fingerprint is still computed on the fly for display in the review popup below. **A nickname's pin is per-device and additive**, never silently replaced: reconnecting from a second machine is a routine, expected event, so pinning a new device's key never touches or removes another device's already-pinned entry.
   - A pinned key is checked by simple comparison — a `pq_hybrid` identity is loaded from a file and never supposed to change, so any difference at all is the signal. A peer announcing bytes that do not decode as a keybundle has no `pq_hybrid` identity to pin, and is tracked instead as an independent, `Direct`-framed pin (below) that never collides with a `pq_hybrid` one for the same nickname.
   - The first time a nickname is ever seen at all, or a new device of an already-known nickname is seen for the first time, or one is seen again with the same (or provably continuing) key as before, nothing happens — this is invisible in normal use. A first sighting is still saved to disk immediately, so it's pinned for the next reconnect too. Reconnecting from a device this client already knows about — even before that device's identity is confirmed — silently claims that device's key in place, rather than raising a review, once the two provably match.
   - If a nickname reconnects from a device whose pinned key doesn't match — a byte change against every device sharing this pin's encryption method (`docs/PROTOCOL.md` §12.4) — messaging with that device is gated immediately, and the **identity review popup** (see "Connected UI" above) opens as soon as this connection's own address/device id are known (below), naming the user and a short fingerprint of both the old and the new key. This can mean the person genuinely regenerated their key, that they're connecting from a device whose key looks unfamiliar, or that someone else is now using that nickname — the app doesn't decide which; it puts the decision to the user via **Accept** or **Reject**, rather than guessing.
   - **Accept** trusts the new key for *that specific device* from that point on: it's saved to disk immediately — synchronously, in real time, not batched or deferred — and any of that peer's channel/DM messages that arrived while the review was unresolved (held rather than shown, see below) are revealed into the log, in the order they arrived. Crucially, **every other device already pinned for that nickname is left completely untouched** — Accept only ever adds or updates the one device under review. **Reject** writes nothing to disk at all — the previous pin for this device, if any, is left exactly as it was — and is never a permanent block: selecting that peer again (Enter on their sidebar entry) reopens the same popup for reconsideration, rather than staying silently stuck. **Nothing else needs a separate update either**: `/info`/`i` on that peer already shows whichever device this connection actually is, before and after Accept alike, since it reads the live connection rather than the pin; and if a one-time-pad session was already running with the *old* device, it's left completely alone — OTP's own keychain naming is independent of this pin — so only the ordinary (non-OTP) messaging moves onto the newly accepted device, not any pad session already in progress.
   - Until a peer's review is resolved (`Pending`), and for as long as it stays `Rejected`, messaging with them is gated: this client won't send them anything (excluded from a channel send, and their private room can't be opened or typed into at all), and anything they send is held rather than displayed — decrypted normally, since that only needs *this client's* own key, but not shown until they're `Accept`ed. Their sidebar entry renders red the whole time, taking priority over the offline-gray color. A channel message is otherwise unaffected: it still reaches every other, verified member.
   - Several peers — or several devices of the same nickname — can be unresolved at once; the popup shows one at a time, in the order their mismatches were detected — resolving the one showing (either button) opens the next automatically.
   - **Device id and last-seen address** (`docs/PROTOCOL.md` §12.7). Each installation generates a random 8-character id, unique per nickname, the first time it connects as a given nickname (`~/.aloo/d_id`) and reuses it for that nickname forever; it's sent to a peer as part of establishing the direct connection. Unlike an address, a device id is not purely informational: it decides *which* of a nickname's several devices a key comparison runs against or a review is opened for — though a spoofed one still can't grant trust or forge anything on its own, since real acceptance always rests on cryptographic material. Once a peer's direct connection is up, the address it was reached at is remembered alongside that specific device's pinned key. The **identity review popup** shows both: `Last known from <addr> (device <id>)` — whatever was recorded the last time this specific device's *previous* key was connected, `unknown` if it never was, or if there is genuinely no other device of this nickname to compare against yet — next to `Now connecting from <addr> (device <id>)` for this specific attempt, `unknown` if the direct connection couldn't be established at all. This is exactly why the popup itself waits a moment after the mismatch is first detected: without it, there would only be two fingerprints to go on.
   - **`/contacts` shows one row per pinned device, not one per nickname.** A multi-device contact produces one row per device, each with its own non-editable **device** column (a fixed `(unbound)` placeholder for a pin with no device confirmed yet, and a real device id — 8 characters, since `~/.aloo/d_id` ids are 8-character random strings, so this rarely crops in practice — cropped to 10 characters plus `...` if longer) between the nickname and the last-seen columns, and its own three keys: PQH, OTP, OTP MAIL, each rendered as a small button — `[✅ PQH]`/`[❌ OTP]`/`[❌ OTP MAIL]`, green or red naming whether it exists. Selection is a genuine grid: `Up`/`Down` moves which **row** (device) the cursor is on, `Left`/`Right` moves which **key** the cursor is on within that row, and only the one button that is both the current row and the current key is highlighted (a gray background) — never the same key across every row at once, so which device's key `Enter` is about to open is never ambiguous, even for two rows of the same nickname. `Enter` opens that exact (device, key)'s details popup. The popup always shows a fixed, yellow explanation of what that key is for (PQH pins an identity so you can use pqh encryption at all; OTP is for live sessions when you're both online; OTP MAIL is for mail that waits, encrypted, until the recipient comes online — `docs/PROTOCOL.md` §16.1.1/§17), then the **full, uncropped device id** it was opened for — deliberately never the list's own cropped one, since this is exactly where a cropped id would leave a destructive action (delete key) or an install ambiguous about which device it targets — then either its path on disk (plus, for OTP/OTP MAIL, the same seq/offset/remaining-per-direction figures shown elsewhere) and a **Delete key** action behind a confirm, or — if it doesn't exist — **Create key** (PQH: import a self-signed identity card via a file browser, `docs/PROTOCOL.md` §12.6 — upgrades the nickname's unbound entry, never a specific already-bound device, since a card vouches for a key rather than a device; the one exception is a brand-new contact from **Add contact** below, which binds directly to the device just typed instead) or **Install manually** (OTP/OTP MAIL: a two-file-path form, filing the result under whichever device the row was opened from, and whichever key was selected — refused outright, with an inline error, if this exact contact still has a live `/otp` negotiation in flight: this side's own fresh-pad proposal awaiting the peer's answer, or the peer's own proposal sitting unanswered as an open invite popup — accept, reject, or `/endotp` it first). `Left`/`Right` inside the popup switches which key it's showing. Deleting the **PQH key from a row's own detail popup** forgets just that one device — its identity pin and both its own OTP/OTP MAIL keys, since they can no longer be named without it — leaving every sibling device untouched; deleting OTP or OTP MAIL alone (from either purpose's own detail popup) touches only that one purpose of that one device. The list's own top-level `d`/Delete still forgets the whole nickname outright, every device at once. Every one of these actions **takes effect immediately**: the list re-gathers its rows, and an already-open `/mail` compose view for that same nickname has its recipient check re-run without retyping anything — unblocking the hard gate above the instant a mail key appears, and re-blocking it the instant one is removed. Deleting a **live** OTP key this way — alone, or as part of a whole-device or whole-contact delete — also ends any session that key was backing, immediately, with a notice: the compose bar's 🔑 badge and every OTP-routed send it implied go with it, the same local effect an incoming `/endotp` from the peer has (`docs/PROTOCOL.md` §16.6). Once a key is fully spent in both directions nothing here is removed automatically — the row still shows `[✅]`, since the keychain entry itself is left exactly as it is — but for a **live** key still marked active, the session ends immediately on its own, with a notice, the same as if you'd run `/endotp` yourself, and this side tries to tell the peer too so both sides converge (`docs/PROTOCOL.md` §16.7). A mail key has no session to end, only a notice that it's spent.
   - **`a` opens Add contact**, for pinning someone before ever connecting to them: a small form asking for a **nickname** (required) and a **device id** (optional), each validated the same way a `direct_punch_to` line's own nickname/device fields already are — non-empty, no tab or newline — and refused if that exact nickname+device already names a real row, or, with a blank device id, if the nickname already has an unbound row of its own. Confirming (`Enter`) immediately creates the contact as a bare placeholder with no key at all — a real row, visible right away with all three key badges red — and opens the very same key-details popup `Enter` on a real row does, so `Esc` at any point leaves the contact pinned but keyless, addable later exactly like any other row missing a key. The **identity card is optional too**: from that popup, PQH's **Create key** binds directly to the device just typed, or the shared unbound slot for a blank one (unlike the ordinary per-row case above, which always targets the unbound slot), filling the placeholder in place; once it succeeds the popup stays open rather than closing, so OTP and OTP MAIL — now eligible, the same as any row with a PQH key — can be added right after in the same sitting.
   - **Exporting this client's own identity card** — the live-session equivalent of `aloo --export-identity-card`, no arguments needed since a live session already has its own keybundle and nickname loaded. Reachable two ways: the `x` shortcut from anywhere in the list, or an **Export identity card (own pqhybrid key)** button that is always the list's own last entry, one position past the last real contact — reached by `Up`/`Down` like any row, and present even with no contacts pinned yet; `Enter` on it exports rather than opening a key-details popup, and `Left`/`Right`/`d`/`o` do nothing while it's selected, since they all act on a specific contact. Either way it writes `~/.aloo/exports/<nickname>.aloo-card`, the same `~/.aloo/exports` root every other export writes under, and shows a status notice naming the path and the bundle's safety phrase — "exported identity card (own pqhybrid key) to `<path>` - safety phrase: `<phrase>`". Purely local, never reaching the server.

   **Reference: every pinning/communication starting state and its outcome.** The crux fact behind the "otp only" rows: a nickname's `pq_hybrid` pin and its serverless, pad-only (`Direct`-framed) pin are independent, non-colliding trust dimensions (`docs/PROTOCOL.md` §12.2) — meeting the same person once serverless and later through a server never collide.

   *Server introduces* (a shared server relays both sides' real identities):

   | # | alice has | bob has | outcome |
   |---|---|---|---|
   | 1 | bob pinned (`pq_hybrid`), matching device | alice pinned (`pq_hybrid`), matching device | ordinary silent communication, both sides |
   | 2 | bob pinned (`pq_hybrid`), **different** device | alice pinned (`pq_hybrid`), matching device | alice gets an impersonation review; `Accept` **adds** bob's new device alongside the untouched old one; bob sees nothing — asymmetric, each side judges independently |
   | 3 | only bob's otp key (no `pq_hybrid`) | only alice's otp key (no `pq_hybrid`) | neither side has a `pq_hybrid` entry for the other yet → mutual first sighting, fresh `pq_hybrid` pins created silently, independent of and without touching the pre-existing otp-only relationship |
   | 4 | only bob's otp key (no `pq_hybrid`) | nothing for alice at all | identical outcome to row 3 — bob's side is a plain first sighting either way; alice's unrelated otp-only entry never enters the `pq_hybrid` comparison |
   | 5 | bob pinned, matching device | nothing for alice at all | ordinary asymmetric case: bob's side first-sights alice silently, alice's side already matches — communicates normally on both sides |
   | 6 | bob pinned, matching device, announced key differs **with a valid continuity cert** | — | silently re-pinned in place, no review, status-line notice only — checked against every device entry, so it still fires even if the retiring identity also changed devices in the same step |
   | 7 | bob pinned under two devices (d1, d2); a third device (d3) announces the **identical** key already pinned under d1 (a copied `my_key` file) | — | still an impersonation review — identical bytes never silently merge into a device that never proved it holds them; only a human `Accept` adds d3 |

   *No server / server unreachable* (`--no-server`, or a reachable server with no shared `pq_hybrid` pinning for this pair):

   | # | alice has | bob has | outcome |
   |---|---|---|---|
   | 1 | bob pinned (`pq_hybrid`), matching device | alice pinned (`pq_hybrid`), matching device | ordinary `pq_hybrid`-framed communication over the punched link — `pq_hybrid` pinning doesn't care whether a server is present |
   | 2 | bob pinned (`pq_hybrid`), different device | alice pinned (`pq_hybrid`), matching device | same impersonation review as server row 2 |
   | 3 | only bob's otp key | only alice's otp key (mutual) | they punch directly (`direct_punch_to`); every message carries the sender's device id as **cleartext wire metadata**, checked before `otp --decrypt` ever runs (no pad spent on a mismatch, `docs/PROTOCOL.md` §16.2.2); the first message binds the pad; a later message from a different device is refused pre-decrypt and stays in the sender's own outstanding queue, retried on reconnect, until the bound device answers. Which device applies is decided at *configuration* time (`direct_punch_to=<nickname>+<device_id>,...`), not live — the claim only confirms that address is still answered by that device |
   | 4 | only bob's otp key | nothing for alice at all | **they cannot communicate** — serverless mode has no discovery mechanism at all; both a `direct_punch_to` entry and a pinned counterpart key must already exist on *both* sides before either side can even derive a contact name to punch with |
   | 5 | nothing for bob | nothing for alice | same as row 4 — no communication possible; serverless mode's baseline is "must already be a mutually pre-arranged contact" |
   | 6 | alice has **two devices**, each with its own independently-generated raw key for bob | bob has only one `direct_punch_to` line for "alice," naming one address | bob can only ever reach whichever one of alice's devices that line's address/key correspond to — the other is unreachable until bob adds a **second**, device-suffixed `direct_punch_to` line; a configuration gap, not a refusal, independent of whether alice's two devices share one `pq_hybrid` identity or not |

9. **Send a file to a channel or a user, with the recipient's consent.** Type `/file` in the compose bar and press Enter (must be joined to a channel, or have a non-offline, verified DM room open — otherwise this does nothing and the typed `/file` stays put, same as Space with nowhere to record voice to). A popup file browser opens, centered on screen — the same in-TUI widget (`Up`/`Down` select, `Enter` open a directory or pick a file, `Left`/`Right` back/forward, `Esc` cancel) the connect popup's `rsa` server_key field already uses.
    - **Confirmation.** Selecting a file (Enter on it, not a directory) replaces the browser with a confirmation box: `Send "<filename>" to #<channel>?` or `Send "<filename>" to <username>?`, with two buttons, **Send file** and **Discard** — `Discard` focused by default, same reasoning as the identity review popup's `Reject`-first default (Functionality #8): sending should never be one accidental Enter away. `Left`/`Right`/`Tab` move focus, `Enter` confirms. Choosing **Discard** returns to the file browser at the same directory (not all the way back to the compose bar); pressing `Esc` on the confirmation box does the same. `Esc` on the browser itself cancels the whole `/file` flow. Filenames longer than 230 characters are cropped at the end before being offered (`docs/PROTOCOL.md`'s file transfer section) — the receiving client independently crops again on whatever it actually receives.
    - **Offering.** Choosing **Send file** sends an *offer* — filename and size, encrypted exactly like a text message (sealed per recipient, `docs/PROTOCOL.md` §13.3) — to every ready recipient; nothing is read from disk yet. There is no size cap: since the file itself is streamed in small chunks only once accepted (below), the old whole-file-in-one-message limit no longer applies. A channel send is one independent offer per member — one recipient accepting doesn't wait on, or get affected by, another rejecting — but **one row** in your log for the whole send, the same shape a channel voice message has: the recipients are named individually in its details popup (`i`), not as a line each. That row aggregates all of them: while any transfer is still going it shows the least advanced of them (the file is not sent until it is sent to everyone), and once none are left it reads completed if any recipient took it, rejected if they all declined, and failed otherwise.
    - **The recipient's popup.** Before any file bytes arrive, the receiving side sees a centered popup — accompanied by a chime (`assets/bell.wav`) — reading `<nickname> is sending "<filename>" (<size>) via #<channel>` (or "via a private message" for a DM). Two buttons, **Accept** and **Reject** — **Accept focused by default**, the opposite of this app's usual safety-first default (Functionality #8's identity review, this flow's own Discard-first confirmation above): accepting an incoming file is the common case here, so it shouldn't cost an extra keystroke. `Left`/`Right`/`Tab` move focus, `Enter` confirms. Several offers arriving close together queue and show one at a time, same as identity reviews.
    - **Appearance and progress.** Both sides render the message as a paperclip and the filename, e.g. `📎 report.pdf`, in the channel/DM log — a channel send's per-recipient rows also name who each is addressed to. Before a decision, the sender's row reads "(waiting for accept...)"; once **Accept**ed, the file streams in small chunks straight to `~/.aloo/downloads` (never held whole in memory on either side) and both sides' rows show a live progress bar and percentage until every byte has moved, at which point the row settles back to the plain paperclip-and-filename look. Choosing **Reject** ends it there — the sender's row shows "(rejected)" instead, so declining a file is as visible to them as accepting one.
    - **A `.txt` file previews instead of saving straight away.** Once fully arrived, its row instead reads `📎 <filename> (Enter: preview)`. `Enter` opens a full-width, scrollable, read-only popup with the file's content — capped at roughly 1 MiB, with a truncation notice if the real file is longer (the file itself is never truncated, only what's shown) — and a bottom hint, `d: save   Esc: close`. Opening it tells the sender the file was viewed (`DELIVERED+VIEWED` in their details popup, below) the first time, not on every reopen. `d` does exactly what accepting any other file already does automatically: saves it to `~/.aloo/downloads` and tells the sender it's `DELIVERED+SAVED`. Never pressing `d` simply leaves it unsaved — nothing is lost, since the content stayed staged the whole time, only cleared on the next session start.
    - **Trust gating and offline peers** work exactly like text (Functionality #7/#8): an offer from a `Pending`/`Rejected` sender is decrypted but held — no popup, no chime — until they're `Accept`ed, at which point it's queued for real; a gated or offline channel member is simply not offered the file at all, same as text/voice; an offline or gated DM peer's room can't receive one at all (same gate that already blocks `/file` from starting in the first place).

10. **`pq_hybrid`: a post-quantum hybrid encryption method** — ML-DSA-87+RSA4096 signing, ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption. Full model in `docs/PROTOCOL.md` §13; from the user's point of view:
    - Selected as the `my_key` type in the connect popup - and selected by default. Unlike every other type, its keys aren't generated fresh in-process at connect time; they live in a keybundle file pair (`file_pub`/`file_priv`). You don't have to prepare that pair yourself: the popup prefills the fields (from `~/.aloo/.cache`'s most-recently-used entry for a server you've connected to before, or otherwise a freshly-assigned location under `~/.aloo/`), and connecting transparently generates the actual keys at that location the first time it's used, if they don't already exist (`docs/PROTOCOL.md` §13.9). `aloo --keygen-pq-hybrid <prefix>` (writes `<prefix>` and `<prefix>.pub`) is still there if you want to generate one yourself - e.g. to point both files at a specific, memorable location, or to produce one to move to another machine - but it's optional now, not required.
    - **The connect popup remembers your `pq_hybrid` identity per server.** After connecting (attempted or not - whichever files were used to try), `~/.aloo/.cache` records that `(host, port)`'s `file_pub`/`file_priv`. Reopening the app, or returning to the same server later in one session, prefills the exact same identity automatically - a different server you haven't used before still gets its own freshly-assigned location the first time.
    - Text, file, and voice messages are all signed with **both** ML-DSA-87 and RSA-4096 before being encrypted — a receiver only accepts a message if **both** signatures check out, so a break in either primitive alone isn't enough to forge one. The bulk data is AES-256-GCM-encrypted once per send, and that one-time key is separately wrapped for each recipient by combining an ML-KEM-1024 exchange with a second, independent RSA-4096 encryption — recovering it needs breaking both, not just one.
    - Its own encryption keys rotate every message, per peer relationship - a fresh ML-KEM-1024+X25519 pair each time, cheap enough to run inline with no visible delay. A message typed for a peer before their next fresh key arrives isn't dropped - it's held and sent automatically the moment that key shows up, in the order it was typed. See `docs/PROTOCOL.md` §13.10.
    - **Sealing a send needs a readable keybundle on both sides.** Producing a valid message needs the *sender's* own ML-DSA-87/RSA-sign identity and the recipient's announced bundle. Every client has both, so every peer reached through a server is addressable. A peer who announced no readable bundle is reachable only under an already-installed one-time pad (`docs/PROTOCOL.md` §16.2's `Direct` framing) and is otherwise silently excluded, the same as any other unreachable recipient (an offline member).
    - Voice messages work the same way as text — the expensive signing/key-exchange work happens once per recording, not per 15ms chunk, so holding Space to talk feels identical to any other method.
    - Its identity is static (loaded from the keybundle file, not regenerated every session) and file-backed, so it's pinned in `id_store` exactly like `password` (Functionality #8) — a `pq_hybrid` nickname reconnecting under a different keybundle triggers the same identity review popup a changed `password` key would.

11. **Leave a channel with `/leave`.** Type it in the compose bar and press Enter — no argument, it always targets the channel the channel selector currently names (must actually be joined, same "leaves the typed command in place if it can't act" behavior as `/file`). It drops off that selector with the membership, public or private alike; a public channel is still listed in `/channels` to rejoin from. Leaving also drops every direct peer link that channel was the only reason for (Functionality #2, `docs/PROTOCOL.md` §7.1.3). Full model in `docs/PROTOCOL.md` §6.2/§7.1.3.

12. **Presence notices in the message log.** A peer joining, leaving, or disconnecting logs a plain, app-generated line into the message log — `<local time> <name> joined`/`left`/`disconnected`, rendered in yellow (`MessageBody::Presence` — distinct from the gray/italic `MessageBody::System` OTP's own narration uses, and, like it, never given the OTP 🔑 prefix). The local time is this client's own wall clock, `HH:MM:SS`.
    - **Joined** — logged into a channel's own log the moment someone joins it, but only for a genuine live join: the existing-member snapshot a client's own first join into that channel receives (Functionality #2, `docs/PROTOCOL.md` §6.1) is silent, since it isn't really anyone joining, just being introduced to who's already there. A duplicate join for someone already listed logs nothing either.
    - **Left** — logged into a channel's own log the moment a member leaves it (Functionality #2).
    - **Disconnected** — a full disconnect (Functionality #7) is not scoped to one channel, so it's logged into every channel the departing user was a member of, and into an already-open private room with them, all before any of that connection's membership bookkeeping runs — so the notice still lands even for a peer with no DM history, who is then dropped from the channel's member list in the same call.

13. **OTP mail: write someone a mail that waits, one-time-pad encrypted, on the server until they connect.** Full model in `docs/PROTOCOL.md` §17; from the user's point of view:
    - **`/mail`** refuses locally, before opening anything, if the local `otp` binary isn't available — the same check `/otp`/`/new-otp-mail-key` already make (docs/PROTOCOL.md §16.1), so composing a mail can never reach send time only to find out there. Otherwise it opens a **full-screen compose view** in the compose bar — a command rather than a key chord, since the natural chord (Ctrl+M) and Enter are the same byte on terminals without the kitty keyboard protocol: From (fixed to your own nickname), To, a **Device** selector, Subtext (the subject line), a multi-line Content box, and an attachments pane. Tab/Shift+Tab cycle the fields; they can be filled independently, in any order. The terminal's own cursor blinks in To the instant the view opens, and tracks whichever single-line field (To/Subtext) Tab moves focus to next — the same "which field is about to receive keystrokes" cue the connect popup's own fields give. Esc discards the draft and returns to whatever view was underneath.
    - **The To field validates as you type**, on every keystroke: a valid recipient — a pinned device under that nickname (Functionality #8) whose pin is a `pq_hybrid` identity, an OTP **mail** keychain contact for the pair (its own key, entirely independent of any live `/otp` session with the same person — `docs/PROTOCOL.md` §16.1.1 — never one and the same, even when both exist), and a key strictly longer than the whole mail — renders green with a ✅; anything else renders red with a ❌ and the specific reason inline. The verdict is live in both directions: typing enough content to outgrow the pad flips a valid recipient back to ❌.
    - **The Device selector, below To, names which of the recipient's pinned devices the mail is sealed for.** It lists every device the resolved nickname has an identity pin for, each with a ✅/❌ for whether it carries a mail key, and defaults to the most-recently-seen device that has one (falling back to the most-recently-seen device overall only if none does). Tab only stops there once at least one device is known — an unpinned or not-yet-checked nickname skips straight to Subtext, unchanged from before this selector existed. Up/Down move the selection and re-run the To field's own validation against whichever device is now highlighted; Send seals the mail under that explicitly selected device, never an implicit guess.
    - **No mail key at all is a hard stop, not just a red ❌.** A centered, red modal covers the compose view (still visible underneath) reading `no otp mail key available for <nickname> - install one manually from /contacts or exchange one with the user if he is online using /new-otp-mail-key (requires pinned contact)`. Every key but Esc does nothing while it's showing — no typing, no attaching, no Ctrl+S — and Esc closes the modal *and* the whole compose view together, in one step; there's no way to fix the recipient in place and carry on. **`/new-otp-mail-key`** is how two people who are both online right now get one: the same consent/size/glare/transfer flow `/otp` itself uses (`docs/PROTOCOL.md` §16.1), just producing a mail-only key instead of a live-session one. `/contacts`' key details popup (Functionality #8) is the other way, for installing one manually or when only one of you is online. Unlike `/otp`, which legitimately re-sends its request even when a key exists (that's how a paused session resumes), a mail key has no session to resume - but run again on a contact that already has one, it does not refuse either: it always proposes a fresh key, exactly like a first-ever request, and installing it replaces the old one on both sides. This is the way to replace a mail key that's running low, without deleting anything from `/contacts` first. A pad-only pair (no shared server, `docs/PROTOCOL.md` §7.1.5) is the one exception: there's no channel to share a fresh key over regardless of whether one already exists, so `/new-otp-mail-key` there still refuses, the same as it did before one was ever installed - only a manual `/contacts` install can replace it. And a mail key that ran all the way out on its own - nothing left to encrypt or decrypt in either direction - is never deleted automatically; a notice says so the moment it happens, and the very next `/new-otp-mail-key` still replaces it correctly (it always proposes a fresh key regardless of what's already there, above), so nothing extra is needed to move past it.
    - **The remaining key, in MB, sits in the top right** of the screen once the nickname has validated, and updates in realtime as content is typed and attachments are added or removed.
    - **Attachments** reuse the existing machinery: in the attachments pane, `a` opens the same in-TUI file browser `/file` uses, and holding **Space** — only while the attachments pane is focused; in every other field Space just types — records a voice message with the same hold-to-record flow as Functionality #4, accumulated for the mail instead of live-streamed. **Enter** on an attached voice recording replays it through the normal mixer, and **Esc** during that playback stops it (and nothing else — the compose view stays), exactly as replaying a logged voice message works. An attachment (file or finished recording) larger than the remaining key **cancels the operation** outright, with a notice; `d` removes the selected attachment, after a confirm popup whose default is Cancel.
    - **Ctrl+S sends — only through a confirm popup** (Cancel focused by default). On confirm the whole mail (fields, voice PCM, attachment bytes) is encoded, signed with your durable identity, sealed through `otp --encrypt`, and uploaded; a local reference (never the content) is stored under `~/.aloo/otp_mail/`. The server's acknowledgement moves it to "on server"; if that acknowledgement never arrives, the next connect re-uploads the exact ciphertext recovered from the keychain's `.last_sent` copy under the same mail id — never a fresh encode, never a second pad spend.
    - **`/mailbox` opens the mailbox popup**, laid over the mail view it opens as its backdrop (Esc out of the popup closes an untouched backdrop with it): every sent mail with its delivery status (`awaiting server` / `on server` / `delivered ✓` / `failed` — status only, never content) and every received mail. **Enter on a received mail reads it**: the payload is decrypted in memory only and shown full-screen — Subtext, Content, voice parts playable through the normal mixer (Enter), attachments savable to `~/.aloo/downloads` (Enter). `d` removes a mail (confirm popup): removing a received mail overwrites and deletes its stored ciphertext **and** pad, destroying the content for good; removing a sent mail drops only the local status reference.
    - **Receiving**: a client with the `otp` binary asks the server for its mail right after connecting; each delivered mail is decrypted through the keychain exactly once, its identity signature checked against the pinned sender, then immediately re-encrypted under a fresh local one-time pad and stored as that (ciphertext, pad) file pair — plaintext is never at rest. A notice (with the file-offer chime) announces new mail; the sender is told when their mail was genuinely delivered, on their next connect if offline at the time.

14. **Live voice calls: a continuous, multi-user conversation, distinct from a voice message (Functionality #4).** Full model in `docs/PROTOCOL.md` §7.7; from the user's point of view:
    - **`/call`** in the compose bar starts one, addressed to whatever's currently in view — the selected channel, or an open private room — same "nowhere to send it" no-op as Space (Functionality #4) if neither applies. Refused, with a status notice, while already on a call (there is only ever one at a time), while a push-to-talk recording is in progress, and — DM only — while an OTP session (`docs/PROTOCOL.md` §16) is active with that peer, since that layer has no live-streaming concept at all; a channel call simply leaves out any member under one, the same silent exclusion an unreachable member already gets elsewhere (Functionality #7/#8).
    - **Nobody is rung before you confirm.** `/call` opens a confirmation naming, in yellow, how many people the invite will reach — every reachable member for a channel call, the one peer for a DM. Cancel rings nobody. If the answer is nobody at all, there is nothing to confirm: the call never starts and a notice reads `Call has ended: no one was invited`. A DM call to a peer under an OTP session is likewise refused *before* the confirmation rather than after it — it could never succeed, so there is nothing to agree to.
    - **Every reachable member/the peer sees a popup** — chimed, like a file offer — reading `Voice call incoming from <nickname>`, with **Accept**/**Reject** buttons, **Accept focused by default** (same reasoning as the file-offer popup, Functionality #9). A caller already on a different call is answered automatically with a decline, no popup shown - the reference client supports one active call at a time. Several invites queue and show one at a time, same as file offers; one from a not-yet-trusted identity (Functionality #8) is held, not shown, until that identity is `Accept`ed.
    - **Accepting joins.** Once joined, the microphone stays open continuously - not push-to-talk, no 4-minute cap - and stays that way for as long as the call runs. Every participant who accepts hears every other one; there is no server and no single participant's connection the others depend on staying up (`docs/PROTOCOL.md` §7.7's roster-convergence rule).
    - **A permanent red indicator** (see "Connected UI" above) marks the whole time a call is active, naming how many other participants are currently connected and whether the microphone is muted. The compact header version blinks while unmuted — the same live-activity blink a recording or a streaming voice message uses — and shows 🔇 in place of the dot, steady rather than blinking, while you are muted.
    - **A call modal** opens the moment the call becomes active — for the caller and for everyone who accepts — and is the call's own screen:
        - **The live duration sits on top**, in yellow, ticking every second.
        - **Below it, everyone on the call**: the **host** (whoever ran `/call`) first, named `<nickname> (host)` rather than carrying a label of its own — your own row reads `<nickname> (you)`, and both marks together on your own call. Each row then carries where that person stands — `IN CALL` in green, `INVITED` in yellow for an invite nobody has answered yet, `REJECTED` in grey for one that was declined — plus `MUTED` in red if they cannot currently be heard — whether they silenced themselves or the host did, since the row answers "can I hear this person right now" — and a **live voice-level bar** that moves with what they are actually saying. Every row is `<nickname> <labels> <voice meter>` and all three columns line up down the list: the name column is as wide as the widest name in *this* call, followed by four columns of gap so a name that fills it never runs into its label; the label column is as wide as the widest label pair in the call, and the meters sit flush against the modal's right edge — so a `MUTED` appearing on one row never slides that row's bar out of line with the others. The modal itself is only as wide and as tall as the call in it needs: two people with short names get a small modal rather than a fixed box with blank columns down its middle. Your own bar reads empty while you are muted. Only the host ever sees `INVITED`/`REJECTED`: everyone else learns the roster purely from who is actually on the call.
        - **The list scrolls**; Up/Down move the cursor and it stays in view.
        - **`Esc` folds the modal away** into the top row's `⏺ Call Ctrl+R` indicator — a red-bordered box filling the header band's full height, sitting immediately left of the status figures — so the ordinary sidebar/messages/compose layout is usable again. **`Ctrl+R`** brings it back up over that layout. `[`/`]` work through the modal too — they fold it away first, so it doesn't reappear on top of whatever was navigated to.
        - **`END CALL`** (Enter, or `e`) **asks first**: a small red-bordered box over the modal, `Leave this call?`, with `END CALL` and `Cancel` — `Cancel` focused, so a stray Enter on the modal's default button costs nothing and leaving takes a deliberate move onto the other one. It absorbs every key while it is up (Escape answers it the same as Cancel), so no roster key can be mistaken for an answer. Confirming leaves the call — the same thing `/endcall` does from anywhere once the modal is out of the way, which is not gated: typing a command is already deliberate.
        - **`m` on your own row mutes your own microphone**, and again unmutes it: captured audio is simply never sent while muted, so every other participant hears silence, same as an ordinary pause in talking. It stays yours alone to lift, and nothing about the call ends — but everyone is told, so every roster shows you as `MUTED` while it lasts (`docs/PROTOCOL.md` §7.7).
    - **Silence isn't sent.** A call is a full mesh — every participant sends separately to every other — so a moment when nobody is speaking costs a packet to each of them for nothing. Capture stops going on the wire once it has been quiet for `voice.rs` `SILENCE_HANGOVER` and resumes the instant it isn't; the hangover is what stops the pauses *inside* speech (the closure before a plosive, the gap between words) from cutting the stream. Deliberately **not** done for a voice message (Functionality #4), which is a recording the receiver reassembles chunk by chunk: dropping its silence would shorten the message and pull the audio either side of a pause together.
    - **Echo control applies here exactly as it does to a voice message** (Functionality #4's "Echo"), and matters more, since a call runs continuously rather than for the length of one held key.
        - **The host can mute anyone else** with `m` on their row. Unlike muting yourself, that is not theirs to undo: the muted participant stops sending until the *host* lifts it, and everyone's roster shows it. On anyone else's row `m` does nothing for anyone but the host.
        - **The host can invite one more person** with `i`, choosing from the people they share a joined channel or DM history with. Anyone already on the call, or already holding an unanswered invitation to it, is not offered — one active invitation per user at a time.
    - **When the host leaves, the call ends for everyone**, and each participant is told: `Call has ended: the host left the call`. Any other participant leaving just removes their row. Anyone still holding an unanswered invitation to that call is told too, so an invite can never outlive the call it was for: **accepting an invite whose call has already ended starts nothing** and says `that call has already ended` instead.
    - **`/endcall`** leaves the call: every other participant is told and stops hearing from us. Refused, with a notice, while not on a call. For anyone but the host the call has no separate "end" beyond that — it is, at any moment, simply whichever participants haven't yet left.
    - **Mutually exclusive with push-to-talk.** Space and the global shortcut (Functionality #4) do nothing while on a call - the microphone is already spoken for - and `/call` cannot be run mid-recording either.

15. **`/endotp`: ending an active one-time-pad session, in sync on both sides.** Full model in `docs/PROTOCOL.md` §16.6; from the user's point of view:
    - **Either side may end a session alone**, no accept/reject needed the way starting one does - the peer is told, not asked. Typed in the same open DM room `/otp` was started from. Refused, with a status notice, if there is no active session with that peer, if an end is already in flight, if the peer is offline, or if an OTP mail (Functionality #13) to that same contact is still awaiting delivery confirmation.
    - **It needs both of you online, and takes effect only when the peer confirms.** Ending is a two-phase handshake: `/endotp` shows "ending session - waiting for <them> to confirm" and your side *stays in the session* - with new sends to that contact refused out loud - until their acknowledgement of the end notice comes back, at which point "OTP session ended - confirmed by <them>" appears and both sides stand paused together, never one paused while the other unknowingly keeps spending the pad. An offline peer can confirm nothing, so `/endotp` at one is refused with a notice saying to try again when they're back - the compose bar still shows what's typed the moment anything is, rather than the fixed "(user offline)" notice. `/otp` cancels a pending end if you change your mind.
    - **A confirmation lost mid-handshake still arrives, however long that takes.** If the peer drops after the notice went out but before confirming, your side stays in the session and aloo re-delivers that exact notice - recovered, never re-encrypted - every time a direct link to them next becomes reachable, until their acknowledgement genuinely lands; their side ends the moment the notice reaches them, yours the moment the confirmation reaches you. The receiving side never gets a vote: there's nothing to accept or reject, only to converge to, and it pauses its own side the moment the notice lands.
    - **The pad is paused, never destroyed.** Both sequence counters and the keychain entry survive, so a later `/otp` with the same contact resumes the identical pad exactly where it left off rather than generating a new one.
    - **Neither side disconnecting ends a session by itself.** A peer going offline and coming back - even under a fresh identity handle internally - leaves an active session exactly as active as it was; only `/endotp`, run by one of the two participants, ever ends it.
    - **The DM itself is unaffected, only reachable a different way.** While a session is active, every DM with that person rides it - there's no way to send one a plain, non-pad-wrapped message in the meantime (§16.2). Ending a session never closes the private room or stops you talking to that person, though: it only turns off the extra pad layer, and every message from that point on goes right back to a plain send, same as before `/otp` was ever run - the compose bar's own 🔑 (live state, §7's tag convention) disappears with it. Every message already logged while the pad was on keeps its own 🔑 permanently, since it names what that message actually was, not what the session is doing now.
16. **Mute one person's voice messages with `/mute-voice <nickname>`.** A voice message plays itself the moment it arrives (Functionality #4) — which is the point of a walkie-talkie, and occasionally the problem with one. Muting turns that off for one person, without turning off anything else.
    - **`/mute-voice <nickname>`** stops that nickname's incoming voice messages from playing on arrival; **`/unmute-voice <nickname>`** resumes them. Both confirm with a status notice. Either command **with no nickname** lists who is currently muted instead of erroring — nothing else in the UI answers that question. These are the only two commands that take an argument; a second word is refused rather than guessed at, since a nickname never contains whitespace.
    - **A muted message is not a blocked one.** It still arrives, still decrypts, and still appears in the log as a replayable entry — only live playback is suppressed, so `Enter` on it plays it whenever you choose. This is the same mechanism a not-yet-trusted sender's audio already goes through (Functionality #8): decrypted and accumulated, never sent to the mixer. The end-of-message chime is suppressed along with it, since it would otherwise announce audio that never played.
    - **Muted users are marked `🔇` in the sidebar**, so a channel that has gone quiet because someone is muted is distinguishable from one where nobody is talking.
    - **Muting is by nickname, not by connection.** Someone can be muted while offline, or before they have ever connected, and the mute applies the moment they appear. It persists in `~/.aloo/settings` as one `muted_voice=<nickname>` line per entry — one line each rather than one comma-separated value, because a nickname rejects only whitespace, so a comma is legal inside one. Being keyed on a name rather than a key makes this a comfort setting, not a security control: nicknames are unique only among currently-connected clients and are never reserved (which is exactly why identity pinning exists, Functionality #8), so a mute can in principle land on a different person who later takes that name.
    - **It never affects a live voice call** (Functionality #14). Who you can hear on a call is separate state that lasts only as long as the call; `/mute-voice` is about messages that arrive on their own.

17. **Direct punching: keeping a link to someone with no server involved.** Full model in `docs/PROTOCOL.md` §7.1.5; from the user's point of view:
    - **It is off unless `~/.aloo/settings` turns it on**, and it is entirely separate from the ordinary direct link (Functionality #2, §7.1) - turning it on changes nothing about how everyone else is reached.
    - **You name who to punch at, where, and how often.** `direct_punch=on`, then one `direct_punch_to=<nickname>,<host>,<frequency>` line per person. The host may be an IPv4 address, an IPv6 address or a hostname, and may carry its own port (`bobpublic.com:9000`, `[2001:db8::1]:9000`); with none, both sides assume `direct_punch_port` (7879 by default). The frequency is one of `every_1m`, `every_5m`, `every_10m`, `every_15m`, `every_20m`, `every_25m`, `every_30m`, `every_35m`, `every_40m`, `every_45m`, `every_50m`, `every_55m`, `every_1h` — the `every_` prefix keeps a line unambiguous at a glance.
    - **Both people have to configure each other.** There is no server to arrange a meeting, so what makes two clients probe at the same moment is that both run the same frequency and both schedules restart at every o'clock: `every_1m` fires at :00, :01, :02, ...; `every_1h` at :00 only. A client started mid-slot waits for the next boundary rather than probing at a time its peer has no reason to answer.
    - **A line with a typo says so** at startup, naming the line and the reason, and never costs the lines around it - a mistyped frequency must not look like a peer who simply never answers.
    - **An attempt lasts 30 seconds**, and a slot arriving for someone already connected does nothing at all. If a connected link drops and there is no server that could re-establish it, it is re-punched straight away, up to 5 times, before going back to waiting for its next slot.
    - **There is never more than one connection to the same person**, whether it was opened directly or through a server.
    - **They show up as a real person, not just a connection.** Once a punched link opens, each side sends the other a sealed note saying which channels it is in. Opening that note is what proves who they are — it is checked against the key already pinned for that nickname — so a punch alone registers nobody, and someone able to reach your port cannot claim to be a friend. That note needs a pinned `pq_hybrid` identity to be sealed to.
    - **Or a shared pad proves it instead.** Two people who hold a one-time pad for each other but have never exchanged `pq_hybrid` identities have no note to send — and are exactly who this is for. The pad stands in: a link opening to someone you hold a pad for registers them straight away, with the session already on (there is nothing to negotiate — you both already hold the key — so `/otp` opens no round trip and your first message rides the pad). Coming the other way, a pad-wrapped message from someone nobody introduced is opened first and registers them only if `otp` genuinely decrypts it, which it does only for the holder of the matching key at the expected position. Their nickname comes from your own settings and their key from your own pin — never from anything they claim — so this registers people, it never renames them.
    - **An unpinned name from someone you already listed asks first.** If a `direct_punch_to` nickname punches successfully but you have no key pinned for it at all, you're asked whether to check your other local `pq_hybrid` keys for a match instead of it staying a silent, transport-only link forever — checked whether the proof itself is a plain `pq_hybrid` announcement or an OTP session running on top of one, but never against a pad-only pin, which would mean running every one-time pad you hold against an unverified message just to find out who it's from. Say yes and it runs a real cryptographic check — never a guess — and if exactly one matches, offers to use it for the new name too; confirming pins that key under the new nickname and finishes registering them immediately. Nothing matching says so plainly: "Impossible to establish communication with the user without a key. Requires a server for key exchange or manually exchanging the keys." Declining either question costs nothing — no check runs, and a later message asks again. Three genuinely failed checks from one address, spread over at least two minutes within 10 hours, permanently blocks any further request from it until you edit `~/.aloo/banned_ips.log` yourself. Never triggered for a nickname you never listed, or for anyone the server introduces. Full model in `docs/PROTOCOL.md` §7.1.5.
    - **They appear in the channels you both are in**, and behave exactly like anyone else there: listed in the sidebar, reachable by a channel message, by voice, by push-to-talk, and by a call. That is what makes this work in background mode — with the app in the background and the focus on a channel you both joined, `Ctrl+Alt+P` reaches them, and their voice plays on your side, with no server involved at either end. Attach a terminal later and they are simply there in the sidebar. Focused on their nickname instead, the same applies to your DM.
    - **What they tell you is the whole truth**, not an addition: a channel missing from their note means they have left it. Channels you have not joined yourself are ignored. Sharing no channel at all still leaves them reachable as a DM.
    - **Leaving a channel does not disconnect them.** The link came from your settings and the schedule, not from the channel, so only those end it.
    - **For the two-people case specifically** — a DM with no channel and no server, optionally under `/otp`, optionally headless — see "Talking to one person, with no server" below, which walks the whole thing through.
    - **No-IP updates, for a home connection whose address moves.** `noip_when_no_server_and_direct_punch_is_active=on`, plus `noip_hostname`, `noip_username` and `noip_password` (all off/empty by default, and all three needed for anything to run). Whenever there is no server to hear from — `--no-server`, or the server connection has been lost — and `direct_punch` names at least one target, this runs a background job that keeps that No-IP hostname pointed at wherever this machine currently is: an update fires as soon as it starts, then every 5 or 6 minutes alternately (averaging 5.5 minutes), always landing on second 50 of its minute so it completes before the punch schedule's own boundaries, which always fall on second 0. It stops the moment the server is reachable again. Full model in `docs/PROTOCOL.md` §7.1.5 "No-IP updates".

18. **Running with no server at all (`--no-server`).** A server only ever introduces people and tracks channel membership; everything that carries content was already peer-to-peer. `aloo --daemon --no-server` (add `--foreground` to keep it in the terminal) runs with none. A plain, non-daemon `aloo --no-server` skips the connect popup entirely — there is no server to authenticate against — and either goes straight into a connected, serverless session (reachable only by the `direct_punch_to` peers in `~/.aloo/settings`) if at least one is configured, or exits immediately with a one-line explanation if none is: with nobody to reach, there is nothing for a serverless session to do.
    - **Where everything comes from.** Peers come from `direct_punch_to`, channels from `direct_punch_channel` — one name per line, joined at startup, and the only channels that exist. `Ctrl+J` and `/channels` show exactly those, since there is no directory to browse and nothing to create. Your own identity is your local key; no nickname is claimed from anyone.
    - **What still works:** text, voice, push-to-talk, files, live voice calls, and live `/otp` sessions — all peer-to-peer — plus identity pinning, `--initial-focus`, and the whole daemon/attach flow.
    - **What is refused, by name, when you ask for it:** joining a channel that is not configured, and OTP mail (the server *is* the mailbox — live `/otp` is unaffected). Refusals appear on the status line the moment you ask, never as an action that silently does nothing.
    - **Two different "no".** A server you never had reads as permanent; one that is merely unreachable reads as temporary and worth waiting for. They are never described with the same sentence.
    - **Losing a server mid-session does not end it.** Direct links are peer-to-peer and were never affected, so the session carries on with the server-backed actions refused, rather than disconnecting the people the outage did not touch — and, with a server configured at all, it is being reconnected to the whole time (Functionality #19).
    - **Waiting looks like waiting.** A channel or conversation nobody has punched into yet says *"Waiting for other users to connect directly to you"* rather than sitting blank, so a correctly configured client that is simply early is not mistaken for a broken one.
    - **Worked through end to end** in "Talking to one person, with no server" below, including the `/otp` layer and the daemon flags.
    - **Limits worth knowing.** You can only reach people you have talked to through a server at least once — that is where their pinned key came from — so there is no way to meet anyone new. There is no STUN either, so at least one side needs a genuinely reachable address and port.

19. **Reconnecting to the server, for as long as the session lasts.** Full model in `docs/PROTOCOL.md` §4.2; from the user's point of view:
    - **Losing the server never ends the session, and never ends a conversation.** Direct peer links are peer-to-peer and carry on untouched; what stops is presence — the server frees the nickname 30 seconds after it stops hearing anything (`docs/PROTOCOL.md` §4.1), tells everyone this client went offline, and never mentions it to anyone who connects afterwards. Without reconnecting, a client whose network blinked keeps *sending* messages that arrive perfectly well while appearing in nobody's user list.
    - **It retries by itself, immediately and then on a widening backoff** — 5s, 10s, 20s, then every 30s — with no limit and no giving up. The header says which of those is happening ("Connected UI" above), including a live countdown to the next attempt.
    - **A nickname that is still held is retried, not surrendered.** The connection holding it is usually this client's own dead one, which the server releases within half a minute.
    - **Coming back rejoins the channels you were in**, password-protected ones included (the password is remembered for the session, never written anywhere), so other people — including people who connected while you were away — see you in the member list again. You come back with a new identity as far as the server is concerned (`docs/PROTOCOL.md` §3), which is also why everyone else's is re-learned from scratch on reconnect rather than assumed to have stayed put.
    - **The status line says it once, not repeatedly.** Losing the server, and the first failed attempt with its reason, each raise one notice; after that the header carries it, so a long outage does not bury the conversation under retry messages.
    - **`--no-server` sessions do none of this** (Functionality #18): there is nothing to reconnect to, and the header says so plainly instead of counting down at something that does not exist.

20. **Delivery acknowledgments: knowing whether the message you sent got there.** Full model in `docs/PROTOCOL.md` §7.2.1; from the user's point of view:
    - **Every message you send reads `you -> message`**, and only yours: text, a voice message and a file transfer all carry it, while a message from somebody else reads `them: message`, since it arrived here by definition. So do the app's own system and presence lines.
    - **The arrow is coloured by how far the message has got.** In a private room it has two states — gray while the message has not reached the other person yet, green once it has.
    - **In a channel it has three**, because one message you send is really one message per member (`docs/PROTOCOL.md` §7.2): gray while nobody has it, orange once some of them do, green once all of them do. A file send in a channel is one row too, over every recipient it went out to, so it has the same three.
    - **A message that reached nobody at all is struck through** — an empty channel, or one where every member was excluded — with the arrow left gray. It is not waiting on anyone, so it must not sit there looking like it is.
    - **Green means their app could actually read it** — their client decrypted the message and said so. It does not mean a human has looked at it. For a file that is the offer opening; for a voice message, the audio decoding.
    - **Under `/otp`, green additionally means it was provably them.** An ordinary acknowledgement is taken on trust; a pad one has to prove it decrypted the message before the arrow moves, so it stays gray until that proof lands rather than turning green on somebody's word.
    - **Gray is not a failure.** A message to somebody whose link is still being punched, or who is briefly unreachable, is held and re-sent by itself; the arrow turns green whenever it finally lands. A send that genuinely failed is already shown in red (`UiState::mark_dm_message_failed`), which is a different thing.
    - **Pressing `i` on a message opens its details** (message log focused): `sent_at`, then every user it was sent to, each with that user's own coloured arrow and status aligned to the right — `UNDELIVERED`, `DELIVERED`, and for a voice message they have heard, a `.txt` file they previewed without saving, or a file they have on disk, `DELIVERED+LISTENED`, `DELIVERED+VIEWED`, or `DELIVERED+SAVED`. That extra state shows only here; the log's arrow never changes for it. `i` or Escape closes it, and it absorbs every other key while open. On a message that tracks no delivery — anything incoming, a presence notice — it says so instead, next to when that message arrived.
    - **It does not survive a restart.** Acknowledgements are matched against messages this run sent; anything still gray when the client stops simply stays that way.

21. **Clearing message history with `/clear` and `/clear-all`.** `/clear` empties the log of whichever channel or private room is open right now — the backing history itself, not just the rendered view — and never touches any other screen's log. `/clear-all` does the same for every channel and every private room at once. Neither survives a restart anyway (message history is in-memory only, `docs/SPEC.md`'s "Connected UI"), so this only ever brings that forward.

22. **Opening a link straight from a message.** A text message's `http://`/`https://` links are rendered blue and underlined in the log, distinguishing them from plain text. `Ctrl+O` opens the first link in the *focused* message (`message_selected`) in the OS default browser — `xdg-open` on Linux, `open` on macOS, `start` on Windows — and pressing it again on the same message cycles to that message's next link, wrapping back to the first; it does nothing on a message with no link.

23. **Direct-punch status and editing (`Ctrl+S`).** Once at least one `direct_punch_to` peer is configured, the header shows `<active>/<total> direct punches, next try in <time> (Control+s)` to the left of `Conn:`/`CPU:` — green once every configured peer is connected, yellow otherwise. Nothing is shown at all when direct punching isn't configured. `Ctrl+S` opens a "Direct Punches" popup listing every configured target: `a` adds one, `Enter`/`e` edits the selected one prefilled, `d` deletes it, `Esc` backs out one level at a time. Each field of the add/edit form is its own titled, bordered box — the same look the connect popup's own fields use — with the terminal's own cursor blinking in the nickname box the instant the form opens (the default first focus) and tracking whichever free-text field (nickname/host/port) Tab moves to next; frequency is a bounded `Left`/`Right` selector over the same values `~/.aloo/settings` accepts, so it has no cursor of its own. Saving persists the whole list back to `~/.aloo/settings` (a merging write, so a concurrently-running daemon's own keys are untouched), reconfigures the scheduler immediately — the new schedule is live the same tick, not on the next restart — and shows a confirmation notice.

24. **Unread OTP mail in the header.** Every received mail is unread from the moment it arrives until its reader is opened; while at least one still is, the header shows a blinking ✉ followed by `<n> unread OTP Mails`, ahead of the direct-punch/Conn/CPU indicators. Nothing is shown once every received mail has been read. The flag is persisted (`~/.aloo/otp_mail`'s index), so the count survives a restart; a mail stored before this concept existed loads as already read.

25. **Channel ownership and moderation.** Full model in `docs/PROTOCOL.md` §6.7; see "Channel ownership and moderation" under Channels above for `/delete-channel`, `/ban`, `/unban`, `/lock-joins` and `/assign-admin`. Every one of these needs a server - there is nobody to enforce a ban, a lock, or an admin handoff against an uncooperative peer without one - and each is refused with a clear status-line message in `--no-server` mode.

26. **Server superadmins.** Full model in `docs/PROTOCOL.md` §5.5; see "Server superadmins" under Channels above. Whoever is listed in `server_superadmin` can run, over the wire:
    - **`/deactivate <nickname> <reason>`** - blocks that account's next login (shown to them in red, quoting the reason) and, if they're currently connected, takes over their session immediately with a full-screen red modal - `Your account has been deactivated ("<reason>")` - the only key it answers is Escape, which closes aloo.
    - **`/activate <nickname>`** - reverses a `/deactivate`, or clears a still-pending email activation code - the same underlying "make this account able to log in right now," reached either way.
    - **`/remove-account <nickname>`** - deletes the account outright and removes every channel it administers, notifying that channel's members ("the channel has been removed by the admin").
    - **`/remove-channel <name>`** - removes any public channel regardless of who administers it (`the-hall` excepted, even for a superadmin). There is no equivalent for a private channel: its existence is never advertised outside its own membership, so a superadmin who isn't already in one has no name to act on.
    - **`/users`** - opens a popup listing every registered user and which channels each currently administers ("no channels" for one administering none). Read-only; Escape closes it. Refused for anyone not listed in `server_superadmin`, the same as the four commands above.

27. **Autosaving chat/voice history (`autosave_messages`).** Off by default; set `autosave_messages=on` in `~/.aloo/settings` to have every channel/DM message — text, voice, file-transfer notices, presence lines, everything that appears in the scrollback — appended, as it happens, to a plain-text log under `~/.aloo/exports/<server>/{channels,dms}/<name>.log`, `<server>` being the host and port last connected to (or the literal `DIRECT` for a `--no-server` session). Each line is timestamped in UTC — `[2026-08-26T14:23:01Z] <- alice: hello`, the arrow showing direction. A finished voice message additionally gets a `<utc>_<nickname>.wav` file written beside its `.log`, referenced from the line by filename. Existing logs are only ever appended to, never replaced or truncated, across restarts and separate sessions. Read once at startup like every other setting — turning it on in the file takes effect on the next run, not live.

28. **Exporting specific channels/DMs on demand (`Ctrl+E`).** Independent of `autosave_messages` above — works whether or not continuous autosave is on. Opens a popup listing every joined channel and every open DM as an unchecked box: `Up`/`Down` move the cursor, `Enter` toggles the row under it, and `Tab`/`Left`/`Right` move onto (and between) a Confirm/Cancel row once past the last one — `Cancel` focused by default. `Esc` always backs out with nothing exported, from either the list or the buttons. Confirming with at least one row checked dumps each selected surface's *current* in-memory log to the same `~/.aloo/exports/<server>/...` locations autosaving uses, in the same line format, but every file this export produces — the `.log` and any `.wav` alongside it — is prefixed with one freshly generated short id, so a manual export never collides with the continuous autosave log sitting beside it, or with an earlier export.

29. **Resuming history from the on-disk export log (`resume_from_log`).** Off by default; set `resume_from_log=on` in `~/.aloo/settings` to have a channel/DM's scrollback pull its older history back in from the `.log` file `autosave_messages` (item 27) writes — whether that file was written this session or an earlier one. A chunk loads automatically the moment a channel/DM genuinely becomes the view (selecting it, or landing straight in one just joined), sized to however many rows the message log currently occupies on screen; scrolling `Up`/`PageUp`/`Home` past the top of what's loaded pulls in another chunk the same size, one press at a time, until the file is exhausted. Nothing is invented that isn't actually on disk: a `System`/`Presence` line reads back as a plain system notice (the two are textually identical once written, so the distinction is lost), a `[file] <name>` reference reads back as inert text rather than a re-offered file transfer, and a voice line's audio is never decoded up front — it shows as an unloaded reference (dimmed, `Enter to load`) until actually replayed, at which point its `.wav` is read from disk on the spot and the row becomes an ordinary voice message from then on. A voice line whose `.wav` was never written (the original autosave couldn't save it) says so instead of attempting to play anything.

30. **Changing your own password with `/password <old> <new>`.** Available to any logged-in user, needs a server (there is no meaning for a password without one). Sends `ChangePassword` (`docs/PROTOCOL.md` §5.1), which re-checks `old` against the account exactly like logging in would, rather than trusting that this connection once authenticated with it — a wrong `old` is refused with a status notice and changes nothing; a right one changes the password immediately, confirmed the same way. Both `old` and `new` are exactly one word each, the same limitation every other space-delimited slash-command argument in this app already has.

31. **Clicking with a mouse, where available.** Mouse capture is on for the whole session; a left click on the input bar focuses it, and a left click on a row in the member sidebar (while actually viewing a channel, not a DM) selects that member and focuses the sidebar — the same click-to-focus a chat app is expected to have. A click does nothing while a popup or any other overlay is in front of the view (nothing to click through to), and does nothing while viewing a DM (the sidebar isn't shown there at all). Right clicks, drags and scrolling aren't handled yet. Most terminal emulators still let a held modifier key (commonly Shift) bypass this for native text selection/copy.

## Running in background mode

Run aloo connected, in the background, so the global push-to-talk shortcut
works from wherever you already are.

### What this is for

aloo's walkie-talkie shortcut (`Ctrl+Alt+P` by default) only works while
aloo is running. That is a real gap: the moment you want is usually the
moment you are inside something else — an editor, a browser, a game — and
"open a terminal, run aloo, wait for the connect screen, pick the right
channel, *then* hold the key" is not a walkie-talkie. It is a chat app you
have to visit.

Background mode closes that gap. One `aloo --daemon` at login, and from
then on:

- you are connected, all day, without a terminal open anywhere;
- you are in the channels you actually talk in — **not** `the-hall`, which
  a normal client joins on connect and a daemon never does unless you ask;
- one channel or one person is **focused**, so a held shortcut goes
  straight there without a decision;
- and when you do want to read the log or type, you run `aloo` in any
  terminal and the session you already have appears — the same connection,
  the same links, the same open conversations. `/daemon` hands it back.

Nothing is re-connected in that hand-off, which is the point. Your direct
peer links stay punched, your OTP sessions stay live, your identity stays
pinned.

### Starting one

```sh
aloo --daemon --host=chat.example.com --channels=team --initial-focus=channel:team
```

That prints a pid and returns immediately:

```
aloo: daemon started (pid 20481), logging to /home/you/.aloo/daemon.log
aloo: type 'aloo' in any terminal to attach, /daemon to hand it back
```

The daemon is now in its own session with no controlling terminal, so
**closing the terminal you started it from does not touch it**. It
re-launches itself detached rather than forking, which is what keeps it
clean: by the time aloo has started, it already has audio and hotkey
threads, and forking a threaded process gives you a child holding locks no
thread will ever release.

Its stdout and stderr go to `~/.aloo/daemon.log` — a daemon has nowhere
else to report, and the things worth reporting (server unreachable,
nickname taken, no keybundle) all happen before anyone could attach to
watch.

#### Foreground

```sh
aloo --daemon --foreground
```

Identical, except it does not re-launch itself and does not return. This is
what a service manager wants, since it does its own supervising — see
[Running it at login](#running-it-at-login).

#### Checking on it, and stopping it

```sh
aloo --daemon-status      # aloo: aloo daemon running (pid 20481)
aloo --daemon-stop        # ends the session and exits
```

Only one daemon runs at a time. A second `aloo --daemon` refuses and tells
you the pid of the one already there. "Already there" is decided by
actually connecting to its socket, not by a file existing — a daemon killed
with `SIGKILL` leaves its socket file behind, and that debris is cleaned up
rather than mistaken for a live instance.

### Taking the session over, and giving it back

```sh
aloo            # a daemon is running -> attach to it
```

With a daemon running, a bare `aloo` attaches instead of opening the
connect screen. You get the full UI — sidebar, channels, message log,
compose bar — driving the session that was already there.

To hand it back, type `/daemon` in the compose bar. The session keeps
running; your terminal is released.

`Ctrl+C` does the same thing. It is answered by the attaching program
itself and never reaches the daemon, so **quitting your viewer can never
kill the session behind it**. Ending the daemon is `aloo --daemon-stop`,
deliberately a different command.

One terminal at a time. A second `aloo` while someone is attached is told
so and exits rather than fighting over the cursor.

If you want a separate, independent session while a daemon is running:

```sh
aloo --no-attach
```

Be aware the server will refuse it if it is using the same nickname —
nicknames are unique among connected clients.

### Where your voice goes: `--initial-focus`

This is the setting that makes the shortcut worth having. `--initial-focus` decides
what a held `Ctrl+Alt+P` addresses, with no window to look at and no
decision to make.

#### A channel

```sh
aloo --daemon --channels=team --initial-focus=channel:team
```

Hold the shortcut, talk, release — it goes to `team`. Everyone in that
channel hears it live, as they would from any client.

#### A person

```sh
aloo --daemon --channels=team --initial-focus=alice
```

The daemon watches for `alice`. The moment she appears it opens the DM with
her and puts the focus there, so the shortcut talks to *her*, not to the
channel. Until she appears, there is nothing to talk to and the shortcut
does nothing.

A bare value is a nickname. `dm:alice` is the explicit spelling of the same
thing, and `channel:alice` is how you would name a channel called `alice`.

> **A DM focus needs a channel to watch from.** Presence in aloo is
> channel-scoped: the server only tells you a person exists if you share a
> joined channel with them, and there is no "is alice online?" query in the
> protocol. `--initial-focus=alice` with no `--channels` therefore has nowhere to
> see her from, so the daemon joins `the-hall` as a discovery channel and
> says so in its log. Naming a channel you actually share with her is
> better in every way — it is quieter, and it is where she will be.

### Channels

`--channels` takes them comma separated, and a daemon joins **exactly**
what you name — never `the-hall` unless you name it. That is the difference from a normal
client, which joins `the-hall` on connect.

```sh
aloo --daemon --channels=team,ops --initial-focus=channel:ops
```

With a password:

```sh
aloo --daemon --channels=ops:hunter2
```

Channels are separated by commas, and a password follows its channel after
a **colon**. The colon is what makes this unambiguous: it is legal in
neither a channel name nor a channel password, whereas a comma is legal in
a password. The name/password split is on the **first** colon.

One consequence worth knowing: `--channels=ops:a,b` is *not* the channel
`ops` with the password `a,b` — the comma split runs first, so it reads as
`ops` with password `a`, plus a channel called `b`. A password containing a
comma can only be set in `~/.aloo/settings`, where each channel has a line
to itself and nothing splits on commas. An empty password
(`--channels=ops:`) means "no password", not "the empty password".

A focused channel is joined automatically even if you forgot to list it:
`--initial-focus=channel:ops` implies `--channels=ops`.

### Nicknames and identity

```sh
aloo --daemon --nick=david
```

Defaults to `$USER`. The nickname must be free — the server rejects a
duplicate, and for a daemon that is a startup failure (see
[When it fails](#when-it-fails-to-start)).

Your identity is always `pq_hybrid`, aloo's strongest. A daemon connects
with nobody watching, and that is the only key type needing no typed secret
and no prompt: if the keybundle does not exist yet, it is generated on
first connect. Point at a specific one with:

```sh
aloo --daemon --my-key=/home/you/.aloo/mykeys      # mykeys + mykeys.pub
```

That is the pair `aloo --keygen-pq-hybrid /home/you/.aloo/mykeys` writes, so
a keybundle you generated yourself can be pointed at directly. A
`mykeys.priv` left by an earlier auto-generated bundle is still accepted,
and preferred when both are present; a fresh one is written as
`mykeys` + `mykeys.pub`.

Otherwise it reuses whatever you last connected with (`~/.aloo/.cache`).

### Logging in

```sh
aloo --daemon --nick-pwd=SECRET   # the nickname's password on this server
```

`--nick-pwd` is the one credential a headless start needs; with a
server named but no password anywhere (flag or `daemon_server_password`
in settings), the daemon refuses to start rather than dialling in with an
empty one - a serverless start (`--no-server`) is the one exception, since
it has nothing to log in to. It's remembered, so the next bare
`aloo --daemon` reconnects the same way. Dialling over TLS is not a flag
at all - set `connect_using_ssl=on` in `~/.aloo/settings` (the same one
setting a normal connect reads too, see "Not connected UI" above); get it
wrong for what the server actually wants and the daemon refuses to start
with a specific reason rather than a bare connection failure.

### Focusing a person, with OTP

```sh
aloo --daemon --channels=team --initial-focus=alice --otp
```

`--otp` means *have* a one-time-pad session with alice — the strongest
thing aloo offers, layered over `pq_hybrid`. It does one of two things,
depending on what already exists:

- **No session yet** → an invitation is sent the moment she appears. She
  gets the usual Accept/Reject popup; the session starts only if she
  accepts, exactly as `/otp` behaves.
- **A session already active** → nothing is sent. It is simply continued.

The second case matters more than it looks. An OTP session survives both
sides disconnecting and even restarting the app — only `/endotp` ends one
(`docs/PROTOCOL.md` §16.6) — and aloo resumes it automatically the moment
the peer reappears. Inviting on top of that would put an Accept/Reject
popup in front of someone already in the session and spend a fresh pad
handshake to arrive back where they started.

At most one invitation per daemon run, so a peer on a flapping connection
does not become a queue of popups.

`--otp` needs a person. `--initial-focus=channel:... --otp` is refused: OTP is
provisioned pairwise, per contact, and has no channel-wide form.

None of this needs a server. The whole handshake rides the direct link,
so the same flags work under `--no-server` against a `direct_punch_to`
peer - see "Talking to one person, with no server" below.

### Sounds and notifications

A daemon has no screen, so it says things out loud.

| When | Sound | Notification |
|---|---|---|
| Someone arrives where the focus currently is, with nobody watching | `joined.wav` | "alice is here" |
| They leave the focused channel, or disconnect | — | "alice left / disconnected" |
| An OTP session fails to start | `bell.wav` | the reason |
| The daemon fails to start | `bell.wav` | the reason |

The join sound is deliberately the narrowest of these. It exists for one
situation — nobody is looking at aloo, and something changed where a held
shortcut would land — so it plays only when all of this is true:

- **it is a daemon**, since a foreground client already shows the arrival
  in its log;
- **no terminal is attached**, since a viewer already has it on screen;
- **the arrival is where the focus is *now*** — not where `--initial-focus` put it
  at startup. The two agree until someone attaches and moves; after that
  only the live one is worth announcing, because that is where the next
  held shortcut actually goes.

On a **channel** focus, every arrival in that channel is its own event and
gets its own sound. On a **person** focus, them coming online is announced
once — however many shared channels the arrival reaches you through, since
`UserJoined` is sent per channel and "alice is online" is one event — and
again the next time they come online after having gone offline.

The notification keeps the wider rule on purpose: it is silent, it costs
nothing to see later, and it also covers leaving and disconnecting, which
the sound deliberately does not.

Notifications use whatever your desktop already provides — `notify-send`
on Linux, Notification Center on macOS, a toast on Windows. Two honest
caveats: **an app cannot choose where a notification appears** (that
belongs to your notification daemon), and the 8-second duration is a
*request* — GNOME, for one, ignores timeout hints. If there is no
windowing system at all (a text console, or over ssh), notifications are
skipped rather than failing once per event.

Sounds can be turned off in `~/.aloo/settings`; see below.

### When it fails to start

A daemon that quietly failed at login is indistinguishable from one that
worked — until you hold the shortcut and nothing happens. So a failed start
plays a tone, raises a notification, writes the reason to
`~/.aloo/daemon.log`, and exits non-zero. It is fatal when:

- the server is unreachable, or the host does not resolve;
- authentication is rejected (wrong `--nick-pwd`, or none given);
- the nickname is already taken;
- the keybundle cannot be read;
- **every** configured channel failed to join;
- a daemon is already running.

Some things are warnings instead — the session is still worth having:

- one of several channels failed to join;
- the global shortcut could not be registered (you can still attach and
  hold `Space`);
- the focused person is not online yet — that is the normal case;
- notifications are unavailable.

> **Linux: the global shortcut needs X11.** aloo's hotkey backend has no
> Wayland support, and no application-level workaround exists — a Wayland
> compositor deliberately does not let one app grab keys globally. Under
> Wayland the daemon connects, focuses and can be attached to normally, but
> the shortcut will not fire. It says so at startup rather than failing
> silently.

### Running it at login

Use a **user** service, not a system one. A system service has no `$HOME`,
no display and no audio — it could not do the hotkey, the sounds or the
notifications.

A ready-to-use unit ships at the repository root as `aloo.service`:

```sh
cp aloo.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now aloo
```

It reads:

```ini
[Unit]
Description=aloo daemon
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/aloo --daemon --foreground
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now aloo
systemctl --user status aloo
journalctl --user -u aloo -f
```

Note `--foreground`: systemd supervises the process itself, so the daemon
must not re-launch and exit under it.

The unit deliberately carries no flags beyond that. A bare `aloo --daemon`
reuses the last configuration you started one with (see
[Settings](#settings)), so the host, channels, focus and credentials live
in `~/.aloo/settings` rather than being duplicated in the unit file. Set it
up once by hand with the flags you want, then let the unit start it.

On X11 the shortcut needs `DISPLAY` and `XAUTHORITY` in the user manager's
environment. Most desktop sessions do this for you; if yours does not:

```sh
systemctl --user import-environment DISPLAY XAUTHORITY
```

**macOS** has no systemd. Use a `launchd` agent in
`~/Library/LaunchAgents/`, running `aloo --daemon --foreground` with
`RunAtLoad`. **Windows**: a shortcut to `aloo --daemon` in the Startup
folder, or a Scheduled Task at logon.

### Settings

Every flag has a `daemon_`-prefixed key in `~/.aloo/settings`, and a daemon
writes its resolved configuration back on every start. That is what lets
the service unit above be flag-free.

```ini
daemon_host=chat.example.com
daemon_port=7878
daemon_nickname=david
daemon_server_auth_type=password
daemon_server_password=hunter2
daemon_my_key_pub=/home/david/.aloo/ab12.pub
daemon_my_key_priv=/home/david/.aloo/ab12.priv
daemon_channel=team
daemon_channel=ops:hunter2
daemon_initial_focus=alice
daemon_otp=true
```

`daemon_channel` is one line per channel rather than a single
comma-separated value, using the same `name:password` form as
`--channels`. That is deliberate: with a line to itself, nothing is
splitting on commas, so this is the one place a password containing a
comma can be set.

Precedence, for any given setting: **a flag given this run wins; anything
omitted falls back to `~/.aloo/settings` — its own `daemon_` key first,
then the `connect_` keys the connect screen last recorded; anything still
missing comes from the keybundle in `~/.aloo/.cache`; and only then a
built-in default.** The same rule `aloo --server` already uses for its own
flags.

The `connect_` step is what makes a *first* `aloo --daemon` need no flags
at all on a machine that has only ever been used interactively: the host,
port and nickname you last connected with by hand are already recorded
there (see "Not connected UI"), so the daemon comes back on the same server
as the same person rather than as `$USER` on a host it has to be told
about again. Nothing about the host, port or nickname is *mandatory* on the
command line once any of those three sources has it.

### Files it owns

| Path | |
|---|---|
| `~/.aloo/daemon.sock` | Unix: the socket a terminal attaches through |
| `~/.aloo/daemon.pid` | the running daemon's process id |
| `~/.aloo/daemon.log` | its stdout and stderr |

All three are removed when it exits. Windows has no Unix domain sockets,
so there `daemon.sock` is never created at all — the attach channel is a
named pipe instead (`\\.\pipe\aloo-daemon-<username>`), which needs no
file of its own to remove.

> **The transport is the access control.** Anyone who can reach the
> attach channel controls the session completely: they can read every
> message in it and send voice, text and files as you. On Unix that
> channel is `~/.aloo/daemon.sock`, created mode `0600`, and aloo refuses
> to speak to one that is not owned by the user running it. On Windows
> it's the named pipe above, created with a DACL granting access to its
> own creator alone (nobody else can even open it), and aloo likewise
> refuses to speak to one whose owning process names a different user's
> SID. This is a larger capability than reading `~/.aloo/settings`, which
> only exposes stored secrets — see `docs/SECURITY.md`.

### Full example

Connected at login, in two work channels, voice going to `ops`, with a
one-time-pad session kept up with alice:

```sh
aloo --daemon \
  --host=chat.example.com \
  --nick-pwd=SECRET \
  --nick=david \
  --channels=team,ops:hunter2 \
  --initial-focus=alice \
  --otp
```

Then, from anywhere: hold `Ctrl+Alt+P`, talk, release — alice hears it,
pad-encrypted, the moment you speak. Run `aloo` to read the log, `/daemon`
to step back out.

### See also

- - [`PROTOCOL.md`](PROTOCOL.md) §16 — the one-time-pad layer, and §16.6 for
  what starts and ends a session.
- `docs/SECURITY.md` — what aloo protects and what it does not.

## Talking to one person, with no server

The shortest useful shape of Functionality #17/#18: two people who want to
reach each other and nothing else. No channel, no server, no directory -
just a DM that opens itself, optionally under the one-time-pad layer, and
optionally with nobody sitting at either terminal.

### What has to be true first

**Each of you must have something pinned for the other.** A pinned key is
the only thing that will make either client believe a nickname later
(§7.1.5 step 7). There are two ways to get one, and either is enough:

- **You met through a server once.** That is where each of you got the
  other's `pq_hybrid` key. A one-time cost: after it, the server is never
  needed again for the two of you.
- **Or you exchanged a one-time pad out of band and installed it
  yourselves** (`/contacts`, `o`), with no server ever involved. Then the
  pad is what proves who is who: a link opening to someone you hold a pad
  for registers them, and a pad-wrapped message that `otp` genuinely
  decrypts registers the sender. Every message between you rides the pad
  from the first one - there is no `pq_hybrid` envelope underneath, and
  none is needed.

**Both of you must name the other.** A `direct_punch_to` line is half of a
handshake, not a permission: a probe is answered only for a nickname the
*receiver* also lists, so a one-sided entry reaches nobody in either
direction. Both sides also need the same frequency, since what makes two
clients probe at the same instant is that both schedules restart at every
o'clock.

**At least one of you must be reachable.** There is no STUN and no relay,
so the address in the other's settings has to actually arrive - a
forwarded UDP port, or a host with a public address. Both behind NAT with
nothing forwarded will never open.

### The DM itself

Alice's `~/.aloo/settings`:

```
direct_punch=on
direct_punch_to=bob,bobs-host.example,every_1m
```

Bob's:

```
direct_punch=on
direct_punch_to=alice,alices-host.example,every_1m
```

That is the whole configuration. **No channel is involved** - `direct_punch_channel`
is for channels and does nothing here. A peer who shares no channel with
you is still registered as someone you can DM, which is exactly what this
buys.

At the next slot both punch, the link opens, each sends the other a sealed
note naming its channels (an empty list here), and opening that note is
what proves who sent it. From that moment the other person is an ordinary
peer: pick them in the sidebar and press Enter, or `--initial-focus` them, and the
DM works exactly as it does through a server - text, voice, push-to-talk,
files, calls.

### Adding the one-time-pad layer

`/otp` is unchanged by any of this, because it never involved the server in
the first place: it is a layer *over* `pq_hybrid` (`docs/PROTOCOL.md` §16),
and its whole handshake rides the same direct link everything else does.

- **It does not replace the pinned key, it sits on top of it.** An active
  OTP session still needs the `pq_hybrid` pin underneath, so the "met once
  through a server" requirement is not waived by having pad material.
- **Starting one always takes an explicit accept from the other side.**
  One of you runs `/otp` in the open DM; the other gets the invite popup
  and accepts. There is no auto-accept, deliberately - mutual consent is
  the point of §16.1 - so a pair of unattended daemons will punch a link,
  register each other, and then wait forever on an unanswered invite.
- **Once accepted it persists.** Only `/endotp` ends a session: neither
  disconnecting, nor restarting, nor the link dropping does. A peer who
  comes back with a session already provisioned simply has it continued.
- **`/mail` does not work here** - the server *is* the mailbox
  (Functionality #13). Live `/otp` is unaffected.

So the pad layer costs exactly one human accept, once, ever.

### How a pad-wrapped message authenticates itself

Every message that arrives under the pad layer is checked before a single
key byte is spent, and the statement it has to satisfy is this: the message
must have been **produced by the holder of the mirror key at the expected
offset, and next in sequence**. Anything that fails is refused outright and
never reaches the conversation.

That statement is not something aloo computes. It is what the `otp` command
itself decides, from an encrypted metadata block it puts at the front of
every message (`otp-toolkit`'s "Origin and order verification"). The block
carries three things, and each answers one part of the sentence:

| Field | What it is | What it proves |
|---|---|---|
| `source_id` | 16 bytes taken from the key itself, at this message's offset | **the holder of the mirror key** - only the correspondent whose key is the mirror of this one holds those exact bytes at that exact position |
| `offset` | the absolute key position this message starts at | **at the expected offset** - it must equal where this contact's own key has actually reached |
| `seq` | this message's sequence number in its direction | **next in sequence** - it must be exactly the next one expected, so a replayed, reordered or duplicated message is refused |

Because the source_id is drawn from the pad, it cannot be forged by anyone
who does not already hold the pad - and it is destroyed along with the rest
of that message's key range once spent, so it cannot be replayed either.

The check runs *before* anything is staged, delivered or truncated, so a
message that fails leaves the key untouched. `otp` reports the outcome
through its exit code, and that verdict is the whole of what aloo needs: a
successful decrypt **is** the proof of origin and ordering, so there is no
separate signature to verify and no identity to look up. A failing verdict
means the message came from the wrong source or was encrypted against the
wrong pad; aloo shows that plainly and processes nothing
(`client::otp::finish_opening_otp_envelope`'s rejection notice).

This holds in both directions of use:

- **Under `pq_hybrid`** (the ordinary case) the verdict is checked in
  addition to the envelope's own signature - a message that decrypts but
  fails verification is discarded rather than opened.
- **Without `pq_hybrid`**, where there is no inner envelope to sign
  anything, the verdict is the *only* authentication - and it is
  sufficient, because holding the mirror pad is a stronger statement about
  who is speaking than holding an identity key is.

It only takes *one* side to be missing `pq_hybrid` for the second case to
apply, since an envelope needs both a sender who can sign it and a
recipient who can open it. So a pair where only one has a `pq_hybrid`
identity talks over the pad directly, exactly as a pair where neither does.
Both sides work this out independently, from the keys themselves, and
always reach the same answer.

Two things this does not change: the pad's contact is still named from
*keys* rather than nicknames, and every message is still acknowledged the
same way (below). Offline mail is the one exception - it is stored and
acknowledged by a server that holds no pad, so its sender binding is a
signature and it needs `pq_hybrid`; a pure-pad pair is told so rather than
falling back to something weaker.

### Proving an acknowledgement, without spending pad to do it

The verdict says a message came from the right correspondent. It does not
say the message *arrived* - the two directions are independent, and nothing
about receiving something proves the peer received what you sent. Since a
pad range is destroyed the moment it is used, aloo sends exactly one
message at a time to a contact and waits for that message to be
acknowledged before spending any more key.

So the acknowledgement itself has to be trustworthy, and naming a sequence
number is not enough - anyone who watched the packet go past can quote one.
Instead every message carries a fresh 16-byte nonce buried under the pad,
and the acknowledgement returns `sha256` of it:

| | |
|---|---|
| What goes out | the message, with a random nonce in front of it, all under the pad |
| What comes back | `sha256(nonce)` - no pad spent, no key consumed |
| Why it can't be faked | the nonce is only readable by decrypting, which needs the mirror pad |
| Why the nonce isn't echoed raw | that would expose 16 bytes of known plaintext against known ciphertext, which is 16 bytes of recovered key |

A fresh nonce per message is what makes this repeatable: the proof is bound
to *that* message, so an old acknowledgement is worthless against the next
one. And a hash costs the receiver nothing, which matters more than it
sounds - an acknowledgement that spent pad would itself be a message
needing acknowledgement, and the recursion would never bottom out.

Two cases carry the user's bytes verbatim - a file's content, and a voice
message - so there is no room to insert a nonce without corrupting what
lands on disk. Those use the plaintext's own `sha256` instead, which proves
the same thing: only someone who decrypted the content can name it.

The practical effect is a hard bound on impersonation. A pad is filed
against the correspondent's *keys*, never their nickname, so someone who
takes a familiar name gets nowhere. Someone who takes an identity key gets
one message - and then the gate closes, because they cannot produce the
proof. Even that one message is not lost: nothing overwrites its retained
copy while the gate is held, so it is still deliverable to the real
contact when they return.

One consequence is worth stating: because verification is a property of
decryption, authenticating costs pad. A message sent purely to prove
identity would spend key like any other, which is why nothing here adds an
authentication handshake - the first real message's own verdict does the
job. And once a ciphertext has left the machine its key range is spent for
good, so a lost message is re-transmitted byte-identically
(`otp --recover-last --sent`) and never re-encrypted.

### Doing it with no terminal (daemon)

Both sides can then run headless:

```sh
aloo --daemon --no-server --initial-focus bob --otp
```

- **`--initial-focus bob`** points the global push-to-talk shortcut at that DM, so
  holding `Ctrl+Alt+P` from any other app talks to them. It is a *starting*
  position: once placed, wherever someone later moves the focus from an
  attached terminal is respected.
- **`--otp`** makes the daemon propose an OTP session the moment that peer
  appears, so nobody has to type `/otp` - and continues an already-active
  one silently instead. It behaves identically with and without a server;
  "Focusing a person, with OTP" above has the full rule.
- **The first accept still needs a person.** Attach once on the receiving
  side (`aloo`), accept, detach (`/daemon`). Everything after that is
  unattended, including across restarts of either side.
- **Nothing waits on a channel.** A peer reached this way arrives in no
  channel at all, and the focus, the join sound, the desktop notification
  and the OTP proposal all fire for them regardless - a DM focus is about
  the person, not about where they turned up.

### What it looks like while nobody is there

Until the other side punches in, the DM says *"Waiting for other users to
connect directly to you"* rather than sitting blank. With an hourly
frequency that wait can genuinely be an hour - the schedule only fires on
the hour - so a client that looks idle shortly after starting is usually
correct rather than broken.

## Where diagnostics go

Anything aloo has to say *about itself* — a STUN reply it cannot use, an
audio device that went away, a store it could not save, a settings line it
had to skip — is a diagnostic, not a message, and there is exactly one
place it goes:

- **While the terminal UI holds the screen, nothing is written to it.**
  Ratatui owns every cell from `terminal::setup` to `terminal::restore`;
  bytes written straight out in between land wherever the cursor happens to
  be and tear a hole through the frame — a warning about an unusable STUN
  reply printed across the header and the selectors is the shape that
  takes. Diagnostics raised in that window are collected instead — the
  most recent `log::RING_CAPACITY` of them — and written out,
  `aloo:`-prefixed, the moment the terminal is handed back. A warning worth raising is still worth reading; it just has
  to wait for a screen that is not being repainted several times a second.
- **Everywhere else it is one line on stderr, immediately.** A `--server`,
  `--daemon` or `--foreground` start, and every one-shot subcommand
  (`--keygen-pq-hybrid`, `--export-identity-card`, `--daemon-status`, …),
  own no screen, so a diagnostic is simply printed. A backgrounded daemon's
  stdout and stderr both go to `~/.aloo/daemon.log`.

This is a property of the whole codebase, not of any one call site: nothing
in `src/` writes a diagnostic with `println!`/`eprintln!` of its own. What
remains on stdout is program *output* rather than diagnostics — the paths
`--keygen-pq-hybrid` wrote, the address `--server` is listening on, the
answer `--daemon-status` was asked for.

Messages meant for the user rather than about the app are a different
thing entirely and never come through here: those are the top-right status
notice, the yellow presence lines, and the app's own `System` rows in a
conversation.

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
| Connection lifecycle (§4), auth (§5), TLS (§1.4) | `server/mod.rs` `handle_connection`, `ServerOptions`; `server/users_registry.rs` `UsersRegistry`; `server/ssl.rs`; `client/connect.rs` `connect_and_handshake`, `open_control_channel` |
| Liveness, `Heartbeat` (§4.1) | `proto.rs` `HEARTBEAT_INTERVAL`, `HEARTBEAT_TIMEOUT`, `ClientMessage::Heartbeat`; `server/mod.rs` `client_loop`; `client/session.rs` `run_connected_session` |
| Reconnecting (§4.2) | `client/reconnect.rs` `ServerSink`, `ServerEvent`, `ServerLinkState`, `ReconnectPlan`, `spawn_supervisor`, `delay_after`, `RECONNECT_FIRST_DELAY`, `RECONNECT_MAX_DELAY`, `SERVER_DOWN_AFTER_ATTEMPTS`; `client/connect.rs` `connect_with_reconnect`, `handshake_as`; `client/session.rs` `handle_server_event`, `on_server_reconnected`, `forget_peer` |
| Registration, nicknames (§5.4) | `server/mod.rs` `Registry::try_register` |
| Login, activation, self-registration (§5.1-§5.3) | `server/users_registry.rs` `UsersRegistry`, `derive_user_key`, `AuthCheck`, `ActivationOutcome`, `generate_activation_code`, `send_activation_email`, `UsersRegistry::reissue_activation`; `server/mod.rs` `reissue_and_resend_activation`; `client/ip_ban.rs` `LOGIN_FAILURE_STRIKES`, `REGISTRATION_ABUSE_STRIKES`; `client/tui/ui_connect_popup.rs` `ActivationPopupState`; `client/connect.rs` `run_client_inner`; `main.rs` `run_register_user`, `run_change_password` |
| Changing your own password, live (§5.1) | `server/users_registry.rs` `UsersRegistry::change_password`; `server/mod.rs` `client_loop`; `client/tui/ui.rs` `UiState::try_password_command`, `UiAction::ChangePassword`; `client/session.rs` `handle_ui_action`, `handle_server_message` |
| Channels (§6), password bans (§6.6) | `server/channels_registry.rs` `ChannelsRegistry::{join, leave, remove_from_all, list, channel_password_attempts}`; `server/mod.rs` `Registry::{join_channel, leave_channel, unregister, channel_list}`; `validation.rs` |
| Channel ownership and moderation, inactivity (§6.7, §6.8) | `server/channels_registry.rs` `ChannelRecord`, `ChannelsRegistry::{require_caller_is_admin, delete_channel, ban, unban, set_join_lock, assign_admin, sweep_inactive, channels_administered_by, force_delete_channel}`; `server/mod.rs` `Registry::{delete_channel, ban_from_channel, unban_from_channel, set_channel_join_lock, assign_channel_admin, sweep_inactive_channels}`, `channel_sweep_loop`; `client/tui/ui.rs` `ChannelCommandConfirmAction`; `client/tui/channel_lock_popup.rs` `ChannelLockPopupState` |
| Superadmin account status (§5.5) | `server/users_registry.rs` `UsersRegistry::{deactivate, deactivation_reason, admin_force_activate}`, `AuthCheck::Deactivated`; `server/mod.rs` `require_superadmin`; `client/tui/ui.rs` `UiState::account_deactivated`; `client/connect.rs` `AccountDeactivatedError` |
| Superadmin `/users` popup (§5.5) | `server/mod.rs` `client_loop`'s `RequestUsersList` arm; `server/channels_registry.rs` `ChannelsRegistry::channels_administered_by`; `client/tui/ui.rs` `UiState::try_superadmin_command`; `client/tui/contacts.rs` `open_users_admin`, `set_users_admin`, `render_users_admin_popup` |
| Direct link, candidates, punching (§7.1) | `client/p2p.rs` `PeerLinkManager`; `p2p_proto.rs` `PunchDatagram`, `RendezvousMessage`, `SAFE_DATAGRAM_BYTES` |
| Serverless direct punch (§7.1.5) | `settings.rs` `DirectPunchTarget`, `PunchFrequency`, `DEFAULT_DIRECT_PUNCH_PORT`, `PUNCH_FREQUENCIES`; `client/p2p.rs` `configure_direct_punch`, `direct_tick`, `on_direct_ping`, `on_direct_pong`, `direct_peer_id`, `is_direct_peer_id`, `utc_second_of_hour`, `DIRECT_PUNCH_WINDOW`, `DIRECT_MAX_RECONNECTS`; `p2p_proto.rs` `MAX_DIRECT_PUNCH_NICK_LEN` |
| `ChannelPresence`, becoming an addressable peer (§7.1.5) | `proto.rs` `Content::ChannelPresence`; `p2p_proto.rs` `P2pPayload::ChannelPresence`; `client/session.rs` `direct_peer_identity`, `reconcile_direct_membership`, `on_channel_presence`, `send_channel_presence`, `broadcast_channel_presence`; `client/tui/channel.rs` `channels_containing_member`, `is_member_of_channel` |
| Reliable layer (§7.1.1) | `client/p2p_reliable.rs` `ArqSender`, `ArqReceiver` |
| `P2pPayload` variants (§7.2/§7.3/§7.6/§7.7) | `p2p_proto.rs` `P2pPayload` |
| RSA-OAEP chunking, for the server auth challenge only (§8.1) | `crypto/mod.rs` `encrypt_chunked`, `decrypt_chunked`, `max_chunk_len` |
| RSA-PSS signing (§8.2) | `crypto/mod.rs` `sign`, `verify` |
| Rotating-key freshness/queueing (§11) | `client/rekey.rs` `RemoteKeys`, `QueuedOutbound` |
| Identity pinning (§12) | `client/idstore.rs` `IdStore`, `Trust`, `KeyCheck`; `client/session.rs` `check_identity`, `finalize_identity_pin` |
| Safety phrases (§12.6) | `crypto/safety.rs` `phrase`, `WORDS` |
| Continuity certificates (§12.6) | `crypto/pq.rs` `ContinuitySig`, `sign_continuity`, `verify_continuity`; `main.rs` `run_rekey_pq_hybrid` |
| Identity cards (§12.6) | `crypto/pq.rs` `IdentityCard`, `make_identity_card`, `open_identity_card`; `main.rs` `run_export_identity_card`; `client/contacts.rs` `export_own_identity_card_to`, `handle_export_own_identity_card` |
| Key bundles (§13.2) | `crypto/pq.rs` `PqPublicBundle`, `PqPrivateBundle`, `PqEncapKeys`, `PqDecapKeys`, `generate_bundle` |
| `SendBinding`, `SendSetup`, sealed sends (§13.3) | `crypto/pq.rs` `SendBinding`, `SendSetup`, `HybridSend`, `seal_setup`, `seal_send`, `seal_chunk` |
| Opening a send (§13.4) | `crypto/pq.rs` `open_setup`, `open_send`, `open_chunk`; `client/session.rs` `decrypt_own_envelope` |
| Replay refusal (§13.4) | `client/replay.rs` `ReplayGuard` |
| OTP framing, and who can be sealed to (§13.6/§16.2) | `client/otp.rs` `OtpFraming`, `framing_for` |
| Encryption-key rotation (§13.10) | `client/pq_rekey.rs` `PqOwnKeys`, `PqPeerKeys`, `PQ_KEY_RETENTION`; `crypto/pq.rs` `PqRotation`, `sign_rotation`, `verify_rotation` |
| Fingerprints (§12.6/§13.3) | `crypto/pq.rs` `bundle_fingerprint`, `fingerprint_of_encoded` |
| Wire-contract constants pinned by vectors | `crypto/pq.rs` `chunk_nonce`, `hkdf_combine`, `send_commitment`; `control.rs` `derive` — see `docs/SECURITY.md`, "Test vectors" |
| One-time-pad layer (§16), `contact_name_for` | `crypto/otp.rs` `contact_name_for`, `OtpKeySetupPayload`, `OtpSessionRequestPayload`, `OtpKeySetupAckPayload`, `OtpEndSessionPayload` |
| `otp` command subprocess wrapper (§16) | `client/otp_cli.rs` `OtpCliConfig`, `encrypt`, `decrypt`, `status`, `has_contact`, `new_key_pair`, `add_contact`, `binary_available` |
| Per-contact OTP state, ack gate (§16.2) | `client/otp_store.rs` `OtpStore`, `OtpContactState`; `client/otp.rs` `OtpOutQueue`, `send_or_queue`, `on_delivery_ack` |
| Turning the layer on, mutual consent (§16.1) | `client/otp.rs` `handle_otp_command`, `detect_or_adopt_existing`, `initiate_provisioning`, `confirm_generate`, `cancel_generate`, `apply_incoming_setup`, `accept_invite`, `reject_invite`, `on_key_setup_ack`, `commit_pending_setup`, `discard_pending_setup`, `resend_pending_setups` |
| Chunked key-setup transfer (§16.1) | `crypto/otp.rs` `OtpKeySetupChunk`, `OtpKeySetupReassembly`; `client/otp.rs` `send_key_setup_chunked`, `on_key_setup`, `OTP_SETUP_CHUNK_BYTES`; `client/session.rs` `SessionState.otp_incoming_setup` |
| OTP session popups and status notice | `client/tui/ui.rs` `PendingOtpGenerate`, `PendingOtpInvite`, `UiAction::RequestOtpSession`/`ConfirmOtpGenerate`/`CancelOtpGenerate`/`AcceptOtpInvite`/`RejectOtpInvite` |
| `OtpEnvelope`/`OtpFileOffer`/`OtpFileContentSeq`/`OtpVoiceOffer`/`OtpDeliveryAck` (§16) | `p2p_proto.rs` `P2pPayload` |
| File content under the pad, two independent pad spends per file - offer and content (§16.2) | `client/otp_cli.rs` `encrypt_file`, `decrypt_file`, `encrypt_file_retrying`, `decrypt_file_retrying`, `FileCliOutcome`; `client/otp.rs` `send_file_offer`, `on_file_offer`, `start_outgoing_file_content`, `finish_incoming_file`, `temp_content_path`, `secure_remove_file`; `client/file_transfer.rs` `OwnFileTarget.otp`, `OtpIncomingFileReceive`, `OtpIncomingKind`; `client/session.rs` `SessionState.otp_send_temp_files`/`otp_incoming_file_receives`, `accept_file_offer`, `handle_file_event`, `handle_p2p_event`'s `FileAccepted`/`FileRejected`/`OtpFileContentSeq` arms |
| Voice content under the pad, recorded fully then sent once (§16.2) | `proto.rs` `Content::VoiceOffer`; `client/file_transfer.rs` `VoiceOfferPayload`; `client/otp.rs` `send_voice_offer`, `on_voice_offer`; `client/voice_stream.rs` `OwnStreamTarget::DirectOtp`, `spawn_record_accumulate_worker`; `client/direct_message.rs` `handle_voice_record_start`'s OTP branch; `client/otp.rs` `open_otp_envelope`; `client/session.rs` `handle_p2p_event`'s `OtpVoiceOffer` arm |
| A finished OTP voice message autoplaying exactly like a live `pq_hybrid` stream, just decided once for the whole clip instead of per chunk (§16.2, AC-357) | `client/otp.rs` `finish_incoming_file`'s `OtpIncomingKind::Voice` arm (`suppress_playback_from`/`is_viewing_dm`, the direct `session.mixer_tx` push); `client/tui/direct_message.rs` `on_direct_voice_message`, `push_incoming_dm` |
| Session visibility in the DM log (§16.3) | `client/tui/ui.rs` `MessageBody::System`, `otp_active_peers`, `mark_otp_active`, `is_otp_active`, `clear_otp_active`, `render_messages` (the 🔑 prefix), `render_input_bar`, `open_otp_session`; `client/tui/direct_message.rs` `push_otp_system_message`; `client/otp.rs` `notify` |
| Asymmetric-provisioning recovery (§16.1) | `client/otp.rs` `NO_MATCHING_KEY_REASON`, `accept_invite`, `on_key_setup_ack`; `client/otp_cli.rs` `remove_contact`; `client/otp_store.rs` `OtpStore::forget` |
| Failed DM send shown in red (§16.3) | `client/tui/ui.rs` `LogEntry.failed`, `UiAction::SendDirectText.log_index`, `render_messages` (red styling); `client/tui/direct_message.rs` `push_outgoing_dm`, `mark_dm_message_failed`; `client/otp.rs` `PendingOtpSend::Direct.log_index`, `send_now`, `send_or_queue` |
| User-chosen pad size, shown to the peer (§16.1) | `crypto/otp.rs` `OTP_SIZE_MB_MIN`, `OTP_SIZE_MB_MAX`, `otp_size_mb_in_range`; `client/tui/ui.rs` `otp_size_input`, `UiAction::ConfirmOtpGenerate.size_mb`, `PendingOtpInvite.pad_size_mb`, `render_otp_size_popup`; `client/otp.rs` `confirm_generate`, `transfer_estimate` |
| Streamed pad delivery, pacing, and the two-phase commit both sides verify before installing (§16.1) | `client/otp_pad.rs` `PAD_CHUNK_BYTES`, `PAD_INFLIGHT_FRAMES`, `spawn_send_pad_worker`, `spawn_receive_pad_worker`, `PadEvent`, `IncomingPad`, `OutgoingPad`; `client/otp.rs` `start_pad_send`, `on_pad_start`, `on_pad_chunk`, `on_pad_end`, `on_pad_event`, `send_pad_verify`, `on_pad_verify`, `on_pad_commit`, `on_pad_commit_ack`, `route_pad_key_setup`; `crypto/otp.rs` `KeyDigest`, `digest_key_file`; `client/p2p.rs` `outbound_depth`; `client/p2p_reliable.rs` `ArqSender::depth`; `p2p_proto.rs` `P2pPayload::OtpPadStart`/`OtpPadChunk`/`OtpPadEnd`/`OtpPadVerify`/`OtpPadCommit`/`OtpPadCommitAck` |
| Crash-safe staging: nothing half-written can ever be installed (§16.1) | `client/otp_staging.rs` `tmp_root`, `sweep`, `new_dir`, `promote`, `secure_remove_file`, `secure_remove_dir`; `client/otp.rs` `stage_pending_setup`, `apply_incoming_setup` |
| Streamed pad generation and its progress spinner (§16.1) | `client/otp_cli.rs` `new_key_pair`, `new_key_pair_with_progress`; `client/otp.rs` `initiate_provisioning`, `initiate_provisioning_with_progress`, `OtpKeygenEvent`, `on_keygen_event`; `client/tui/ui.rs` `OtpKeygenProgress`, `SPINNER_FRAMES`, `open_otp_keygen`, `set_otp_keygen_progress`, `close_otp_keygen`, `otp_keygen_open`, `tick_otp_keygen_spinner`, `render_otp_keygen_popup`; `client/session.rs` `otp_keygen_tx` |
| Origin/order verification refusing a message before any key is spent | `client/otp_cli.rs` `OtpCliOutcome::Rejected`, `FileCliOutcome::Rejected`; `client/otp.rs` `UnwrapOutcome`, `unwrap_incoming`, `finish_opening_otp_envelope`, `recover_orphaned_decrypt`, `finish_incoming_file`; `client/otp_mail.rs` `on_mail_deliver` |
| Recovering a stuck send via `otp --recover-last`, never re-encoding (§16.4) | `client/otp_cli.rs` `recover_last`, `recover_last_file`, `RecoverDirection`; `client/otp_store.rs` `OtpContactState.pending_content`, `PendingOtpContent`, `OtpStore::pending_sends`; `client/otp.rs` `recover_and_resend`, `recover_and_resend_envelope`, `recover_and_resend_file_offer`, `recover_and_resend_file_content`, `recover_and_resend_voice_offer`, `peer_for_contact_name`; `client/session.rs` `handle_p2p_event`'s `LinkStatusChanged` arm |
| Rejecting a resent ciphertext before it touches the pad a second time (§16.4) | `client/otp_store.rs` `OtpStore::is_next_expected`; `client/otp.rs` `on_message` |
| Live key-metadata header (§16.5) | `client/otp_cli.rs` `ContactDetail`, `show_contact`, `parse_show_contact`; `client/otp.rs` `refresh_otp_key_status`, `poll_key_status`; `client/tui/ui.rs` `UiState.otp_key_status`, `set_otp_key_status`, `otp_key_status_for`; `client/tui/direct_message.rs` `render_private_room`, `render_otp_header`, `push_otp_key_spans`, `OTP_KEY_LOW_THRESHOLD_BYTES`; `client/session.rs` tick loop |
| `/endotp`: local pause, notice, and the mail/multi-session guards (§16.6) | `client/otp.rs` `handle_end_otp_command`, `decide_end_otp`, `EndOtpDecision`, `on_end_session`, `on_end_session_ack`, `send_end_notice_now`, `recover_and_resend_envelope`, `send_sealed_end_session_ack`; `client/otp_store.rs` `OtpStore::mark_end_requested`, `pause_after_peer_ended`, `PendingOtpContent::EndNotice`; `client/tui/ui.rs` `UiAction::EndOtpSession`, `submit_input` (`/endotp`); `proto.rs` `Content::OtpEndSession`/`OtpEndSessionAck` |
| `/endotp`'s durable notice, retried until acknowledged (§16.6) | `client/otp_store.rs` `OtpContactState.pending_end_notice`, `OtpStore::clear_end_notice`, `pending_end_notices`; `client/otp.rs` `resend_pending_end_notices`; `client/session.rs` `handle_p2p_event`'s `LinkStatusChanged` arm |
| A session surviving a reconnect until `/endotp` (§16.6) | `client/otp.rs` `contact_name_if_active`; `client/session.rs` `handle_server_message`'s `UserJoined` arm (re-marks a reconnected, already-provisioned peer active) |
| OTP mail payload, ids, sealed shape (§17.1/§17.2) | `crypto/otp.rs` `OtpMailPayload`, `OtpMailVoice`, `OtpMailFile`, `OtpMailSealed`, `new_mail_id`, `mail_id_is_valid`, `OTP_MAIL_MAX_BYTES` |
| Mail identity signature over a malleable pad (§17.2) | `crypto/pq.rs` `sign_mail`, `verify_mail` |
| Mail wire messages (§17.2/§17.3) | `proto.rs` `ClientMessage::{OtpMailSend, OtpMailFetch, OtpMailAck, OtpMailDeliveredAck}`, `ServerMessage::{OtpMailResult, OtpMailDeliver, OtpMailDelivered}` |
| Server-side mail storage and routing (§17.2/§17.3) | `server/mail.rs` `MailStore`, `StoredMail`, `DeliveredReceipt`, `on_mail_send`, `on_mail_fetch`, `on_mail_ack`, `on_mail_delivered_ack`; `server/mod.rs` `Registry::id_by_name`, `client_loop`'s mail arms |
| Compose view, recipient check, live key budget (§17.1) | `client/tui/otp_mail.rs` `OtpMailState`, `ComposeState`, `MailAttachment`, `MailboxRow`, `ReaderState`; `client/otp_mail.rs` `RecipientCheck`, `check_recipient`, `MAIL_OVERHEAD_ESTIMATE`; `client/tui/ui.rs` `UiAction::{CheckOtpMailRecipient, OpenOtpMailbox, SendOtpMail, ReadOtpMail, DeleteOtpMail, SaveOtpMailAttachment}`, `VoiceTarget::MailAttachment`; `client/voice_stream.rs` `OwnStreamTarget::MailAttachment` |
| Mail send, gate sharing, `.last_sent` retry (§17.2) | `client/otp_mail.rs` `handle_send`, `resend_pending`, `on_mail_result`; `client/otp_store.rs` `PendingOtpContent::Mail`; `client/otp.rs` `flush_one_queued` |
| Delivery acknowledgment (§7.2.1) | `p2p_proto.rs` `P2pPayload::DeliveryReceipt`, `ReceiptStage`; `client/p2p.rs` `P2pEvent::Delivered`; `client/session.rs` `send_delivery_receipt`, `remember_delivery_id`, `settle_delivery_id`, `handle_p2p_event`'s `Delivered` arm; `client/channel.rs` `on_message`; `client/tui/ui.rs` `MessageDelivery`, `DeliveryRecipient`, `DeliveryStatus`, `DELIVERY_ARROW`, `PLAIN_SEPARATOR`, `STRIKE_OVERLAY`, `strike_through`, `start_delivery`, `alloc_msg_id`, `mark_delivered`, `own_stream_msg_id`, `owe_replay_receipt`, `recipient_label`, `LISTENED_LABEL`, `SAVED_LABEL`, `LogEntry.delivery`, `LogEntry.owed_receipt`, `sender_prefix`, `render_messages`, `render_message_info_popup`; `client/tui/channel.rs` `push_outgoing_channel`; `client/tui/direct_message.rs` `push_outgoing_dm` |
| Sending what waited on a rotating key, and giving up bounded (§11.1) | `client/rekey.rs` `MAX_QUEUED_SEND_ATTEMPTS`, `QueuedOutbound`, `RemoteKeys::on_rotated`, `requeue`; `client/session.rs` `flush_queued_outbound`, `handle_pq_key_rotated` |
| Mail delivery, pre-decrypt gate, re-pad storage (§17.3) | `client/otp_mail.rs` `on_mail_deliver`, `on_mail_delivered`, `MailGate`, `mail_gate`, `handle_read`, `handle_delete`; `client/otp_mail_store.rs` `OtpMailStore`, `SentMailRef`, `ReceivedMailRef`, `SentMailStatus`; `crypto/otp.rs` `repad`, `xor_pad` |

## Encryption: how it actually works

Implementation map for `pq_hybrid` - this app's one peer-to-peer scheme -
and the two things it encrypts (text and voice), across both destinations
(channel and DM). Wire-level rules live in `docs/PROTOCOL.md`; this
section is the "where is it in the code" index. Entries reference file +
function name (no line numbers - they rot on every refactor; the name is
the stable handle).

### One scheme, one sourcing

Every peer-to-peer payload is sealed under the PQ-hybrid scheme
(Functionality #10), whose primitives live in `crypto/pq.rs`. It is the
only such scheme: `my_key` has one type, so every peer both signs and
opens sealed sends and there is no addressability rule to apply.

RSA-OAEP survives in exactly one place: the server's `rsa` auth
challenge (`connect.rs` `build_auth_response`, `server/mod.rs`'s verify),
where the client proves it holds the server's key by decrypting a nonce.

| Step | Where |
| --- | --- |
| Bytes-per-block for a key (auth challenge only) | `crypto/mod.rs` `max_chunk_len` |
| Encrypt/decrypt the auth nonce | `crypto/mod.rs` `encrypt_chunked`, `decrypt_chunked` |
| Wire shape of one encrypted body | `proto.rs` `Envelope` |

`my_key` has one sourcing: a keybundle loaded from `file_pub`/`file_priv`,
generated there on first connect if missing. `connect.rs`
`resolve_my_keypair` is the whole of it, returning a `ResolvedIdentity`
that `session.rs` (`run_connected_session`) unpacks into
`SessionState::own_pq_private` / `own_pq_fp` / `own_pq_keys` - all
non-optional, since every session has them.

The scheme is still announced to peers as `proto.rs` `KeyMode` in
`Identify`, which is what drives the encryption tag; it now has one value.

### Text messages

| | Channel | DM |
| --- | --- | --- |
| Send | `channel.rs` `handle_send_text` | `direct_message.rs` `handle_send_text` |
| Encrypt | `channel.rs` `encrypt_for_each` — loops recipients, each through `envelope.rs` `encrypt_envelope_for` → `encrypt_hybrid_envelope_for` | `direct_message.rs` `encrypt_for_recipient`, same call |
| Wire message | `P2pPayload::Envelope { channel: Some(_), .. }`, one per member | `P2pPayload::Envelope { channel: None, .. }` |
| Delivery | direct peer-to-peer link, one per recipient (`docs/PROTOCOL.md` §7.1/§7.2) — the server relays only the initial candidate exchange, never the message itself | same |
| Receive + decrypt | `session.rs` `decrypt_envelope_for` → `crypto/pq.rs` `open_send` against our own rotating keys, then the binding's channel and `ReplayGuard` are checked | same |

A channel message is therefore encrypted N times for N members and delivered
over N independent direct links — the server never sees any of them. A
member whose rotating key isn't fresh yet is queued rather than dropped
(`rekey.rs`), and one whose announced keybundle doesn't decode at all is
silently excluded, like any other unreachable recipient.

### Voice messages

Voice is streamed live, not recorded-then-sent (Functionality #4), so
encryption happens per 15ms chunk (`voice.rs` `CHUNK_INTERVAL`) on a
dedicated thread — never on the async event loop.

| Stage | Where |
| --- | --- |
| Recipients' stream keys sealed **once** at record-start | `voice_stream.rs` `build_pq_stream_out`, from `channel.rs` `handle_voice_record_start` / `direct_message.rs` `handle_voice_record_start` |
| Record + encrypt loop (own thread) | `voice_stream.rs` `spawn_record_stream_worker` |
| Ducking the microphone while the speakers are playing | `voice.rs` `EchoDucker`, `publish_playback_level` (from `mix_output`), `Recorder::echo_cancelled` |
| Deciding whether there is an echo path to duck for at all | `voice.rs` `EchoProbe`; `voice_stream.rs` `duck_capture`; `settings.rs` `EchoDucking` |
| Coding a chunk for the wire, and decoding one back | `voice.rs` `encode_voice_chunk` / `decode_voice_chunk`, `seed_step_index` |
| Encrypt a chunk — channel (per recipient) | `voice_stream.rs` `build_chunk_recipients` → `p2p::P2pOutbound::ChannelVoiceChunk` |
| Encrypt a chunk — DM | same, → `p2p::P2pOutbound::DirectVoiceChunk` |
| Delivery | direct peer-to-peer link, unreliable/unordered per chunk (`docs/PROTOCOL.md` §7.1/§7.3) — never touches the server |
| Receiving: snapshot our decryption keys **once** for the whole stream | `voice_stream.rs` `resolve_incoming_key`, from `SessionState::own_pq_keys` |
| Decrypt loop (one thread per incoming stream) | `voice_stream.rs` `spawn_stream_decrypt_worker`, decrypt in `ChunkDecryptor::decrypt` |
| Jitter buffer: when a source starts, how much backlog it may carry | `voice.rs` `MixSource::ready`/`on_push`/`note_underrun`, `jitter_ready_to_start`, `overflow_drop_samples`, `grown_prebuffer`, `decayed_prebuffer` |
| Asking the device for a short period instead of its default | `voice.rs` `DEVICE_BUFFER_MS`, `device_buffer_frames`, `build_with_buffer_fallback`; `voice_pulse.rs` `playback_attr`, `capture_attr` |

Each incoming stream gets its own decrypt thread because unwrap+AEAD is
meaningfully costlier than the sender's own encrypt — one shared thread
would fall behind real time with two or three simultaneous speakers.

### File transfer

Consent-gated and streamed (Functionality #9, `docs/PROTOCOL.md`'s file
transfer section) - the offer is sent/encrypted like text, then an accepted
transfer's bytes move like voice's chunk stream, except always
point-to-point (never a channel broadcast) since accept/reject/progress is
inherently per-recipient. `file_transfer.rs`'s workers mirror
`voice_stream.rs`'s plumbing but move bytes to/from disk instead of the
audio mixer, reusing its stream-key types (`DirectStreamKey`,
`IncomingStreamKey`, `ChunkDecryptor`) directly rather than duplicating
them.

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
| Not sending silence to every participant of the mesh | `voice.rs` `SilenceGate`, `SILENCE_LEVEL`, `SILENCE_HANGOVER` |
| Decrypt loop (one thread per participant's incoming audio) | `voice_call.rs` `spawn_call_decrypt_worker` |
| Telling a call chunk/setup apart from a voice message's, sharing the same wire events | `voice_call.rs` `is_call_stream`; `session.rs` `handle_p2p_event`'s `StreamChunk`/`StreamKeySetup` arms |
| Muting yourself (yours to lift, announced to the call) | `voice_call.rs` `toggle_mute`, `on_call_mute`'s self-report branch, `CallRecorderCmd::SetMuted`; `tui/ui.rs` `CallMember::self_muted` |
| Leaving, tearing down every participant | `voice_call.rs` `end_own_call`, `remove_participant` |
| END CALL asking before it leaves | `client/tui/ui.rs` `CallUiState::end_confirm`, `handle_end_call_confirm_key`, `render_end_call_confirm_popup`, `END_CALL_CONFIRM_TITLE` |
| Invite/accept/reject popup + permanent indicator | `client/tui/ui.rs` `PendingCallInvite`, `CallUiState`, `push_call_invite`/`call_invite_open`/`take_call_invite`, `begin_call`/`end_call`/`set_call_muted`, `UiAction::StartCall`/`AcceptCallInvite`/`RejectCallInvite`/`ToggleCallMute`/`EndCall` |
| The `/call` confirmation, with its invitee count | `client/tui/ui.rs` `PendingCallConfirm`, `call_invitee_count`, `render_call_confirm_popup`, `NO_ONE_INVITED_NOTICE` |
| The call modal - roster, duration, voice meters, END CALL | `client/tui/ui.rs` `CallMember`, `CallMemberState`, `tick_call_duration`, `set_call_level`, `handle_call_modal_key`, `render_call_modal`, `CallColumns`, `call_modal_rect`; `client/voice.rs` `level_from_pcm` |
| Folding it away into the top row's indicator, and back with Ctrl+R | `client/tui/ui.rs` `CallUiState::minimized`, `call_modal_showing`, `handle_call_modal_key`; `client/tui/channel.rs` `render_header_row` |
| Host mute (authoritative, host-only) | `client/tui/ui.rs` `set_call_member_host_muted`, `UiAction::HostMuteCallMember`; `voice_call.rs` `host_set_muted`, `on_call_mute`, `CallRecorderCmd::SetHostMuted` |
| Host invite mid-call, and the roster a latecomer needs | `client/tui/ui.rs` `call_invite_candidates`, `open_call_invite_picker`; `voice_call.rs` `invite_to_call`, `on_call_roster` |
| The host's departure ending the call for everyone | `voice_call.rs` `on_call_end`'s host branch, `teardown_own_call`; `client/tui/ui.rs` `HOST_LEFT_NOTICE` |
| Holding a key setup that outran its participant | `voice_call.rs` `PendingCallSetups`, `forward_key_setup`, `add_participant` |
| The help overlay's two columns (Functionality #7) | `client/tui/ui.rs` `HelpLine`, `help_keys_col`, `help_desc_col`, `wrap_to_width`, `help_lines_for_column`, `help_total_lines`, `render_help_popup` |
| The `#` a channel is shown with, and a typed one being ignored | `validation.rs` `CHANNEL_DISPLAY_PREFIX`, `normalize_channel_name`; `client/tui/ui.rs` `channel_label`; `client/tui/channel.rs` `handle_join_popup_key` |
| A peer who reconnects taking their own row and room back | `client/tui/ui.rs` `UiState::returning_peer_id`, `adopt_returning_peer`; `client/tui/channel.rs` `seed_member` |
| One log row for a channel file send, over all its transfers | `client/tui/ui.rs` `FileRowProgress`, `register_file_row_stream`, `update_file_row`; `client/channel.rs` `handle_send_file` |
| Giving up on an incoming stream nobody will finish | `voice_stream.rs` `IdleStreamAction`, `idle_stream_action`, `ActiveStream::end_requested`; `session.rs` `sweep_idle_streams` |
| The tag a pad session gives a person, wherever they are named | `client/tui/ui.rs` `OTP_TAG`, `OTP_TAG_COLOR`, `UiState::encryption_tag`, `SelectorEntry`; `client/tui/channel.rs` `render_sidebar`, `dm_selector_title`, `render_selector_dropdown` |
| A selector's dropdown hanging under that selector | `client/tui/channel.rs` `selectors_start_col`, `render_selector_dropdown` |
| Where a diagnostic goes ("Where diagnostics go") | `log.rs` `warn`, `silence`, `unsilence`, `drain`, `take_collected`, `RING_CAPACITY`, `PREFIX`; `client/tui/terminal.rs` `setup`, `restore` |
| A popup replacing the view behind it, and a resize repainting all of it | `client/tui/ui.rs` `render`; `client/tui/surface.rs` `Surface::resize` |
| The remembered connection, and what prefills the connect form with it | `settings.rs` `Settings::remember_connection`; `client/connect.rs` `prefill_connect_defaults`; `client/daemon.rs` `DaemonConfig::resolve` |
| How one message was encrypted, in the details popup | `client/tui/ui.rs` `MessageCrypto`, `crypto_lines`, `render_message_info_popup`; `client/otp_cli.rs` `OtpKeyStatus`, `contact_key_paths`; `crypto/mod.rs` `short_fingerprint_der` |

### What `pq_hybrid` adds

The identity itself is *static* - one keybundle loaded from a file for the
whole session - but its *encryption* keys rotate per peer as messages are
exchanged, so it reuses `rekey.rs`'s generic `RemoteKeys` for
freshness/queueing (§11) even though its rotation signing/verification is
entirely its own (`pq_rekey.rs`, `crypto/pq.rs`). Full model in
`docs/PROTOCOL.md` §13.

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
| Server proving its identity | `server/ssl.rs` `SslFiles`, `load_acceptor`, `client_connector`, `accept`, `connect` — TLS, not the control channel's own (unauthenticated) offer |
| How much a pin is worth | `client/idstore.rs` `Trust` (`tofu`/`verified`), `check_and_pin_with`, `mark_verified`, `trust` — third column of the store file |
| Retire an identity for a new one | `crypto/pq.rs` `ContinuitySig`, `sign_continuity`, `verify_continuity`, `PqPublicBundle::with_continuity`; `main.rs` `run_rekey_pq_hybrid` (`--rekey-pq-hybrid`); `session.rs` `continuity_proven` — a proven change re-pins with a status note instead of a review |
| Identity card (pin before first contact) | `crypto/pq.rs` `IdentityCard`, `make_identity_card`, `open_identity_card`, `save_identity_card`, `load_identity_card`; `main.rs` `run_export_identity_card` (`--export-identity-card`); `client/contacts.rs` `export_own_identity_card_to` (`/contacts`' `x`) |
| Save/load bundle files (private one `0o600` on unix) | `crypto/pq.rs` `save_public_bundle`, `load_public_bundle`, `save_private_bundle`, `load_private_bundle` |
| CLI keygen (no `openssl` equivalent exists) | `main.rs` `run_keygen_pq_hybrid`, `--keygen-pq-hybrid` |
| Key bundle fingerprint (identity, stable across reconnects) | `crypto/pq.rs` `bundle_fingerprint`, `fingerprint_of_encoded` |
| Seal one send's key, bound to recipient/room/counter | `crypto/pq.rs` `SendBinding`, `SendSetup`, `seal_setup` (ML-KEM-1024 + ephemeral X25519 wrap, then ML-DSA-87 + RSA-PSS over the commitment) |
| Open a send's key, verifying both signatures and the binding | `crypto/pq.rs` `open_setup` (refuses a setup sealed for anyone but us) |
| Seal/open one chunk (any content type) | `crypto/pq.rs` `seal_chunk`, `open_chunk`, `chunk_nonce` (deterministic `send_id`+`seq`) |
| One-chunk send (text, file offer) | `crypto/pq.rs` `HybridSend`, `seal_send`, `open_send`; `client/envelope.rs` `encrypt_hybrid_envelope_for` |
| Stream setup on the wire, once per recipient | `p2p_proto.rs` `P2pPayload::StreamKeySetup`; `voice_stream.rs` `PqStreamOut::setups`, `forward_key_setup` |
| Hold chunks that outrun their setup, replay once it verifies | `voice_stream.rs` `ChunkDecryptor::install_setup`, `MAX_PENDING_CHUNKS` |
| Hold chunks that outrun their own `StreamStart`, replay once it starts | `voice_stream.rs` `PendingChunkBuffer`, `forward_chunk`, `start_incoming_stream` |
| Refuse a send that already arrived | `client/replay.rs` `ReplayGuard`; `session.rs` `decrypt_own_envelope` (also checks the binding's channel) |
| Own key material in the live session | `session.rs` `SessionState::own_pq_private`, `own_pq_fp`, `own_pq_keys` - all non-optional, since every session has them |
| Who can be addressed | anyone who announced a keybundle that decodes; one who did not is reachable only under an already-installed pad (`otp.rs` `framing_for`) |
| `id_store` pinning | `session.rs` `check_identity` - a file-loaded identity is the same bytes every connect, so a plain byte comparison against the pin is the whole check |
| Auto-generate keys if missing | `crypto/pq.rs` `ensure_bundle_at`, called from `connect.rs` `resolve_my_keypair` (`docs/PROTOCOL.md` §13.9) |
| Resolve a keybundle prefix to its two files | `crypto/pq.rs` `bundle_paths` (writing), `resolve_bundle_paths` (reading, accepts both layouts); `daemon.rs` `resolve_my_key` (`docs/PROTOCOL.md` §13.9) |
| Refuse a mismatched pub/priv pair | `crypto/pq.rs` `bundle_pair_matches`, checked by `connect.rs` `resolve_my_keypair` (`docs/PROTOCOL.md` §13.9) |
| Connect-popup cache (`~/.aloo/.cache`) | `connect.rs` `ConnectCache`, `cache_path`, `random_prefix`, `fresh_pq_hybrid_paths_in`, `prefill_connect_defaults` |

### Logging in — a separate axis

Authenticating *to the server* is unrelated to the message encryption above:
one nickname, one password, checked against the users registry
(`server/users_registry.rs` `UsersRegistry::check_credentials`). Client
side: `connect.rs` `handshake_as` sends `ClientMessage::Auth`. Server side:
`server/mod.rs` `handle_connection` matches on `AuthCheck`.

| Outcome | What happens |
| --- | --- |
| `AuthCheck::Ok` | the derived key matches (`crypto/mod.rs` `constant_time_eq`) and the account is activated — `AuthResult { ok: true }`, then `Identify` |
| `AuthCheck::ActivationPending { expired: false }` | credentials right, code still owed — `AuthResult { ok: false, activation_pending: true }`, one `ClientMessage::Activate` may follow |
| `AuthCheck::ActivationPending { expired: true }` | the code is more than `ACTIVATION_VALIDITY_SECS` old — a fresh one is reissued and resent to the email on file if possible (same as registering again), otherwise refused |
| `AuthCheck::Rejected` | wrong password, or no such nickname — the same answer either way, so a login attempt cannot enumerate accounts |

The password is never persisted: `UsersRegistry` stores only the
PBKDF2-HMAC-SHA256 key it derives from nickname+password
(`derive_user_key`), hex-encoded in each account's `key` file.

## Server responsibilities

The server is only a medium of connection *setup*: it manages client connections, channel membership/broadcast, relays public key exchange (join notifications), and relays the candidate exchange that lets two clients punch a direct peer-to-peer link to each other (`docs/PROTOCOL.md` §7.1). Text, voice, and file content travel only over that direct link once it's established — the server never sees any of it, not even as ciphertext. It does not persist anything — chat/DM history lives only in each client's memory for the session. It does enforce nickname uniqueness, since that's connection bookkeeping rather than message content. It distinguishes a client explicitly leaving one channel from its connection closing entirely (Functionality #7), notifying peers with a different message for each (`docs/PROTOCOL.md` §6.2, §6.4) — but the *decision* of whether to keep an offline user's name around (grayed out) or drop it is made entirely client-side, based on that client's own private-message history, which the server has no visibility into.

It also arbitrates who owns and may moderate a channel (admin, ban/unban, join-lock, admin handoff), when an inactive channel is finally removed, and account-level status (a superadmin's `/activate`/`/deactivate`, or removing an account or a public channel outright) - all signaling the server already sits in the middle of, extended rather than exceeded (`docs/PROTOCOL.md` §6.7, §6.8, §5.5). None of this touches message/voice/file content, still peer-to-peer and invisible to the server; and none of it is persisted - channel ownership, bans and join-locks reset with every restart exactly like membership itself does, while account status (registration, activation, deactivation) is disk-backed because `UsersRegistry` already persists accounts today.
