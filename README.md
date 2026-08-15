# aloo

![aloo](aloo.png)

Walky talky in your terminal! aloo is a terminal chat app for talking with people privately and securely — text, voice, and file sharing, all end-to-end encrypted, all running in your terminal. No servers reading your messages, no accounts, no tracking.

Just you, your terminal, and the people you're talking to.

* [⬇️ Download](https://github.com/DavidValin/aloo/releases) (⭐ MacOS ⭐ Linux and ⭐ Windows supported)

## Features

- 💬 **Text chat** — type and hit `Enter`, just like any chat app.
- 🎙️ **Walkie-talkie voice messages** — hold `Space` to talk, let go to send. Just like a real walkie-talkie, it auto-plays live on the other end as you're talking — no play button, nothing to tap, they just hear you. You can also replay it later: scroll to it in the log and press `Enter` to hear it again. `Ctrl+Alt+P` does the same thing globally, even while aloo isn't focused.
- 📎 **File transfer** — send files straight from the app with a built-in file browser, no external tools needed. Capped at 1 MiB per file — it's built for quick attachments, not large files.
- 📢 **Public channels** — join the channels the server advertises, shown as tabs across the top.
- 🔒 **Private channels** — create or join a channel that isn't advertised to anyone; you just need to know its name.
- ✉️  **Private messages (DMs)** — open a one-on-one conversation with anyone in the sidebar.

- 🛡️  **Everything above is end-to-end encrypted**. See the "Encryption" section below for how.
- 💾 **Nothing is saved to disk.** Chat history — text, voice, files, all of it — only ever lives in memory for as long as the app is running. Close it or disconnect, and it's gone; there's no local chat log sitting around to find later.

## Getting started

### 1. Installation

* Easy way: [Download](https://www.github.com/aloo/releases)
* From git source code: `cargo build --release` (will be built at `target/release/aloo`)
* From crates.io: `cargo install aloo`

### 2. Start (or join) a server

If someone already runs a server for you, skip to step 3 — you just need their host and port.

To run your own:

```sh
aloo --server                          # anyone can connect
aloo --server --password MYPASSWORD    # people need this password to connect
aloo --server --enc rsa server_key     # people need a matching RSA key to connect
```

The server always starts with one public channel called `general`.

Whatever `--bind`/`--port`/`--password`/`--enc` you run it with gets saved to `~/.aloo/settings`; a bare `aloo --server` afterwards (e.g. after a crash) reuses the last configuration you started it with, auth included, instead of resetting to open access on the default port.

### 3. Connect

```sh
aloo
```

This opens a connect screen. Fill in the host/port, pick a nickname, and press Connect. Everything else on that screen has sensible defaults — you don't need to touch it to get started (see `docs/SPEC.md` if you want to know what every field does).

Your identity type is already set to `pq_hybrid` (PQ-Hybrid, see "Encryption" below) — no need to generate any keys yourself beforehand, aloo creates them automatically the first time you connect.

Nicknames are case-sensitive and must be free — if someone else is already connected with it, you'll be bumped back to this screen with an error, so just pick another one and try again.

### 4. Chat away

- **Tab** moves you between the sidebar, the message log, and the compose bar.
- Type a message and press **Enter** to send it to the current channel.
- Press **Space** and hold it to record and send a voice message live — let go to stop.
- Press **Ctrl+Alt+P** to do the same thing from anywhere — even if aloo isn't the focused window. Enabled by default; edit `~/.aloo/settings` (`global_ptt_shortcut`, `global_ptt_enabled`) to change the combo or turn it off. Needs X11 on Linux — not available under Wayland.
- Type `/file` and press **Enter** to send a file.
- Pick someone in the sidebar and press **Enter** to open a DM with them.
- Press `]` / `[` to switch between channel tabs, `Ctrl+J` to join or create a private channel.
- Press `Ctrl+H` anytime for an in-app help screen with all of this.

## Encryption

Every message — text, voice, or file — is encrypted on your device before it ever leaves it, individually for each person who's meant to read it. **The server never sees plaintext.** It only relays already-encrypted bytes and keeps track of who's in which channel — it's a mail carrier that can't open the envelopes it delivers.

There are two separate places encryption shows up: how *you* prove who you are, and how *your messages* get locked. You pick both when you connect.

### Talking to the server (authentication)

How you prove you're allowed to connect:

- 🔓 **None** — anyone can connect, no questions asked.
- 🔑 **Password** — a shared password the server owner gives out.
- 🗝️ **RSA key** — the server owner hands you their public key file; only people with a matching key can connect.

### Your identity & message encryption

How your own messages get locked so only the intended reader can open them:

- 🚨 **PLAIN** (`None`) — a fresh key is generated for you automatically each time you connect. Simple, but nobody can tell it's really "you" across sessions.
- 🚨 **PWD** (`Password`) — your key is derived from a password, so the same password always gives you the same identity, from any machine.
- 🔒 **RSA** (`RSA, file`) — a key pair saved to disk, reused every time you connect, so people recognize you as the same person session after session.
- 🔒 **RSAPM** (`RSA, rotating per message`) — instead of one long-term key, aloo quietly generates a fresh key *for each person you talk to*, and swaps it out every time you send or receive a message with them. Nothing to prepare before connecting — the first key is generated automatically. aloo does keep one small file (`own_next_keys`) so a peer can still tell you're the same person after you disconnect and reconnect; treat it like any other private key file.
- 🛡️ **PQH** (`PQ-Hybrid`, quantum-resistant) — the strongest option, and the **default**. It combines four things at once: ML-DSA-87 + RSA-4096 to sign and prove a message really came from you, ML-KEM-1024 + RSA-4096 to securely share a one-time key, and AES-256-GCM to actually lock the message content. Even if one of the newer post-quantum algorithms turns out to have a weakness someday, the classical RSA half still has to be broken too. You don't have to set anything up: if the keys don't exist yet, aloo generates them for you automatically the first time you connect.

These are the exact tags aloo shows next to a person's name, so you always know how someone's messages are protected just by looking at them.

| Tag | Method | Security level | Quantum-resistant? |
| --- | --- | --- | --- |
| 🚨 PLAIN | None | None | ❌ No |
| 🚨 PWD | Password | Basic | ❌ No |
| 🔒 RSA | RSA (file) | Secure | ❌ No |
| 🔒 RSAPM | RSA, rotating per message | Secure | ❌ No |
| 🛡️ PQH | PQ-Hybrid | Ultra secure | ✅ Yes |

Whichever identity type you and everyone else picks shows up as a little tag next to your name in the app, so it's always clear how a person's messages are being protected.

> **Heads up about PQH:** since it's the default, most people you meet will be using it — but it only talks to its own kind. A `PQH` user can message anyone, but can only *be messaged by* another `PQH` user. If a friend on `PLAIN`/`PWD`/`RSA`/`RSAPM` can't seem to reach you, that's why — one of you needs to switch to `pq_hybrid` too.

By default, everything aloo writes to disk on its own — your auto-generated PQ-Hybrid keys, identity-pinning files, downloaded files — lives under `~/.aloo`. It never writes anywhere else unless you deliberately point a field (like an RSA key file) somewhere else yourself.

## Knowing who you're really talking to

Nicknames aren't proof of identity — anyone could reconnect as "alice" the moment the real alice disconnects. To handle this, aloo remembers people the same way SSH remembers servers in `known_hosts`:

- The **first time** you see someone's nickname, aloo just trusts their key and quietly remembers it (pinned locally, never sent anywhere).
- **Next time** they show up with the *same* key, nothing happens — it's silently confirmed as the same person.
- If that nickname ever comes back with a **different, unrecognized key**, aloo stops and asks you: an identity review popup shows up with **Accept** or **Reject**. Until you decide, you can't send them anything, and any messages they send stay hidden instead of appearing in your log.
- **Accept** if you've confirmed it's really them (new device, lost their old key, etc.) — the new key is pinned from then on. **Reject** if you're not sure — nothing is trusted, and you can revisit the decision later by opening a chat with them again.

This only applies to identity types that actually stay the same across reconnects (`Password`, `RSA (file)`, `PQ-Hybrid`, and `RSA rotating per message` in its own way) — the `None` type has no persistent identity to pin in the first place, so there's nothing to compare.

## Want the technical details?

This README is the friendly tour. For the full nuts and bolts:

- [`docs/SPEC.md`](docs/SPEC.md) — the complete application specification.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the wire protocol, message framing, and cryptographic design in full detail.
- [`docs/TESTING.md`](docs/TESTING.md) — how the project is tested.
