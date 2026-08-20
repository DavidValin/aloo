# aloo

<p align="center">

* Status ⚠️ ALPHA (under heavy development and testing)

</p>

![aloo](aloo.png)

*Equipped with One-Time-Pad encryption (perfect secrecy) and quantum-resistant hybrid encryption.*

Walky talky in your terminal! aloo is a terminal chat app for talking with people privately and securely — text, voice, and file sharing, all end-to-end encrypted, all running in your terminal. A server connects you with the people you talk to and helps your app punch a direct connection to theirs, but your actual messages travel peer-to-peer — the server never carries them, encrypted or otherwise. No accounts, no tracking.

Just you, your terminal, and the people you're talking to.

* [⬇️ Download](https://github.com/DavidValin/aloo/releases) (⭐ MacOS ⭐ Linux and ⭐ Windows supported)

## Features

- 🎙️ **Walkie-talkie voice messages** — hold a key, talk, release. It plays live on the other end as you speak, and stays in the log to replay.
- 🔇 **Mute one person's voice** — stop one person's clips playing themselves, without blocking them or losing anything.
- 📞 **Live voice calls** — continuous, multi-user calls with a roster, per-person voice meters and host mute — distinct from a walkie-talkie clip.
- 💬 **Text chat** — type and hit Enter, just like any chat app.
- 📎 **File transfer, with consent** — a built-in file browser, and nothing moves until the recipient accepts. No size cap.
- 📢 **Public channels** — join what the server advertises; new ones appear live, no reconnect.
- 🔒 **Private channels** — unadvertised, joined by name, optionally password-protected.
- ✉️  **Private messages (DMs)** — a one-on-one room with anyone in the sidebar.
- 🔐 **Live One Time Pad sessions** — wrap a DM in real one-time-pad encryption, the only cipher with proven perfect secrecy, on top of the quantum-resistant layer you already have. Requires [otp-toolkit](https://github.com/DavidValin/otp-toolkit).
- 📨 **OTP mail** — a whole mail (subject, text, voice, attachments) that waits pad-sealed on the server, unreadable to it, until the recipient connects.
- 🌙 **Background mode** — keeps running with no terminal, so the global shortcut works from whatever app you're in. Attach a terminal whenever you like.
- 🎯 **Direct punching, with no server at all** — reach someone you already know without any introduction, on a schedule you both keep.
- 🌐 **Server-coordinated, never server-carried** — the server introduces people and helps punch a direct link; your content then travels peer-to-peer and never touches it. (OTP mail is the one deliberate exception: an already-sealed blob it stores, unreadably, until collected.)
- 🛡️ **Everything above is end-to-end encrypted.** See "Encryption" below for how.
- 💾 **Chat history isn't saved to disk.** Text and voice live in memory only — close it and they're gone. Accepted files are the exception (that's the point), and a received OTP mail stays as ciphertext plus its pad until you delete it, which destroys both.

## Getting started

### 1. Installation

* Easy way: [Download](https://www.github.com/DavidValin/aloo/releases)
* From git source code: `cargo build --release` (will be built at `target/release/aloo`)
* From crates.io: `cargo install aloo`
* If you need One Time Pad encryption, make sure the `otp` command is available on your system by installing [otp-toolkit](https://github.com/DavidValin/otp-toolkit)

### 2. Start (or join) a server

If someone already runs a server for you, skip to step 3 — you just need their host and port.

To run your own:

```sh
aloo --server                          # anyone can connect
aloo --server --password MYPASSWORD    # people need this password to connect
aloo --server --enc rsa server_key     # people need a matching RSA key to connect
```

The server always starts with one public channel called `the-hall` — the one channel a client joins automatically on connecting. Any other public channel is joined deliberately, from `/channels`.

The server and everyone connecting to it must run the **same version** of aloo. There is no version negotiation on the wire (see `docs/PROTOCOL.md` §9), so a server left behind on an older release isn't slower or reduced — clients simply can't connect to it, failing on connect with a decode error. `aloo --help`'s first line reports the version on each side.

Whatever `--bind`/`--port`/`--password`/`--enc` you run it with gets saved to `~/.aloo/settings`; a bare `aloo --server` afterwards (e.g. after a crash) reuses the last configuration you started it with, auth included, instead of resetting to open access on the default port.

### 3. Connect

```sh
aloo
```

This opens a connect screen. Fill in the host/port, pick a nickname, and press Connect. Everything else on that screen has sensible defaults — you don't need to touch it to get started (see `docs/SPEC.md` if you want to know what every field does).

Your identity type is already set to `pq_hybrid` (PQ-Hybrid, see "Encryption" below) — no need to generate any keys yourself beforehand, aloo creates them automatically the first time you connect.

Nicknames are case-sensitive and must be free — if someone else is already connected with it, you'll be bumped back to this screen with an error, so just pick another one and try again. A nickname frees up the moment its holder disconnects — even an unclean disconnect (a crash, a lost network) is caught within 30 seconds, so a name is never stuck "in use" for good.

## How to use it

Everything below works from the connected screen. `Ctrl+H` shows the same
thing in-app at any time.

### Getting around

| Key | What it does |
|---|---|
| `Tab` | Cycle focus: sidebar → messages → compose bar |
| `[` / `]` | Move between the channel selector (left) and the DM selector (right) |
| `[` / `]` at either end | Open that selector's dropdown — every channel you're in, or room you have open |
| `Up` / `Down` | Scroll the log one message (works from the compose bar too), or pick an entry in a dropdown or the sidebar |
| `PgUp` / `PgDn` | Scroll ten at a time |
| `Home` / `End` | Jump to the oldest / newest message (log focused) |
| `Ctrl+H` | Help — `Esc` or `Ctrl+H` closes |
| `Ctrl+C` | Quit |

A blinking ✉ marks a channel or DM with messages you haven't seen. A
dropdown left alone folds itself away after 30 seconds.

### Text messages

| Key | What it does |
|---|---|
| type + `Enter` | Send to the current channel or DM (compose bar focused) |

### Voice messages

| Key / command | What it does |
|---|---|
| hold `Space` | Record and send live — release to stop. Not while composing |
| hold `Ctrl+Alt+P` | The same, from any app, even when aloo isn't focused |
| `Enter` | Replay a voice message (messages focused) |
| `Esc` | Stop a replay that's playing |

It streams as you speak rather than sending a finished clip, so the other
side hears you live. Capped at 4 minutes: recording stops itself there, and
an incoming stream is never accepted past it either.

The global shortcut is on by default — change the combo or turn it off with
`global_ptt_shortcut` / `global_ptt_enabled` in `~/.aloo/settings`. Linux
needs X11; it isn't available under Wayland.

### Muting someone's voice

| Command | What it does |
|---|---|
| `/mute-voice <nickname>` | Stop their clips playing themselves on arrival |
| `/unmute-voice <nickname>` | Undo it |
| either, with no nickname | List who's currently muted |

Not a block: their messages still arrive and still show in the log, so
`Enter` replays them whenever you want. Muted people are marked 🔇 in the
sidebar, so a channel that went quiet explains itself. Kept in
`~/.aloo/settings`, so it survives reconnecting — you can even mute someone
who has never connected. Never affects a live call.

### Channels

| Key / command | What it does |
|---|---|
| `/channels` | List every public channel — yours in yellow. `Enter` joins, `Esc` closes |
| `Ctrl+J` | Join or create by name: Public/Private with `Left`/`Right`, optional password |
| `/leave` | Leave the selected channel — its tab disappears |

A public channel you've left stays in `/channels` to rejoin from. A private
one needs its name (and password, if the creator set one).

### Direct messages

| Key | What it does |
|---|---|
| `Enter` on a user | Open a private room with them (sidebar focused) |
| `Esc` | Back to the channel view — the room stays on the DM selector |
| `]` / `[` | Return to it later / go back to your channels |

### Sending a file

| Key / command | What it does |
|---|---|
| `/file` | Browse for a file to send |
| `Left` / `Right` / `Tab` | Choose Send file / Discard (Discard is focused by default) |

The recipient gets a popup with a chime naming you and the file, Accept
focused by default — nothing moves until they accept. It then streams
straight to `~/.aloo/downloads` with a live progress bar. Nothing is held
whole in memory on either side, and there's no size cap.

### Live voice calls

| Key / command | What it does |
|---|---|
| `/call` | Start a call in the selected channel or open DM |
| `/endcall` | Leave the call |
| `Up` / `Down` | Walk the roster |
| `Enter` or `e` | END CALL |
| `Esc` | Fold the modal away into the 🔴 Call indicator |
| `Ctrl+R` | Bring the modal back |
| `m` on your row | Mute your own microphone — yours alone to lift |
| `m` on another row | *(host only)* mute them — only you can lift it |
| `i` | *(host only)* invite one more person |

You confirm first, told how many people it will ring; everyone reachable
gets an Accept/Reject popup naming you. The modal shows live duration, the
host first, each person labelled `IN CALL` / `INVITED` / `REJECTED` (`+
MUTED`), with a moving voice bar. Leaving as the host ends it for everyone.
One call at a time, and not available over an `/otp` session.

### One-time-pad sessions

| Command | What it does |
|---|---|
| `/otp` | In an open DM: propose a one-time-pad layer for that contact |
| `/endotp` | End it immediately — either side may, no accept needed |

Never starts on its own say-so: it always ends in an explicit Accept/Reject
on the other side, confirmed back to you. Once active, every message, voice
clip and file in that room travels pad-wrapped, still peer-to-peer, with a
live header showing both directions' remaining key.

It survives either of you disconnecting and coming back — only `/endotp`
ever ends one, and the other side is told even if that means waiting until
they're next online. Requires
[otp-toolkit](https://github.com/DavidValin/otp-toolkit).

### OTP mail

| Key / command | What it does |
|---|---|
| `/mail` | Full-screen compose: To / Subtext / Content, plus attachments |
| hold `Space` | Record a voice attachment (attachments pane focused) |
| `Ctrl+S` | Send |
| `/mailbox` | Your mailbox: each sent mail's delivery status, and what arrived |

Needs a pinned recipient you share a pad with, and more pad left than the
mail is long — the remaining key shows top-right, updating as you type and
attach. It waits on the server, sealed, until they next connect.

## Running in the background

aloo's walkie-talkie shortcut only works while aloo is running — and the moment you actually want it is usually the moment it isn't: you're in a browser, an editor, a call. Background mode fixes that. aloo stays connected with no terminal at all, and `Ctrl+Alt+P` works from wherever you already are.

```sh
aloo --daemon                 # connect and go to the background
aloo --daemon --foreground    # same, but stay in this terminal
```

It reuses whatever you last connected with, so once you've connected normally at least once, a bare `aloo --daemon` is usually all you need. Flags (`--host`, `--nickname`, `--channels`, …) override, and whatever it starts with is remembered for next time.

```sh
aloo --daemon-status          # is one running?
aloo --daemon-stop            # stop it
```

### Where your voice goes: `--focus`

This is the setting that makes the whole thing worth having. With no window to look at and no decision to make, `--focus` decides where a held shortcut sends your voice.

```sh
aloo --daemon --channels=team --focus=channel:team   # to a channel
aloo --daemon --channels=team --focus=alice          # to one person
```

A bare value is a nickname; `dm:alice` spells the same thing out, and `channel:alice` is how you'd name a *channel* called alice. With a person, the daemon watches for them and opens that DM the moment they appear, so the shortcut talks to **them** rather than to the channel they turned up in. Until they appear there's nothing to talk to and the shortcut does nothing.

`--focus` is a *starting* position, not a standing instruction. Once it's been placed, wherever you later move to from an attached terminal is respected — the daemon won't quietly drag your voice somewhere else behind your back.

> **A person focus needs a channel to watch from.** Presence is channel-scoped: the server only tells you someone exists if you share a joined channel with them. `--focus=alice` with no `--channels` has nowhere to see her from, so the daemon joins `the-hall` to watch and says so in its log. Naming a channel you actually share with her is better — it's quieter, and it's where she'll be.

### Attaching a terminal, and giving it back

```sh
aloo                          # a daemon is running -> attach to it
```

With a daemon running, a bare `aloo` attaches instead of opening the connect screen. You get the full UI — sidebar, channels, message log, compose bar — driving the session that was already there, with all its history.

Type **`/daemon`** in the compose bar to hand it back: the session keeps running, your terminal is released. **`Ctrl+C` does the same thing** — it's answered by the attaching program itself and never reaches the daemon, so quitting your viewer can never kill the session behind it. Stopping it for real is `aloo --daemon-stop`, deliberately a separate command.

One terminal at a time: a second `aloo` while someone is attached says so and exits rather than fighting over the cursor. If you want a genuinely separate session alongside the daemon, `aloo --no-attach` — though the server will refuse it if it's the same nickname, since nicknames are unique among connected clients.

### How voice is handled with nobody watching

- **Sending:** hold `Ctrl+Alt+P` from any app, talk, release. It goes wherever `--focus` points — live, exactly as it would from a normal client.
- **Receiving:** voice messages play themselves the moment they arrive, which is the point of a walkie-talkie. That happens whether or not a terminal is attached, so you hear people without doing anything. `/mute-voice <nickname>` stops one person's from autoplaying; the message still arrives and can be replayed from the log later.
- **The join sound.** A daemon has no screen, so it says one thing out loud: when someone arrives *where the focus currently is* and nobody is watching, it plays a short sound and posts a desktop notification ("alice is here"). It's deliberately the narrowest possible trigger — it exists for "nobody is looking, and something changed where a held shortcut would land". If a terminal is attached, you'd already see it, so it stays quiet.
- **When something needs you**, like an OTP session failing to start or the daemon failing to come up, you get a bell and a notification with the reason — never a silent failure you discover later by pressing the shortcut and hearing nothing.

Full model, including running it at login: [`docs/SPEC.md`](docs/SPEC.md) "Running in background mode".

## Encryption

Every message — text, voice, or file — is encrypted on your device before it ever leaves it, individually for each person who's meant to read it, and delivered directly to them over a peer-to-peer connection your two apps punch through NAT with the server's help. **The server never sees your messages at all** — not the plaintext, not even the encrypted bytes. It only helps clients find each other and keeps track of who's in which channel.

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
- 🛡️ **PQH** (`PQ-Hybrid`, quantum-resistant) — the strongest option, and the **default**. It combines four things at once: ML-DSA-87 + RSA-4096 to sign and prove a message really came from you *and was meant for the person reading it*, ML-KEM-1024 + X25519 to securely share a one-time key, and AES-256-GCM to actually lock the message content. The keys that unlock your messages are also regenerated as you chat and the old ones thrown away, so someone who steals your key file later still can't read what you already said. Even if one of the newer post-quantum algorithms turns out to have a weakness someday, the classical RSA half still has to be broken too. You don't have to set anything up: if the keys don't exist yet, aloo generates them for you automatically the first time you connect.

These are the exact tags aloo shows next to a person's name, so you always know how someone's messages are protected just by looking at them.

| Tag | Method | Security level | Quantum-resistant? |
| --- | --- | --- | --- |
| 🚨 PLAIN | None | None | ❌ No |
| 🚨 PWD | Password | Basic | ❌ No |
| 🛡️ PQH | PQ-Hybrid | Ultra secure | ✅ Yes (as of today) |

Whichever identity type you and everyone else picks shows up as a little tag next to your name in the app, so it's always clear how a person's messages are being protected.

> **Heads up about PQH:** since it's the default, most people you meet will be using it — but it only talks to its own kind. A `PQH` user can message anyone, but can only *be messaged by* another `PQH` user. If a friend on `PLAIN`/`PWD` can't seem to reach you, that's why — one of you needs to switch to `pq_hybrid` too.

> **Going further with `/otp`:** on top of any `PQH` conversation, you can layer real one-time-pad encryption — perfect secrecy, the only cipher proven mathematically unbreakable when used correctly — for one DM at a time. It's not another identity type: nothing changes about your tag. Type `/otp` in a private message; if no shared pad exists for that contact yet, you're asked to either generate one and share it automatically over the already-encrypted `PQH` channel, or exchange it with them offline (run `otp` yourself and place the keys under `~/.aloo/otp/.keychain/`, then try `/otp` again) if you'd rather not send it over the network at all. Either way, the session only starts once your peer explicitly accepts too — from then on, every message in that room is additionally wrapped under the pad and shown with a 🛡️ prefix for as long as it stays active, and a 1-line header above the messages shows both directions' key position (sequence, offset, remaining MB) live, turning red per direction once it drops below 0.5MB. Each contact you do this with keeps its own independent pad — starting one with someone else never touches another's. Requires [otp-toolkit](https://github.com/DavidValin/otp-toolkit) installed — see the in-app help (`Ctrl+H`) for the full flow.
>
> **Ending it with `/endotp`:** either of you can end an active session unilaterally, no round trip needed — type `/endotp` in that room and your own copy of the pad is destroyed immediately, so it can never be spent again. The other side is told; if they're offline right now, aloo keeps trying every time you reconnect until they've genuinely heard, so ending a session with someone who's stepped away always still reaches them. Disconnecting and reconnecting, by either of you, never ends a session on its own — only `/endotp` does. While a session is active every DM with that person rides it — there's no way to drop back to a plain send in the meantime — but ending it never closes the conversation itself: the moment `/endotp` runs, DMs with that person go back to plain `PQH` immediately, same as before `/otp` was ever run.

By default, everything aloo writes to disk on its own — your auto-generated PQ-Hybrid keys, identity-pinning files, downloaded files — lives under `~/.aloo`. It never writes anywhere else unless you deliberately point a field (like a server RSA key file) somewhere else yourself. Set the `ALOO_HOME` environment variable to use a different directory instead — handy for running more than one client on the same machine (e.g. testing in separate terminals), since two clients sharing one `~/.aloo` would otherwise collide.

### Generating an RSA key for server authentication

Only needed if the server you're connecting to requires `--enc rsa`. Every identity type (`None`, `Password`, `PQ-Hybrid`) generates its own keys automatically; skip this otherwise.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out key
openssl rsa -pubout -in key -out key.pub
```

`key` is the private key — pass it to `--enc rsa key` (server). `key.pub` is the matching public key — hand it out to clients.

## One Time Pad mail

A live `/otp` session needs both of you online at once — One Time Pad mail doesn't. Write someone a whole mail — subject, text, voice recordings, file attachments — and it waits for them:

Driving it is in ["How to use it"](#otp-mail) above; what follows is what makes it different from a live session.

**The server's role here — and how it differs from a `/otp` session.** Live `/otp` messages travel **peer-to-peer**: the server carries none of them, it only helps your two apps find each other. Mail can't work that way — the whole point is that the recipient may be offline — so this is the one deliberate exception where the server acts as a mailbox: it **stores** the mail on disk and **delivers** it when the recipient next connects, deletes its copy the moment they confirm it arrived, and holds the delivery receipt for you until you've seen it. What it stores is sealed under your shared one-time pad *before it ever leaves your machine*: the server holds no key material and cannot read a byte of it. And because a bare pad hides content but can't detect tampering, every mail also carries a signature from your durable identity — so the server (or anyone else who touches the blob) can't alter a bit undetected.

Both paths spend the **same** pad for that contact, in strict order, so a mail and your live `/otp` messages never decrypt out of sequence. Composing needs a pinned recipient you share an `otp` pad with (see `/otp` above) and more pad remaining than the whole mail is long — the compose view shows the remaining key live, top-right, as you write and attach. A received mail rests on your disk as ciphertext plus the pad to read it by (never plaintext) until you remove it from `/mailbox`, which destroys both.

## Knowing who you're really talking to

Nicknames aren't proof of identity — anyone could reconnect as "alice" the moment the real alice disconnects. To handle this, aloo remembers people the same way SSH remembers servers in `known_hosts`:

- The **first time** you see someone's nickname, aloo just trusts their key and quietly remembers it (pinned locally, never sent anywhere).
- **Next time** they show up with the *same* key, nothing happens — it's silently confirmed as the same person.
- If that nickname ever comes back with a **different, unrecognized key**, aloo blocks messaging with them right away and, a moment later — as soon as it knows how to reach this new connection — asks you: an identity review popup shows up with **Accept** or **Reject**, naming not just both keys' fingerprints but also where each connection came from: `Last known from <address> (device <id>)` next to `Now connecting from <address> (device <id>)`, so you have more than two fingerprints to judge a key change by. Until you decide, you can't send them anything, and any messages they send stay hidden instead of appearing in your log.
- **Accept** if you've confirmed it's really them (new device, lost their old key, etc.) — the new key is pinned from then on. **Reject** if you're not sure — nothing is trusted, and you can revisit the decision later by opening a chat with them again.
- The "device" shown above is a random id aloo generates once per machine (`~/.aloo/d_id`) and reuses forever — purely informational, sent to peers only so it can show up in this popup.

This only applies to identity types that actually stay the same across reconnects (`Password`, `PQ-Hybrid`) — the `None` type has no persistent identity to pin in the first place, so there's nothing to compare.

## Advanced use

Two things most people will never need, and a few will need badly: reaching someone with no server involved, and running with no server at all.

### Punching straight to someone, with no server in it

Normally the server introduces two clients and they punch a direct connection to each other from there. If you already know where someone's machine is on the internet, you can skip that half too: aloo will punch straight at them on a schedule you both keep, with nothing coordinating it but the clock.

Add this to `~/.aloo/settings` (both of you — this only works if you've each listed the other):

```
direct_punch=on
direct_punch_to=bob,bobpublic.com,1m
direct_punch_to=marco,marcohost.com,1h
```

One line per person: their nickname, where their client is (an IPv4 address, an IPv6 address, or a hostname — add `:9000` for a port other than the default 7879), and how often to try. The frequency can be `1m`, `5m`, `10m`, `15m`, `20m`, `25m`, `30m`, `35m`, `40m`, `45m`, `50m`, `55m` or `1h`.

Every schedule restarts at the top of the hour — `1m` tries at :00, :01, :02, and so on; `1h` at :00 only — which is exactly what makes it work: you're both trying at the same moments, so your two routers open up to each other at the same time. That's also why you both need the same frequency for a given person.

Each attempt keeps trying for 30 seconds. Once you're connected, aloo leaves it alone and stops trying — until the connection drops, at which point it re-punches straight away (up to 5 times) if there's no server that could do it instead. You'll never end up with two connections to the same person; direct or server-arranged, there's only ever one.

Once a link is up, the two of you swap a sealed note saying which channels you're in — so a punched peer isn't just a connection, they show up in the sidebar of any channel you both joined and work like anyone else there: messages, voice, push-to-talk, calls. That's what makes this useful with [background mode](#running-in-the-background): with aloo in the background and `--focus` on a shared channel (or on their nickname), `Ctrl+Alt+P` reaches them and their voice plays on your end, with no server in the middle. Attach a terminal whenever you like and they're already there.

Opening that note is also what proves who they are — it's checked against the key you already pinned for that nickname, so a punch on its own registers nobody and a stranger who finds your port can't pose as a friend. It does mean this only works with people you've talked to through a server at least once (that's where their key came from), on the default `pq_hybrid` identity.

Two caveats. **Your client listens on UDP port 7879 while this is on**, so if you're behind NAT that port has to reach you — forward it, or set `direct_punch_port` to one you have. And **this opens a path, not a conversation**: aloo still needs to have learned that person's keys through a server at some point to encrypt anything to them.

### Running with no server at all

If everyone you want to reach is already in `direct_punch_to`, you don't need a server for anything:

```sh
aloo --daemon --no-server              # background
aloo --daemon --foreground --no-server # stay in the terminal
```

Channels come from your settings (`direct_punch_channel=general`, one per line) — those are the only ones that exist, and they're what `Ctrl+J` and `/channels` show. Everything that actually carries anything still works: messages, voice, push-to-talk, files, calls, and live `/otp` sessions are all peer-to-peer and never needed a server.

Two things are refused, and they say so on the status line the moment you ask rather than quietly doing nothing: joining a channel you haven't configured, and OTP mail (the server *is* the mailbox — live `/otp` is unaffected). A channel nobody has punched into yet says "Waiting for other users to connect directly to you", so an early client doesn't look like a broken one.

The catch, restated because it bites hardest here: you can only reach people you've talked to through a server at least once. There's no way to meet someone new without one.


## Want the technical details?

This README is the friendly tour. For the full nuts and bolts:

- [`docs/SPEC.md`](docs/SPEC.md) — the complete application specification.
If you ever need to replace your keys, use `aloo --rekey-pq-hybrid <old-prefix> <new-prefix>` rather than generating a fresh set: the new keys carry a certificate signed by the old ones, so people who already know you won't be warned that you might be an impostor. And `aloo --export-identity-card <prefix> <your-nickname>` writes a small file you can send to a friend by any means — once they import it, they have you verified before you've even spoken.

- [`docs/SECURITY.md`](docs/SECURITY.md) — what aloo protects, what it does not, and how much of that is actually checked. Read this before trusting it with anything that matters.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — the wire protocol, message framing, and cryptographic design in full detail. Written without reference to any implementation, so it stands on its own if you want to build a second one; section 14 compares the four encryption methods side by side and section 15 collects every message sequence.
- [`docs/TESTING.md`](docs/TESTING.md) — how the project is tested.
- [`docs/SERVER_ON_DOCKER.md`](docs/SERVER_ON_DOCKER.md) — running `aloo --server` in Docker.
