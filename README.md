# aloo

<p align="center">

* Status ⚠️ ALPHA (under heavy development and testing)

</p>

![aloo](aloo.png)

*Equipped with One-Time-Pad encryption (perfect secrecy) and quantum-resistant hybrid encryption.*

Walky talky in your terminal! aloo is a terminal chat app for talking with people privately and securely — text, voice, and file sharing, all end-to-end encrypted, all running in your terminal. A server connects you with the people you talk to and helps your app punch a direct connection to theirs, but your actual messages travel peer-to-peer — the server never carries them, encrypted or otherwise. No accounts, no tracking.

Just you, your terminal, and the people you're talking to.

* [⬇️ Download](https://github.com/DavidValin/aloo/releases) (⭐ MacOS ⭐ Linux ⭐ Windows supported)

## Features

- 🎙️ **Walkie-talkie voice messages** — hold a key, talk, release. It plays live on the other end as you speak, and stays in the log to replay.
- 🔇 **Mute one person's voice** — stop one person's clips playing themselves, without blocking them or losing anything.
- 📞 **Live voice calls** — continuous, multi-user calls with a roster, per-person voice meters and host mute — distinct from a walkie-talkie clip.
- 💬 **Text chat** — type and hit Enter, just like any chat app.
- ✅ **Delivery acknowledgments** — the arrow in `you -> message` says how far it got: grey, orange, green. `i` shows who has it, and who has heard or saved it.
- 📎 **File transfer, with consent** — a built-in file browser, and nothing moves until the recipient accepts. No size cap.
- 📢 **Public channels** — join what the server advertises; new ones appear live, no reconnect.
- 🔒 **Private channels** — unadvertised, joined by name, optionally password-protected.
- ☀️ **Channel ownership and moderation** — whoever creates a channel administers it: `/delete-channel`, `/ban`/`/unban`, `/lock-joins`, and `/assign-admin` to hand it off. An operator can also require `server_allow_create_public_channels=off` so only private channels get made, and set `server_channel_deletion_unactivity_period` to sweep away channels nobody's touched in a while.
- ⚡ **Server superadmins** — `server_superadmin` nicknames can lock an account out (`/deactivate`, `/activate` to reverse it), remove an account or any public channel outright, or list every registered user and what they administer with `/users`.
- 🔑 **Change your password live** — `/password <old> <new>` rotates your own password without a superadmin, taking effect immediately.
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

Run the interactive network installer in your terminal:
```bash
# using curl
curl -fsSL https://raw.githubusercontent.com/DavidValin/aloo/refs/heads/main/installer.sh | bash

# or using wget
wget -qO- https://raw.githubusercontent.com/DavidValin/aloo/refs/heads/main/installer.sh | bash
```
** this method works for server and client (aloo contains both modes in a single command)

### 2. Start (or join) a server

If someone already runs a server for you, skip to step 3 — you just need their host and port.

To run your own:

```sh
aloo --server                                       # bind 0.0.0.0:7878
aloo --server --bind 0.0.0.0 --port 7878            # the same, spelled out
```

Everyone who connects logs in with a nickname and a password, checked against the server's own users registry — there is no server-wide shared password or key any more. Create the first account or two directly on the server's machine:

```sh
aloo --register-user bob acoolpassword    # active immediately, no email needed
aloo --change-password bob newpass        # takes effect on dave's next login
```

Want people to be able to sign themselves up? Turn on `server_allow_registration` and an SMTP relay in `~/.aloo/settings` (see "Talking to the server (authentication)" below) — then anyone can register from the connect screen and activate with the code emailed to them.

The server always starts with one public channel called `the-hall` — the one channel a client joins automatically on connecting. Any other public channel is joined deliberately, from `/channels`.

The server and everyone connecting to it must run the **same version** of aloo. There is no version negotiation on the wire (see `docs/PROTOCOL.md` §9), so a server left behind on an older release isn't slower or reduced — clients simply can't connect to it, failing on connect with a decode error. `aloo --help`'s first line reports the version on each side.

Whatever `--bind`/`--port` you run it with gets saved to `~/.aloo/settings`; a bare `aloo --server` afterwards (e.g. after a crash) reuses the last configuration you started it with instead of resetting to the default port. TLS, registration and SMTP are settings-only — there's no flag for any of them — and are written to that file from the very first start, so they're easy to find and edit by hand; see "Talking to the server (authentication)" below.

### 3. Connect

```sh
aloo
```

This opens a connect screen. Fill in the host/port, a nickname and its password, and press Connect. An email field and a Register button are always there too — no account yet? Fill in an email and press Register instead; on success aloo asks right there for the 12-digit activation code that was just emailed to you. Pressing Register on a server that has `server_allow_registration` off just refuses, in red, telling you so. Everything else on that screen has sensible defaults — you don't need to touch it to get started (see `docs/SPEC.md` if you want to know what every field does).

Your identity type is already set to `pq_hybrid` (PQ-Hybrid, see "Encryption" below) — no need to generate any keys yourself beforehand, aloo creates them automatically the first time you connect. While Connect/Register is working — key generation included, the first time — the popup gives way to the animated background and a centered "connecting..."/"one moment...".

aloo remembers the host, port and nickname you connected with and proposes them again next time, so connecting a second time is usually just pressing Connect. They live in `~/.aloo/settings` (`connect_host`, `connect_port`, `connect_nickname`) if you ever want to change them by hand — and they're also what a flag-free `aloo --daemon` falls back to (see "Running in the background").

Nicknames are case-sensitive and must be free — if someone else is already connected with it, you'll be bumped back to this screen with an error, so just pick another one and try again. A nickname frees up the moment its holder disconnects — even an unclean disconnect (a crash, a lost network) is caught within 30 seconds, so a name is never stuck "in use" for good. It's still your account, though — the same nickname and password log you back in whenever you reconnect.

**If the connection drops, aloo gets itself back.** Nothing about a lost server ends the session: your direct links to other people are peer-to-peer and carry on regardless. But the server is what everyone else's *user list* comes from, so aloo reconnects on its own — right away, then 5s, 10s, 20s and every 30s, for as long as it takes — and re-joins the channels you were in, so you reappear for everyone, including anyone who connected while you were away. The top-left of the header says where it is up to: ⏺ `Connected to server!` in green, ⏺ `Reconnecting...`, ⏺ `Reconnecting in 5s...`, or ⏺ `Server down (reconnecting in 20 sec...)` in red. Running with `--no-server` it reads ⏺ `No server mode` in white instead — there is nothing to reconnect to.

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
| `Ctrl+O` | Open the focused message's link in your default browser — presses again cycle through more than one |
| `Ctrl+S` | Open the "Direct Punches" popup (shown only once you've configured one — see "Punching straight to someone") |
| `Ctrl+E` | Export specific channels/DMs to disk — see "Exporting your chat history" |
| `Ctrl+H` | Help — `Esc` or `Ctrl+H` closes |
| `Ctrl+C` | Quit |

A blinking ✉ marks a channel or DM with messages you haven't seen. A
dropdown left alone folds itself away after 30 seconds.

### Text messages

| Key | What it does |
|---|---|
| type + `Enter` | Send to the current channel or DM (compose bar focused) |
| `i` | Details of the selected message: when it was sent, and who has it (message log focused) |
| `/clear` | Empty the log of whichever channel or DM is open right now |
| `/clear-all` | Empty every channel and DM's log at once |

**Did it get there?** A message you sent reads `you -> message`, and the
arrow says how far it has got: **grey** while nobody has it, **green** once
everyone it was addressed to has, and **orange** in a channel while only
some do. Voice messages and file transfers carry it too. A message that
reached nobody is struck through. Messages from other people read
`them: message` — they arrived here by definition.

Green means their app decrypted it, not that a person read it. Grey is not
a failure: something still being punched through is re-sent by itself and
turns green when it lands.

Press `i` for the details — when it was sent, then each recipient with
`-> UNDELIVERED`, `-> DELIVERED`, or, once they have actually heard a voice
message or saved a file, `-> DELIVERED+LISTENED` / `-> DELIVERED+SAVED`.

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

A muted voice message — or one that simply arrived in a channel/DM you
weren't looking at — never autoplays, and its line ends with a red "not
listened" marker until you replay it (`Enter`) or it arrives somewhere
you're actually viewing.

### Exporting your chat history

Two ways to get a channel or DM's history onto disk as a plain-text log,
both writing under `~/.aloo/exports/<server>/{channels,dms}/` (`<server>`
is the host and port you're connected to, or `DIRECT` with `--no-server`):

- **Continuous, automatic:** set `autosave_messages=on` in
  `~/.aloo/settings`, and every message — text, voice, file notices,
  presence lines — is appended as it happens, `[<UTC timestamp>] <- name:
  text` per line, never replacing what's already there. Off by default.
- **Manual, on demand, any time:** **`Ctrl+E`** opens a popup listing every
  joined channel and open DM as a checkbox — `Up`/`Down` to move, `Enter`
  to check one, `Tab` onto Confirm/Cancel (`Cancel` focused by default).
  Confirming dumps each checked one's *current* history, files prefixed
  with a fresh short id so they never collide with the autosave log beside
  them. Works whether or not `autosave_messages` is on.

Either way, a voice message also gets a `.wav` file next to its `.log`,
named `<UTC time>_<nickname>.wav` and referenced from the log line by name.

**Reading it back:** set `resume_from_log=on` and a channel/DM pulls its own
history back in from that `.log` file (whichever session wrote it) instead
of starting empty — a screen's worth loads the moment you open it, and
scrolling `Up`/`PageUp`/`Home` past the top loads another screen's worth at
a time. Voice audio isn't decoded until you actually replay a row (`Enter`)
— until then it just shows as an unloaded reference. Off by default, and
independent of `autosave_messages` — it only ever reads what's already
there.

### Channels

| Key / command | What it does |
|---|---|
| `/channels` | List every public channel — yours in yellow. `Enter` joins, `Esc` closes |
| `Ctrl+J` | Join or create by name: Public/Private with `Left`/`Right`, optional password |
| `/leave` | Leave the selected channel — its tab disappears |

Channels are shown as `#name`. The `#` is just how they're written — typing
it back in (`#general`, `--channels=#team`) is fine, it's ignored.

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
| `Esc` | Fold the modal away into the ⏺ Call indicator |
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
| `/endotp` | End it, in sync on both sides — either side may, no accept needed; needs the peer online and takes effect once they confirm |

Never starts on its own say-so: it always ends in an explicit Accept/Reject
on the other side, confirmed back to you. Once active, every message, voice
clip and file in that room travels pad-wrapped, still peer-to-peer, with a
live header showing both directions' remaining key.

It survives either of you disconnecting and coming back — only `/endotp`
ever ends one, and the other side is told even if that means waiting until
they're next online. Requires
[otp-toolkit](https://github.com/DavidValin/otp-toolkit) installed
locally — `/otp` (and `/new-otp-mail-key` below) refuses immediately, with
a clear message, if it isn't.

### OTP mail

| Key / command | What it does |
|---|---|
| `/mail` | Full-screen compose: To / Subtext / Content, plus attachments |
| hold `Space` | Record a voice attachment (attachments pane focused) |
| `Ctrl+S` | Send |
| `/mailbox` | Your mailbox: each sent mail's delivery status, and what arrived |
| `/new-otp-mail-key` | Provision a mail-only key with an open DM's peer, both online right now |

`/mail` itself refuses the same way `/otp` does if
[otp-toolkit](https://github.com/DavidValin/otp-toolkit) isn't installed
locally — never opens the compose view only to fail once you try to send.

While anything you've received is still unread, the header shows a blinking
✉ and `<n> unread OTP Mails` — gone the moment you open it in the mailbox.

Needs a pinned recipient with a **mail** key for that contact - its own,
independent of any live `/otp` session with them - and more of it left than
the mail is long; the remaining key shows top-right, updating as you type
and attach. With no mail key at all, compose locks behind a red message
until Escape closes it (and the whole view with it) - see "One Time Pad
mail" and "Managing contacts" below for the two ways to get one. Once
sent, it waits on the server, sealed, until they next connect.

## Running in the background

aloo's walkie-talkie shortcut only works while aloo is running — and the moment you actually want it is usually the moment it isn't: you're in a browser, an editor, a call. Background mode fixes that. aloo stays connected with no terminal at all, and `Ctrl+Alt+P` works from wherever you already are.

```sh
aloo --daemon                 # connect and go to the background
aloo --daemon --foreground    # same, but stay in this terminal
```

It reuses whatever you last connected with — host, port and nickname included — so once you've connected normally at least once, a bare `aloo --daemon` is all you need: none of those are mandatory on the command line if aloo already knows them. Flags (`--host`, `--nick`, `--channels`, …) override, and whatever it starts with is remembered for next time.

```sh
aloo --daemon-status          # is one running?
aloo --daemon-stop            # stop it
```

### Where your voice goes: `--initial-focus`

This is the setting that makes the whole thing worth having. With no window to look at and no decision to make, `--initial-focus` decides where a held shortcut sends your voice.

```sh
aloo --daemon --channels=team --initial-focus=channel:team   # to a channel
aloo --daemon --channels=team --initial-focus=alice          # to one person
```

A bare value is a nickname; `dm:alice` spells the same thing out, and `channel:alice` is how you'd name a *channel* called alice. With a person, the daemon watches for them and opens that DM the moment they appear, so the shortcut talks to **them** rather than to the channel they turned up in. Until they appear there's nothing to talk to and the shortcut does nothing.

`--initial-focus` is a *starting* position, not a standing instruction. Once it's been placed, wherever you later move to from an attached terminal is respected — the daemon won't quietly drag your voice somewhere else behind your back.

> **A person focus needs a channel to watch from.** Presence is channel-scoped: the server only tells you someone exists if you share a joined channel with them. `--initial-focus=alice` with no `--channels` has nowhere to see her from, so the daemon joins `the-hall` to watch and says so in its log. Naming a channel you actually share with her is better — it's quieter, and it's where she'll be.

### Attaching a terminal, and giving it back

```sh
aloo                          # a daemon is running -> attach to it
```

With a daemon running, a bare `aloo` attaches instead of opening the connect screen. You get the full UI — sidebar, channels, message log, compose bar — driving the session that was already there, with all its history.

Type **`/daemon`** in the compose bar to hand it back: the session keeps running, your terminal is released. **`Ctrl+C` does the same thing** — it's answered by the attaching program itself and never reaches the daemon, so quitting your viewer can never kill the session behind it. Stopping it for real is `aloo --daemon-stop`, deliberately a separate command.

One terminal at a time: a second `aloo` while someone is attached says so and exits rather than fighting over the cursor. If you want a genuinely separate session alongside the daemon, `aloo --no-attach` — though the server will refuse it if it's the same nickname, since nicknames are unique among connected clients.

### How voice is handled with nobody watching

- **Sending:** hold `Ctrl+Alt+P` from any app, talk, release. It goes wherever `--initial-focus` points — live, exactly as it would from a normal client.
- **Receiving:** voice messages play themselves the moment they arrive, which is the point of a walkie-talkie. That happens whether or not a terminal is attached, so you hear people without doing anything. `/mute-voice <nickname>` stops one person's from autoplaying; the message still arrives and can be replayed from the log later.
- **The join sound.** A daemon has no screen, so it says one thing out loud: when someone arrives *where the focus currently is* and nobody is watching, it plays a short sound and posts a desktop notification ("alice is here"). It's deliberately the narrowest possible trigger — it exists for "nobody is looking, and something changed where a held shortcut would land". If a terminal is attached, you'd already see it, so it stays quiet.
- **When something needs you**, like an OTP session failing to start or the daemon failing to come up, you get a bell and a notification with the reason — never a silent failure you discover later by pressing the shortcut and hearing nothing.

Full model, including running it at login: [`docs/SPEC.md`](docs/SPEC.md) "Running in background mode".

## Encryption

Every message — text, voice, or file — is encrypted on your device before it ever leaves it, individually for each person who's meant to read it, and delivered directly to them over a peer-to-peer connection your two apps punch through NAT with the server's help. **The server never sees your messages at all** — not the plaintext, not even the encrypted bytes. It only helps clients find each other and keeps track of who's in which channel.

There are two separate places encryption shows up: how *you* prove who you are, and how *your messages* get locked. You pick both when you connect.

### Talking to the server (authentication)

How you prove you're allowed to connect: a nickname and its password, checked against the server's own users registry (`~/.aloo/users` on the server's machine) — the same login every time, not a mode chosen per connection.

- 🔑 **Nickname + password.** The server operator either registers you directly (`aloo --register-user <nickname> <password>`, active immediately) or turns on self-registration.
- ✉️ **Self-registration.** With `server_allow_registration=on` and an SMTP relay configured in `~/.aloo/settings` (`server_smtp_host`, `server_smtp_port`, `server_smtp_username`, `server_smtp_password`), anyone can register from the connect screen's Register button and activate with the 12-digit code emailed to them — valid for one hour, entered right there in aloo's own activation popup. One email address can back only one account, and five wrong codes in a row against a still-pending one remove it outright. More than 3 registrations, or 7 wrong passwords, from one address are refused for a while afterward too — 7 days and 24h respectively.
- 🔏 **Optional TLS.** `server_ssl=on` plus a certificate pair (`server_ssl_fullchain`/`server_ssl_privkey` — a Let's Encrypt pair works well) serves the control connection over TLS. On the client side this is settings-only too, not a connect-screen field, and there's no flag either — set `connect_using_ssl=on` in `~/.aloo/settings`, the one switch shared by a normal connect and a daemon start alike; a self-signed or privately issued certificate needs its root added via `connect_ssl_ca`. Get it wrong and a failed connect says so specifically ("this server appears to require/reject SSL") rather than a bare connection error — aloo never auto-negotiates or silently falls back to the other mode, it just tells you which one to flip.

None of this is per-connection: it's how the server itself is configured, in `~/.aloo/settings` on the server's machine.

### Your identity & message encryption

How your own messages get locked so only the intended reader can open them. There is nothing to choose here — every message uses the strongest scheme aloo has:

- 🛡️ **PQH** (`PQ-Hybrid`, quantum-resistant) — combines four things at once: ML-DSA-87 + RSA-4096 to sign and prove a message really came from you *and was meant for the person reading it*, ML-KEM-1024 + X25519 to securely share a one-time key, and AES-256-GCM to actually lock the message content. The keys that unlock your messages are also regenerated as you chat and the old ones thrown away, so someone who steals your key file later still can't read what you already said. Even if one of the newer post-quantum algorithms turns out to have a weakness someday, the classical RSA half still has to be broken too. You don't have to set anything up: if the keys don't exist yet, aloo generates them for you automatically the first time you connect.

These are the exact tags aloo shows next to a person's name, so you always know how someone's messages are protected just by looking at them.

| Tag | Method | Security level | Quantum-resistant? |
| --- | --- | --- | --- |
| 🛡️  PQH | PQ-Hybrid | Ultra secure | ✅ Yes (as of today) |
| 🔑 OTP | One-time pad — sealed inside PQ-Hybrid, or on its own (see below) | Perfect secrecy | ✅ Yes |

Your own tag is `🛡️ PQH` too, and so is everyone else's — the only thing that ever changes it is turning on a one-time pad with someone.

> **Two ways the pad can run.** Usually you and your contact both have PQ-Hybrid identities, so the pad goes on your message and the `PQH` envelope is sealed around *that* — both protections at once. (That order matters: a `PQH` envelope weighs about 6.4KB no matter how short the message, so padding the envelope instead of the message would burn roughly thirty-five times the pad on a one-line chat message, and pad, once spent, is gone. It also means a forged message is thrown out on its signature before a single byte of your pad is touched. Nothing about the envelope names you or your contact on the wire.) But two people who reach each other directly and have never exchanged PQ-Hybrid keys (no server, or a server that never introduced you) have no envelope to seal, and don't need one: the message goes into the pad and travels just like that. Nothing is lost by that. A one-time pad is unbreakable on its own, and `otp` refuses to decrypt anything it can't attribute to the holder of the matching key at the exact expected position — which is a *stronger* statement about who is speaking than a signature, because it's tied to that one position in your shared pad rather than to a keypair someone could steal. aloo picks between the two for you, per contact, and the message details popup (`i`) says which one a given message used.

> **Going further with `/otp`:** on top of any `PQH` conversation, you can layer real one-time-pad encryption — perfect secrecy, the only cipher proven mathematically unbreakable when used correctly — for one DM at a time. It's not another identity type — but while a session is on, that person's tag reads `🔑 OTP` instead of `🛡️ PQH`, in the user list, on the DM selector, on their dropdown row and in the room's own title, because the pad is what's actually protecting what you say to them. Type `/otp` in a private message; if no shared pad exists for that contact yet, you're asked to either generate one and share it automatically over the already-encrypted `PQH` channel, or exchange it with them offline (run `otp` yourself and place the keys under `~/.aloo/otp/.keychain/`, then try `/otp` again) if you'd rather not send it over the network at all. Either way, the session only starts once your peer explicitly accepts too — accepting opens that room for both of you; from then on, every message in it goes through the pad and is shown with a 🔑 prefix — which also sits at the front of the compose bar, so you can see what's about to happen to what you're typing — and a 1-line header above the messages shows both directions' key position (sequence, offset, remaining MB) live, turning red per direction once it drops below 0.5MB. Each contact you do this with keeps its own independent pad — starting one with someone else never touches another's. Requires [otp-toolkit](https://github.com/DavidValin/otp-toolkit) installed — see the in-app help (`Ctrl+H`) for the full flow.
>
> **How big a pad can be.** Up to **1TB per key** — the streaming limit of `otp` itself, which never loads a key into memory. Generating one shows a live spinner and progress bar, since a large pad takes a while. There is one practical catch: sharing it *automatically over the network* is capped far lower (a pad is handed to the direct link as one burst, and a hole-punched UDP link can only carry so much), so for anything beyond that cap you generate it yourself with `otp --new-key-pair <size_in_MB> <a> <b>` and install it on both sides from `/contacts` (`o`) — which has no size ceiling at all, because nothing crosses the network. aloo tells you which case you're in rather than failing obscurely.
>
> **Every message proves where it came from.** Since otp-toolkit v1.5.1, each message carries an encrypted metadata block — a chunk of the key itself, plus the message's sequence number and key offset — that the receiving side validates *before spending a single key byte*. A replayed, reordered, duplicated, corrupted, or foreign message is refused outright with your keys untouched, and aloo says so plainly rather than quietly producing garbage.
>
> **Ending it with `/endotp`:** either of you can end an active session — the other side is told, not asked — by typing `/endotp` in that room while they're online. Ending is a synchronized handshake: your side shows "ending session - waiting for them to confirm" and stays in the session (new sends to them are refused meanwhile; `/otp` cancels if you change your mind) until their acknowledgement of the end notice comes back — so the two of you always leave the session together, never one paused while the other unknowingly keeps spending the pad. An offline peer can't confirm anything, so `/endotp` at one is refused with a notice to try again when they're back; and if they drop mid-handshake, that exact notice — recovered, never re-encrypted — is re-delivered on every reconnect until it's genuinely confirmed. It pauses the session rather than destroying the pad: your key stays exactly where it was, so running `/otp` with that same contact again later resumes the identical pad instead of generating a new one — nothing is wasted. Disconnecting and reconnecting, by either of you, never ends a session on its own — only `/endotp` does. While a session is active every DM with that person rides it — there's no way to drop back to a plain send in the meantime — but ending it never closes the conversation itself: once confirmed, DMs with that person go back to plain `PQH`, same as before `/otp` was ever run.

By default, everything aloo writes to disk on its own — your auto-generated PQ-Hybrid keys, identity-pinning files, downloaded files — lives under `~/.aloo`. It never writes anywhere else unless you deliberately point a field (like `connect_ssl_ca`, or the server's own certificate paths) somewhere else yourself. Set the `ALOO_HOME` environment variable to use a different directory instead — handy for running more than one client on the same machine (e.g. testing in separate terminals), since two clients sharing one `~/.aloo` would otherwise collide.

### Generating a TLS certificate for a server

Only needed if you're turning `server_ssl` on. A real certificate for a domain you control:

```sh
certbot certonly --standalone -d chat.example.com
# then point server_ssl_fullchain / server_ssl_privkey at
# /etc/letsencrypt/live/chat.example.com/{fullchain,privkey}.pem
```

For local testing, a self-signed pair works too — clients then need its root added via `connect_ssl_ca`:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout privkey.pem -out fullchain.pem -days 365 -nodes -subj "/CN=localhost"
```

## One Time Pad mail

A live `/otp` session needs both of you online at once — One Time Pad mail doesn't. Write someone a whole mail — subject, text, voice recordings, file attachments — and it waits for them:

Driving it is in ["How to use it"](#otp-mail) above; what follows is what makes it different from a live session.

**The server's role here — and how it differs from a `/otp` session.** Live `/otp` messages travel **peer-to-peer**: the server carries none of them, it only helps your two apps find each other. Mail can't work that way — the whole point is that the recipient may be offline — so this is the one deliberate exception where the server acts as a mailbox: it **stores** the mail on disk and **delivers** it when the recipient next connects, deletes its copy the moment they confirm it arrived, and holds the delivery receipt for you until you've seen it. What it stores is sealed under your shared one-time pad *before it ever leaves your machine*: the server holds no key material and cannot read a byte of it. And because a bare pad hides content but can't detect tampering, every mail also carries a signature from your durable identity — so the server (or anyone else who touches the blob) can't alter a bit undetected.

**Mail has its own key, entirely separate from a live `/otp` session.** The two are never the same pad, even for a contact you have both with — spending one never touches the other. Composing needs a pinned recipient (§ above) plus a *mail* key for that contact specifically, with more pad remaining than the whole mail is long — the compose view shows the remaining key live, top-right, as you write and attach. `/new-otp-mail-key` is how you get one while you're both online: the exact same consent-and-transfer flow `/otp` uses, just filing the result as a mail key instead of a live-session one; `/contacts`' key details popup (below) is the other way, for installing one manually or when only one of you is online. Already have a mail key for that contact? Running it again does nothing over the network - you'll just see "otp mail key already exists. use /mail or delete existing in /contacts". **With no mail key at all, the compose view locks**: a centered red message names what's missing and how to fix it, and nothing but Escape does anything until you close it — which closes the whole compose view with it, not just the message. A received mail rests on your disk as ciphertext plus the pad to read it by (never plaintext) until you remove it from `/mailbox`, which destroys both.

## Knowing who you're really talking to

Nicknames aren't proof of identity — anyone could reconnect as "alice" the moment the real alice disconnects. To handle this, aloo remembers people the same way SSH remembers servers in `known_hosts`:

- The **first time** you see someone's nickname, aloo just trusts their key and quietly remembers it (pinned locally, never sent anywhere).
- **Next time** they show up with the *same* key, nothing happens — it's silently confirmed as the same person.
- If that nickname ever comes back with a **different, unrecognized key**, aloo blocks messaging with them right away and, a moment later — as soon as it knows how to reach this new connection — asks you: an identity review popup shows up with **Accept** or **Reject**, naming not just both keys' fingerprints but also where each connection came from: `Last known from <address> (device <id>)` next to `Now connecting from <address> (device <id>)`, so you have more than two fingerprints to judge a key change by. Until you decide, you can't send them anything, and any messages they send stay hidden instead of appearing in your log.
- **Accept** if you've confirmed it's really them (new device, lost their old key, etc.) — the new key is pinned from then on. **Reject** if you're not sure — nothing is trusted, and you can revisit the decision later by opening a chat with them again.
- The "device" shown above is a random 8-character id aloo generates once per nickname it connects as (`~/.aloo/d_id`) and reuses forever for that nickname — purely informational, sent to peers only so it can show up in this popup.

Your PQ-Hybrid identity is what gets pinned, and it stays the same across reconnects — which is exactly what makes a changed key worth asking about.

### Managing contacts: `/contacts`

`/contacts` opens the full list of everyone you've ever pinned — nickname, when they were last seen, how they're encrypted, and, per contact, three keys shown as ✅/❌ badges: **PQH** (the pinned identity itself), **OTP** (a live session key), and **OTP MAIL** (mail's own, independent key).

| Key | What it does |
|---|---|
| `Up` / `Down` | Move the selection |
| `Left` / `Right` | Cycle which of the three keys is highlighted — across the whole list at once, so paging up/down keeps comparing the same key |
| `Enter` | Open the highlighted key's details popup |
| `a` | Add a contact by hand — nickname (device id and identity card both optional) — for someone you haven't connected with yet; submitting pins them right away, even with no keys, and opens their PQH key popup to install one now or later |
| `d` | Delete the selected contact outright — forgets their pin and both other keys (confirms first) |
| `r` | Refresh the list (e.g. after the remaining key has moved) |
| `x` (or select the **Export identity card** button at the end of the list, `Enter`) | Export your own identity card (own pqhybrid key) — the live equivalent of `aloo --export-identity-card`, writing `~/.aloo/exports/<your-nickname>.aloo-card` |
| `Esc` | Close |

**A key's details popup** (`Enter`) explains what that key is for, then shows either its path on disk and live figures (seq/offset/remaining-MB, same as the `/otp` session header) with a **Delete key** action, or, if it doesn't exist yet, a **Create key** (PQH) / **Install manually** (OTP/OTP MAIL) action. Never both at once. `Left`/`Right` inside the popup switches which key it's showing.

- **PQH → Create key** imports a self-signed identity card (`aloo --export-identity-card`'s own output) via a file browser — refused unless the card's own attested nickname matches the row you opened it from.
- **PQH → Delete key** forgets the whole contact: the pin and both other keys with it, since neither can be named without it.
- **OTP / OTP MAIL → Install manually** is the alternative to `/otp`/`/new-otp-mail-key`'s own handshake: generate a pair yourself with the real `otp` command —

  ```sh
  otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>
  ```

  — send one party's keys to the other person out of band, keep the other party's for yourself, then point **encryption key** at your own sending half and **decryption key** at your own receiving half. Both sides need their matching keys installed before messaging — a mismatch decrypts to garbage, not an error, so double-check which half went where.
- **OTP / OTP MAIL → Delete key** removes just that one key, leaving the pin and the other key untouched.

Every one of these actions takes effect immediately: the list refreshes, and if `/mail` is open composing to that same nickname, its recipient check re-runs without you retyping anything.

## Advanced use

Two things most people will never need, and a few will need badly: reaching someone with no server involved, and running with no server at all.

### Punching straight to someone, with no server in it

Normally the server introduces two clients and they punch a direct connection to each other from there. If you already know where someone's machine is on the internet, you can skip that half too: aloo will punch straight at them on a schedule you both keep, with nothing coordinating it but the clock.

Add this to `~/.aloo/settings` (both of you — this only works if you've each listed the other):

```
direct_punch=on
direct_punch_to=bob,bobpublic.com,every_1m
direct_punch_to=marco,marcohost.com,every_1h
```

One line per person: their nickname, where their client is (an IPv4 address, an IPv6 address, or a hostname — add `:9000` for a port other than the default 7879), and how often to try. The frequency can be `every_1m`, `every_5m`, `every_10m`, `every_15m`, `every_20m`, `every_25m`, `every_30m`, `every_35m`, `every_40m`, `every_45m`, `every_50m`, `every_55m` or `every_1h`.

You don't have to hand-edit the file: **`Ctrl+S`** opens a "Direct Punches" popup listing every configured target — `a` adds one, `Enter`/`e` edits the selected one, `d` deletes it, `Esc` backs out. Saving writes straight back to `~/.aloo/settings` and reconfigures the schedule immediately, no restart needed. Once at least one is configured, the header shows `<active>/<total> direct punches, next try in <time> (Control+s)` to its left, in green once every configured peer is connected and yellow otherwise.

Every schedule restarts at the top of the hour — `every_1m` tries at :00, :01, :02, and so on; `every_1h` at :00 only — which is exactly what makes it work: you're both trying at the same moments, so your two routers open up to each other at the same time. That's also why you both need the same frequency for a given person.

Each attempt keeps trying for 30 seconds. Once you're connected, aloo leaves it alone and stops trying — until the connection drops, at which point it re-punches straight away (up to 5 times) if there's no server that could do it instead. You'll never end up with two connections to the same person; direct or server-arranged, there's only ever one.

Once a link is up, the two of you swap a sealed note saying which channels you're in — so a punched peer isn't just a connection, they show up in the sidebar of any channel you both joined and work like anyone else there: messages, voice, push-to-talk, calls. That's what makes this useful with [background mode](#running-in-the-background): with aloo in the background and `--initial-focus` on a shared channel (or on their nickname), `Ctrl+Alt+P` reaches them and their voice plays on your end, with no server in the middle. Attach a terminal whenever you like and they're already there.

Opening that note is also what proves who they are — it's checked against the key you already pinned for that nickname, so a punch on its own registers nobody and a stranger who finds your port can't pose as a friend. It does mean this only works with people you've talked to through a server at least once (that's where their key came from), on the default `pq_hybrid` identity.

**If a punch succeeds but you have no key pinned for that name at all**, aloo asks before doing anything: "A connection was received directly to your public ip from an unknown nickname... Do you want to check which of your local keys matches this request?" Say yes and it runs a real check against every other `pq_hybrid` key you already hold — including one with an OTP session layered on top — never a guess, and if exactly one matches, offers to use it for the new name too. It never checks a pad-only pin this way, since that would mean running every one-time pad you hold against an unverified message. Nothing matching says so plainly, and declining either question costs nothing. Three genuinely failed checks from the same address, spread over at least two minutes within 10 hours, permanently blocks it — lift that yourself by editing `~/.aloo/banned_ips.log`. Never triggered for someone you never listed, or for anyone a server introduces.

Two caveats. **Your client punches out from UDP port 7879 while this is on** — it's actively pinging the other side from that port, not just passively listening on it, and that's what gets through NAT with nothing to configure on your router: both of you punching at the same moment is what opens the path, not a forwarding rule. It can still fail against a stricter (symmetric) NAT or firewall, in which case forwarding that port — or picking a `direct_punch_port` you can forward — is the fallback. And **this opens a path, not a conversation**: aloo still needs to have learned that person's keys through a server at some point to encrypt anything to them.

**If your own address moves** (an ordinary home connection) or you connect from different locations, give a No-IP hostname to the peers punching at you instead of a raw address, and let aloo keep it updated:

```
noip_when_no_server_and_direct_punch_is_active=on
noip_hostname=myhouse.ddns.example
noip_username=bob
noip_password=haa
```

All four are off/empty by default, and all three of the latter need filling in for anything to run. Whenever there's no server to hear from — `--no-server`, or the server connection has dropped — and `direct_punch` names at least one target, this keeps `myhouse.ddns.example` pointed at wherever you currently are: an update fires as soon as it starts, then every 5 or 6 minutes alternately (5.5 minutes on average), always landing on second 50 of its minute so it lands before the punch schedule's own attempts, which fall on second 0. It stops the moment the server is reachable again — this only ever runs while direct punching is actually what's carrying you.

### Running with no server at all

If everyone you want to reach is already in `direct_punch_to`, you don't need a server for anything:

```sh
aloo --daemon --no-server              # background
aloo --daemon --foreground --no-server # stay in the terminal
aloo --no-server                       # plain foreground client, no daemon
```

A plain `aloo --no-server` skips the connect popup — there's no server to log in to — and goes straight to the connected screen if `direct_punch_to` names at least one peer. With none configured there's nothing to reach, so it prints a one-line explanation and exits immediately instead of opening to an empty screen.

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
