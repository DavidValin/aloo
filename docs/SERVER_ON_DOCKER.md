# Running the server on Docker

`docker-server/` packages `aloo --server` as an Alpine image. It doesn't
compile aloo — it downloads the prebuilt static musl binary from this
project's [GitHub releases](https://github.com/DavidValin/aloo/releases), so
building the image is fast and needs no Rust toolchain or build dependencies
(cpal/ALSA, x11rb, etc. — see the main `README.md` "Installation").

The container auto-restarts the `aloo` process if it crashes (see
"Crash recovery" below), independently of whatever restart policy you give
`docker run`/Compose for the container itself.

## Layout

```
docker-server/
├── Dockerfile-server          image definition
├── aloo-server-entrypoint.sh  translates ALOO_* env vars into `aloo --server` flags, supervises the process
└── .dockerignore
```

The directory is a self-contained build context — it doesn't read
`Cargo.toml` or anything else from the rest of the repo. The version to fetch
is baked in as a build arg default instead (see below).

## Building the image

```sh
docker build --no-cache -f docker-server/Dockerfile-server -t aloo-server docker-server
```

Note the build context at the end is `docker-server`, not `.` — the
Dockerfile only needs its own directory.

Always pass `--no-cache`. The `ALOO_VERSION` build arg defaults to `latest`,
resolved by a `RUN` step early in the Dockerfile — but that step's input (the
literal string `latest`) never changes, so Docker's layer cache happily
reuses whatever version it resolved to on the *first* build. Without
`--no-cache`, `docker build` looks like it "picks up the newest release each
time" but actually just replays the cached resolution forever; a real check
against the [releases page](https://github.com/DavidValin/aloo/releases)
only happens when the cache is bypassed.

To build a specific released version instead:

```sh
docker build --no-cache -f docker-server/Dockerfile-server -t aloo-server \
  --build-arg ALOO_VERSION=0.1.0-alpha.5 \
  docker-server
```

`ALOO_VERSION` must then match a tag that has
`aloo-<version>-linux-x86_64-musl.tgz` / `aloo-<version>-linux-aarch64-musl.tgz`
assets on that page. The build picks
x86_64 vs aarch64 from the build machine's own architecture (`uname -m`), so
it also resolves correctly under an emulated (QEMU) `--platform` build.

Either way the build log names the exact version it fetched, and that version
is recorded in the image (see "Which version am I running?" below).

### The server's version must match its clients'

aloo has **no protocol version negotiation** — client and server are expected
to be built from the same message definitions, and there is no compatibility
mechanism for a mismatch (see [`PROTOCOL.md`](PROTOCOL.md) §1 and §9). A
server one release behind its clients is not degraded, it is unreachable:
clients fail during the opening handshake, before authenticating.

That is why the default is `latest` rather than a tag written into the
Dockerfile — a pinned default quietly becomes a server nobody can connect to
as soon as the next release ships. If you do pin `ALOO_VERSION`, pin your
clients to the same tag, and rebuild the image with `--no-cache` whenever you
upgrade them (see "Building the image" above for why `--no-cache` is
required, not optional, to actually pick up a new version).

## Which version am I running?

```sh
docker exec aloo-server cat /etc/aloo-version   # baked in at build time
docker exec aloo-server aloo --help | head -1   # what the binary reports
```

Both should agree. Compare either against the client's own `aloo --help`
header when a connection is refused for no obvious reason — see
"Troubleshooting" below.

## Running the container

```sh
docker run -d \
  --name aloo-server \
  --restart unless-stopped \
  -p 7878:7878/tcp \
  -p 7878:7878/udp \
  -v /srv/aloo-data:/home/aloo/.aloo \
  -e ALOO_PASSWORD=mypassword \
  aloo-server
```

- `--restart unless-stopped` — covers the container itself dying (e.g.
  OOM-killed). See "Crash recovery" for how a crash of just the `aloo`
  process inside a still-running container is handled.
- `-p 7878:7878/tcp -p 7878:7878/udp` — publish **both** protocols on the
  port aloo listens on: TCP for client connections, and UDP for the
  rendezvous socket clients use to discover their own public address for
  direct peer-to-peer hole punching (`docs/PROTOCOL.md` §7.1) — a bare
  `-p 7878:7878` only publishes TCP and silently breaks that discovery
  step (clients still connect and chat fine, but fall back to host
  candidates only, which can't punch across two different NATs). If you
  change `ALOO_PORT` (below), update both mappings to match —
  `-p <host>:<ALOO_PORT>/tcp -p <host>:<ALOO_PORT>/udp`.
- `-v /srv/aloo-data:/home/aloo/.aloo` — see "The `~/.aloo` mount point" below.

## Parameters

The image runs as an unprivileged `aloo` user, not root. `aloo --server`
itself only takes `--bind`/`--port` (`src/main.rs`) - everyone who
connects logs in with a nickname and password checked against the users
registry, not a server-wide credential, so there is no auth flag to
expose. Everything below either maps to one of those two flags or is
written straight into `~/.aloo/settings` by the entrypoint script before
the server starts (`docker-server/aloo-server-entrypoint.sh`), all optional:

| Env var | Maps to | Notes |
| --- | --- | --- |
| `ALOO_PORT` | `--port` | Defaults to whatever `~/.aloo/settings` last recorded, or `7878` on first run. |
| `ALOO_BIND` | `--bind` | Defaults to whatever `~/.aloo/settings` last recorded, or `0.0.0.0` on first run. You'll rarely need to change this inside a container — it's already listening on all interfaces by default so `-p` can reach it. |
| `ALOO_REGISTER_USERS` | `aloo --register-user <n> <p>` per pair | Comma-separated `nickname:password` pairs, run once via the CLI before the server starts - active immediately, no email. Re-running a container that already has these in the mounted `~/.aloo/users` is a no-op: the "already registered" refusal is expected and ignored. |
| `ALOO_SSL` | `server_ssl` setting | `on` to serve the control connection over TLS. |
| `ALOO_SSL_FULLCHAIN` / `ALOO_SSL_PRIVKEY` | `server_ssl_fullchain` / `server_ssl_privkey` settings | Paths *inside the container* to the certificate pair - put them in the mounted volume so they survive recreation. |
| `ALOO_ALLOW_REGISTRATION` | `server_allow_registration` setting | `on` to let anyone register themselves from the connect screen. |
| `ALOO_SMTP_HOST` / `ALOO_SMTP_PORT` / `ALOO_SMTP_USERNAME` / `ALOO_SMTP_PASSWORD` | `server_smtp_*` settings | The relay activation emails go out through - required for `ALOO_ALLOW_REGISTRATION` to do anything but refuse every registration. |
| `ALOO_FEDERATION_ENABLED` | `server_federation_enabled` setting | `on` to link this server into a federation of peers (`docs/PROTOCOL.md` §18). |
| `ALOO_FEDERATION_ID` / `ALOO_FEDERATION_PORT` / `ALOO_FEDERATION_ADVERTISE_ADDR` / `ALOO_FEDERATION_IDENTITY` | `server_federation_id` / `_port` / `_advertise_addr` / `_identity` settings | This server's own federation identity - a PQ-hybrid keybundle prefix (no TLS/certificates), generated automatically on first start if missing; put it in a mounted volume so it survives a container restart. |
| `ALOO_FEDERATION_PEERS` | one `server_federation_peer` setting line per entry | `;`-separated list of trusted peers, each `<peer_id>,<host>,<port>,<public_key_path>` - `<public_key_path>` (that peer's `.pub` file, copied out of band) is also inside the container. Rewritten from this env var on every start, so it's the one source of truth for the peer list. |

If you omit port/bind, on a *second* run the container picks up whatever
was last saved to `~/.aloo/settings` on the mounted volume — same
behaviour as running `aloo --server` bare on the command line after a
crash (see README "Start (or join) a server"). The TLS/registration/SMTP
settings are not re-derived from flags at all, so once they're on the
volume they simply stay - the env vars only need setting again if you
want to *change* one of them.

Example with TLS and self-registration. The image doesn't ship
`certbot`/`openssl`, so put a certificate pair on the volume from outside
the container (see README "Generating a TLS certificate for a server"),
then:

```sh
docker run -d --name aloo-server --restart unless-stopped \
  -p 7878:7878/tcp -p 7878:7878/udp \
  -v /srv/aloo-data:/home/aloo/.aloo \
  -e ALOO_SSL=on \
  -e ALOO_SSL_FULLCHAIN=/home/aloo/.aloo/certs/fullchain.pem \
  -e ALOO_SSL_PRIVKEY=/home/aloo/.aloo/certs/privkey.pem \
  -e ALOO_ALLOW_REGISTRATION=on \
  -e ALOO_SMTP_HOST=smtp.example.com \
  -e ALOO_SMTP_PORT=587 \
  -e ALOO_SMTP_USERNAME=aloo@example.com \
  -e ALOO_SMTP_PASSWORD=s3cret \
  aloo-server
```

Or register a couple of accounts by hand instead of taking registrations at all:

```sh
docker run -d --name aloo-server --restart unless-stopped \
  -p 7878:7878/tcp -p 7878:7878/udp \
  -v /srv/aloo-data:/home/aloo/.aloo \
  -e ALOO_REGISTER_USERS=alice:s3cret,bob:hunter2 \
  aloo-server
```

## The `~/.aloo` mount point

Everything aloo writes on its own lives under `~/.aloo` — this is the same
directory the desktop app uses (see README "Encryption"), and inside the
container it's `/home/aloo/.aloo`:

- `settings` — the last bind/port/auth config, reloaded on a bare restart.
- the server's PQ-Hybrid / RSA identity keys, if auth uses them.
- `downloads/` — files accepted through the app; not really applicable to a
  headless server, but the same binary, so the path exists.

Bind mount a host directory at `/home/aloo/.aloo` so this survives
`docker rm`/recreation:

```sh
-v /srv/aloo-data:/home/aloo/.aloo
```

The image runs as the unprivileged `aloo` user (UID/GID `100:101`), and a
bind mount always keeps whatever ownership the host directory already has —
it never inherits ownership from the image. Create the directory and
`chown` it to that UID/GID before the first run, or `aloo` won't be able to
write to it:

```sh
mkdir -p /srv/aloo-data && chown 100:101 /srv/aloo-data
```

Do the same for anything placed there ahead of time — e.g. a TLS
certificate pair copied in before enabling `ALOO_SSL` (see "Generating a TLS
certificate for a server" in the README) needs `chown 100:101` on those
files too, or `aloo` won't be able to read them either.

## Crash recovery

`aloo-server-entrypoint.sh` runs `aloo --server` in a supervised loop: if
the process exits non-zero (crash, panic, killed), the entrypoint restarts
it after a short delay, doubling up to a 30s cap between attempts, and
resetting back to 1s after a clean run. This keeps the *container* alive and
the service self-healing without relying on `docker run --restart` cycling
the whole container (which also works, and is still worth setting — see
"Running the container" above — but only reacts to the container exiting,
not a respawned-in-place process).

`docker stop`/`docker restart` still work as expected: the entrypoint traps
`SIGTERM`, forwards it to the running `aloo` process, and exits without
restarting once it receives that signal.

## Logs

```sh
docker logs -f aloo-server
```

Restarts are logged by the entrypoint itself (`aloo-server: crashed (exit
<code>), restarting in <n>s`), so a crash loop is visible directly in
`docker logs` rather than only in `docker ps`'s restart count.

## Troubleshooting

### `Error: Decode("UnexpectedEnd { additional: 1 }")` on connect

The client exits with this the moment it connects, whatever `my_key` type or
password it was given, and the server logs nothing unusual. The container is
running an aloo older than the client — almost always one predating the
encrypted control channel ([`PROTOCOL.md`](PROTOCOL.md) §1.3), which added a
field to the server's opening `Hello`. The client decodes the two fields it
knows, reaches for the third, and runs one byte short.

Nothing about the message is specific to that field: any mismatch in the
`ClientMessage`/`ServerMessage` definitions can end this way (§9). This
particular error is just the one an old container produces, because `Hello`
is the very first thing decoded.

Compare the two versions:

```sh
docker exec aloo-server cat /etc/aloo-version
aloo --help | head -1        # on the machine running the client
```

If they differ, rebuild the image with `--no-cache` (see "Building the
image" — without it, the default `ALOO_VERSION=latest` just replays the
cached resolution from the first build instead of picking up the newest
release) and recreate the container:

```sh
docker build --no-cache -f docker-server/Dockerfile-server -t aloo-server docker-server
docker rm -f aloo-server && docker run -d ...   # same flags as before
```

The `~/.aloo` volume carries the server's settings and key material across
this, so recreating the container keeps its configuration and identity.

Images built before `/etc/aloo-version` existed won't have that file; use the
`aloo --help` line for both sides in that case.
