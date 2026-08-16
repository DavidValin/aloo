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
docker build -f docker-server/Dockerfile-server -t aloo-server docker-server
```

Note the build context at the end is `docker-server`, not `.` — the
Dockerfile only needs its own directory.

This builds whichever aloo version is set as the `ALOO_VERSION` build arg's
default (check `docker-server/Dockerfile-server` for the current value — it
tracks the version in `Cargo.toml` at the time the Dockerfile was last
updated, but the two can drift). To build a different released version:

```sh
docker build -f docker-server/Dockerfile-server -t aloo-server \
  --build-arg ALOO_VERSION=0.1.0-alpha.1 \
  docker-server
```

`ALOO_VERSION` must match a tag that has `aloo-x86_64_linux_musl.tar.gz` /
`aloo-aarch64_linux_musl.tar.gz` assets on the
[releases page](https://github.com/DavidValin/aloo/releases). The build
picks x86_64 vs aarch64 from the build machine's own architecture (`uname
-m`), so it also resolves correctly under an emulated (QEMU) `--platform`
build.

## Running the container

```sh
docker run -d \
  --name aloo-server \
  --restart unless-stopped \
  -p 7878:7878/tcp \
  -p 7878:7878/udp \
  -v aloo-data:/home/aloo/.aloo \
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
- `-v aloo-data:/home/aloo/.aloo` — see "The `~/.aloo` mount point" below.

## Parameters

The image runs as an unprivileged `aloo` user, not root. Every flag
`aloo --server` accepts (`src/main.rs`) is exposed as a Docker environment
variable, all optional:

| Env var | Maps to | Notes |
| --- | --- | --- |
| `ALOO_PORT` | `--port` | Defaults to whatever `~/.aloo/settings` last recorded, or `7878` on first run. |
| `ALOO_BIND` | `--bind` | Defaults to whatever `~/.aloo/settings` last recorded, or `0.0.0.0` on first run. You'll rarely need to change this inside a container — it's already listening on all interfaces by default so `-p` can reach it. |
| `ALOO_PASSWORD` | `--password` | Shared password every client must send. Mutually exclusive with `ALOO_ENC_TYPE`/`ALOO_ENC_KEYFILE` — the `aloo` binary itself rejects both being set. |
| `ALOO_ENC_TYPE` | `--enc <TYPE> ...` | Only `rsa` is currently supported. Must be set together with `ALOO_ENC_KEYFILE`. |
| `ALOO_ENC_KEYFILE` | `--enc rsa <FILE>` | Path *inside the container* to a PKCS8 PEM RSA **private** key (e.g. `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out server_key`) — see README "Talking to the server (authentication)". This is a different key from the `pq_hybrid` identity bundle `aloo --keygen-pq-hybrid` generates. Put it inside the mounted volume (e.g. `/home/aloo/.aloo/server_key`) so it survives container recreation. |

If you omit both port/bind, or both auth vars, on a *second* run the
container picks up whatever was last saved to `~/.aloo/settings` on the
mounted volume — same behaviour as running `aloo --server` bare on the
command line after a crash (see README "Start (or join) a server").

Example with RSA auth. The image doesn't ship `openssl`, so generate the key
with a throwaway container that has it, writing straight into the volume:

```sh
docker run --rm -v aloo-data:/home/aloo/.aloo alpine:3.20 sh -c \
  "apk add --no-cache openssl && \
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /home/aloo/.aloo/server_key && \
   chown 100:101 /home/aloo/.aloo /home/aloo/.aloo/server_key"

docker run -d --name aloo-server --restart unless-stopped \
  -p 7878:7878/tcp \
  -p 7878:7878/udp \
  -v aloo-data:/home/aloo/.aloo \
  -e ALOO_ENC_TYPE=rsa \
  -e ALOO_ENC_KEYFILE=/home/aloo/.aloo/server_key \
  aloo-server
```

(`chown 100:101` matches the `aloo` user/group inside the image — see "The
`~/.aloo` mount point" below for why that matters.)

## The `~/.aloo` mount point

Everything aloo writes on its own lives under `~/.aloo` — this is the same
directory the desktop app uses (see README "Encryption"), and inside the
container it's `/home/aloo/.aloo`:

- `settings` — the last bind/port/auth config, reloaded on a bare restart.
- the server's PQ-Hybrid / RSA identity keys, if auth uses them.
- `downloads/` — files accepted through the app; not really applicable to a
  headless server, but the same binary, so the path exists.

Mount a named volume or bind mount at `/home/aloo/.aloo` so this survives
`docker rm`/recreation:

```sh
-v aloo-data:/home/aloo/.aloo          # named volume (recommended)
-v /srv/aloo-data:/home/aloo/.aloo     # bind mount to a host path instead
```

The image pre-creates and `chown`s `/home/aloo/.aloo` to the `aloo` user
(UID/GID `100:101`), so a **brand new named volume gets the right ownership
automatically — but only if the `aloo-server` container is the first one to
ever mount it** (Docker seeds an empty named volume from whatever image
mounts it first, content and ownership included). If some other image
touches the volume first — e.g. the RSA-key-generation snippet above, which
uses plain `alpine` to get `openssl` — that other image creates the mount
point as root instead, and `aloo` then can't write to it. The RSA example
above works around this with an explicit `chown 100:101` on both the
directory and the key file; do the same for a bind mount to a host
directory, which never gets the image's seeded ownership either way:
`chown 100:101 /srv/aloo-data` before first use.

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
