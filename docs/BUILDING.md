# Building

How to build `aloo` locally for each target `.github/workflows/release.yml`
ships. Most targets are a plain `cargo build`; the Linux musl targets need
extra local setup, covered in its own section at the end.

## Index

1. [Prerequisites](#prerequisites)
2. [Linux (glibc)](#linux-glibc)
3. [macOS](#macos)
4. [Windows](#windows)
5. [Cross-compiling with `cross`](#cross-compiling-with-cross)
6. [Linux (musl, static)](#linux-musl-static)

## Prerequisites

- A stable Rust toolchain (`rustup toolchain install stable`), plus
  whichever target you're building for: `rustup target add <target-triple>`.
- `cargo build --release --locked` produces `target/<triple>/release/aloo`
  (`aloo.exe` on Windows) for every target below.

## Linux (glibc)

Native build, e.g. `x86_64-unknown-linux-gnu`. Requires ALSA's dev headers
(`cpal`'s ALSA backend links against them):

```
sudo apt-get install libasound2-dev
cargo build --release
```

## macOS

No extra system packages. Just:

```
cargo build --release
```

## Windows

No extra system packages. Just:

```
cargo build --release
```

## Cross-compiling with `cross`

`aarch64-unknown-linux-gnu` and both Linux musl targets are cross-compiled
with [`cross`](https://github.com/cross-rs/cross) (Docker-based), rather
than natively:

```
cargo install cross --git https://github.com/cross-rs/cross
cross build --release --target <target-triple>
```

`Cross.toml` configures each target's build container - see its comments
for what each step does and why. This needs a working local Docker
install; the containers it spins up download and compile several C
libraries from source, so expect real CPU/disk/network use and a build
that takes noticeably longer than a native one.

## Linux (musl, static)

`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` produce a
fully static (`-static-pie`) single-file binary - no runtime dependency on
glibc or any shared library, including ALSA's own. That static link is why
these targets need more than `cross build` alone to get working audio:

- **ALSA itself**: Debian's `libasound2-dev` package (used for the glibc
  targets above) ships only a shared `libasound.so`, which a static link
  can't use. `Cross.toml` builds `alsa-lib` from source, statically, inside
  the `cross` container instead.
- **PulseAudio/PipeWire**: ALSA normally reaches a PulseAudio or PipeWire
  server through an ALSA plugin (`libasound_module_pcm_pulse.so`) that's
  loaded with `dlopen()` at runtime - and a fully static musl binary can
  never `dlopen()` anything (musl's libc hard-fails this for static
  links, unconditionally, with "Dynamic loading not supported"). Since most
  desktop Linux distros route their *default* ALSA device through exactly
  that plugin, this isn't a corner case - a naively-built static binary
  gets no audio at all on most desktops.

  The fix is `src/client/voice_pulse.rs`: on musl only (`cfg(target_env =
  "musl")`), it talks to PulseAudio/PipeWire directly over `libpulse`'s own
  protocol instead of through ALSA, using `libpulse`/`libpulse-simple`
  statically linked into the binary (also built from source in
  `Cross.toml`, along with their own build-time-only dependencies -
  `libsndfile`, `libltdl`, `gettext-tiny`). No plugin, no `dlopen()`, same
  static-link goal preserved. See that file's doc comment for the full
  story.
- **Static pkg-config discovery**: the crate's own `pkg-config`-based build
  scripts (for `alsa-sys`, `libpulse-sys`, `libpulse-simple-sys`) need
  `PKG_CONFIG_ALLOW_CROSS=1` and `PKG_CONFIG_ALL_STATIC=1` set in the
  environment `cross build` runs in, or the static libraries `Cross.toml`
  just built won't be found/linked correctly:

  ```
  PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_ALL_STATIC=1 \
    cross build --release --target x86_64-unknown-linux-musl
  ```

  (CI sets these the same way, scoped to the musl target only - see
  `release.yml`'s "Build (cross)" step.)

After building, confirm the binary actually stayed static:

```
file target/x86_64-unknown-linux-musl/release/aloo
ldd target/x86_64-unknown-linux-musl/release/aloo   # expect "not a dynamic executable"
```

`aarch64-unknown-linux-musl`'s `Cross.toml` steps mirror x86_64's verbatim
(toolchain triplet swapped); as of this writing they're a port of the
proven x86_64 steps rather than independently build-verified, so treat a
first `aarch64-unknown-linux-musl` build as unproven until you've run it
and checked the same `file`/`ldd` output above.
