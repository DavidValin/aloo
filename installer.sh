#!/usr/bin/env bash
#
# installer.sh - installs `aloo` and `otp` (otp-toolkit) for the current
# operating system and CPU architecture, either from prebuilt binaries or by
# compiling from source.
#
# Usage:
#   ./installer.sh [options]
#
# Options:
#   --aloo-version <tag>   Version/tag of aloo to install (default: 0.3.0-alpha.8)
#   --otp-version <tag>    Version/tag of otp-toolkit to install (default: 1.7.1)
#   --install-dir <dir>    Where to install the binaries (default: /usr/local/bin,
#                           or $HOME/.local/bin if that is not writable/available)
#   --from-source           Compile both from source instead of asking
#   --prebuilt              Use prebuilt binaries instead of asking
#   -y, --yes               Assume "yes" to all confirmation prompts (also picks
#                           prebuilt binaries when the source/binary choice would
#                           otherwise be asked interactively)
#   --skip-emoji-fonts      Don't check/offer to install an emoji-capable font
#   -h, --help              Show this help message
#
# When a C compiler, a Rust toolchain (cargo) and git are all present, the
# script asks whether to install prebuilt binaries or compile from source.
# Otherwise it installs prebuilt binaries without asking.
#
# aloo's interface uses emoji. macOS and Windows ship an emoji-capable font
# out of the box; on Linux/BSD the script detects whether one is present and,
# if not, offers to install one (Noto Color Emoji or the closest local
# equivalent) via the system package manager and refresh the font cache.
#
# Environment variables ALOO_VERSION, OTP_VERSION, INSTALL_DIR, INSTALL_MODE
# (binary|source), ASSUME_YES and SKIP_EMOJI_FONTS can be used instead of the
# flags above.

set -eo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALOO_REPO="DavidValin/aloo"
OTP_REPO="DavidValin/otp-toolkit"

# Keep ALOO_VERSION in sync with the `version` field in this repo's Cargo.toml.
ALOO_VERSION="${ALOO_VERSION:-0.3.0-alpha.8}"
OTP_VERSION="${OTP_VERSION:-1.7.1}"
INSTALL_DIR="${INSTALL_DIR:-}"
INSTALL_MODE="${INSTALL_MODE:-}"
ASSUME_YES="${ASSUME_YES:-0}"
SKIP_EMOJI_FONTS="${SKIP_EMOJI_FONTS:-0}"

SUDO_OK=0
NEED_CLEANUP=()

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

supports_color() { [ -t 2 ]; }

info() {
  if supports_color; then printf '\033[1;34m[info]\033[0m %s\n' "$*" >&2
  else printf '[info] %s\n' "$*" >&2; fi
}
warn() {
  if supports_color; then printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2
  else printf '[warn] %s\n' "$*" >&2; fi
}
err() {
  if supports_color; then printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2
  else printf '[error] %s\n' "$*" >&2; fi
  exit 1
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

confirm() {
  # confirm "question" -> 0 (yes) / 1 (no)
  local prompt="$1"
  if [ "$ASSUME_YES" = "1" ]; then
    info "$prompt [assumed: yes]"
    return 0
  fi
  local reply=""
  if { : < /dev/tty; } 2>/dev/null; then
    printf '%s [y/N] ' "$prompt" > /dev/tty 2>/dev/null
    read -r reply < /dev/tty 2>/dev/null || reply=""
  else
    printf '%s [y/N] ' "$prompt" >&2
    read -r reply 2>/dev/null || reply=""
  fi
  case "$reply" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup() {
  local d
  for d in "${NEED_CLEANUP[@]-}"; do
    [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d"
  done
}
trap cleanup EXIT

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --aloo-version) ALOO_VERSION="$2"; shift 2 ;;
    --aloo-version=*) ALOO_VERSION="${1#*=}"; shift ;;
    --otp-version) OTP_VERSION="$2"; shift 2 ;;
    --otp-version=*) OTP_VERSION="${1#*=}"; shift ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --install-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
    --from-source) INSTALL_MODE="source"; shift ;;
    --prebuilt) INSTALL_MODE="binary"; shift ;;
    --skip-emoji-fonts) SKIP_EMOJI_FONTS=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown option: $1 (use --help for usage)" ;;
  esac
done

# ---------------------------------------------------------------------------
# OS / architecture detection
# ---------------------------------------------------------------------------

detect_os() {
  local s
  s="$(uname -s 2>/dev/null || echo unknown)"
  case "$s" in
    Linux*)   OS=linux ;;
    Darwin*)  OS=macos ;;
    FreeBSD*) OS=freebsd ;;
    NetBSD*)  OS=netbsd ;;
    OpenBSD*) OS=openbsd ;;
    MINGW*|MSYS*|CYGWIN*) OS=windows ;;
    *) err "Unsupported operating system: '$s'" ;;
  esac
}

detect_arch() {
  local m
  m="$(uname -m 2>/dev/null || echo unknown)"
  case "$m" in
    x86_64|amd64)        ARCH=x86_64 ;;
    aarch64|arm64)       ARCH=aarch64 ;;
    armv7l|armv7|armhf)  ARCH=armv7l ;;
    riscv64)             ARCH=riscv64 ;;
    *) err "Unsupported CPU architecture: '$m'" ;;
  esac
}

# ---------------------------------------------------------------------------
# Compile-from-source tooling detection
# ---------------------------------------------------------------------------

detect_can_compile() {
  # sets CAN_COMPILE (0/1), CC_BIN and MISSING_COMPILE_TOOLS
  CAN_COMPILE=0
  CC_BIN=""
  MISSING_COMPILE_TOOLS=()

  need_cmd git   || MISSING_COMPILE_TOOLS+=("git")
  need_cmd cargo || MISSING_COMPILE_TOOLS+=("cargo (Rust toolchain)")

  if [ "$OS" = "windows" ] && need_cmd cl; then
    CC_BIN="cl"
  elif need_cmd gcc; then
    CC_BIN="gcc"
  elif need_cmd cc; then
    CC_BIN="cc"
  elif need_cmd clang; then
    CC_BIN="clang"
  else
    MISSING_COMPILE_TOOLS+=("a C compiler (gcc/cc/clang)")
  fi

  [ "${#MISSING_COMPILE_TOOLS[@]}" -eq 0 ] && CAN_COMPILE=1
}

ask_install_mode() {
  # prints "binary" or "source" on stdout
  if [ "$ASSUME_YES" = "1" ]; then
    info "C/Rust/git toolchain detected, but --yes was given: defaulting to ready-to-use binaries." >&2
    printf 'binary\n'
    return 0
  fi
  if ! { : < /dev/tty; } 2>/dev/null; then
    warn "C/Rust/git toolchain detected, but no interactive terminal is available: defaulting to ready-to-use binaries." >&2
    printf 'binary\n'
    return 0
  fi
  {
    printf '\nA C compiler (%s), Rust (cargo) and git were all found on this system.\n' "$CC_BIN"
    printf 'What do you prefer?\n'
    printf '  a) Install ready to use (prebuilt binaries)\n'
    printf '  b) Compile from source and install\n'
  } > /dev/tty
  local reply
  while :; do
    printf 'Choice [a/b]: ' > /dev/tty
    read -r reply < /dev/tty 2>/dev/null || reply=""
    case "$reply" in
      a|A|"") printf 'binary\n'; return 0 ;;
      b|B) printf 'source\n'; return 0 ;;
      *) printf 'Please enter a or b.\n' > /dev/tty ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

url_exists() {
  local url="$1"
  if need_cmd curl; then
    curl -fsIL -o /dev/null "$url"
  elif need_cmd wget; then
    wget -q --spider "$url"
  else
    err "Neither curl nor wget is available; cannot download binaries."
  fi
}

fetch_to() {
  local url="$1" dest="$2"
  if need_cmd curl; then
    curl -fL --progress-bar -o "$dest" "$url"
  elif need_cmd wget; then
    wget -q --show-progress -O "$dest" "$url"
  else
    err "Neither curl nor wget is available; cannot download binaries."
  fi
}

list_release_assets_hint() {
  local repo="$1" version="$2"
  need_cmd curl || return 0
  curl -fsSL "https://api.github.com/repos/${repo}/releases/tags/${version}" 2>/dev/null \
    | grep '"name":' | grep -v '"login"' | sed 's/.*"name": *"\(.*\)".*/  - \1/' >&2 || true
}

# ---------------------------------------------------------------------------
# Asset resolution: prefer musl on Linux, fall back gracefully if a given
# release does not ship a musl build for that architecture.
# ---------------------------------------------------------------------------

get_suffixes() {
  SUFFIXES=()
  case "$OS" in
    linux)
      case "$ARCH" in
        x86_64)  SUFFIXES=(x86_64_linux_musl x86_64_linux) ;;
        aarch64) SUFFIXES=(aarch64_linux_musl aarch64_linux) ;;
        armv7l)  SUFFIXES=(armv7l_linux_musl armv7l_linux) ;;
        riscv64) SUFFIXES=(riscv64_linux_musl riscv64_linux) ;;
      esac
      ;;
    macos)
      case "$ARCH" in
        x86_64)  SUFFIXES=(x86_64_macos-intel x86_64_macos) ;;
        aarch64) SUFFIXES=(aarch64_macos) ;;
      esac
      ;;
    windows)
      case "$ARCH" in
        x86_64)  SUFFIXES=(x86_64_windows) ;;
        aarch64) SUFFIXES=(aarch64_windows) ;;
      esac
      ;;
    freebsd) [ "$ARCH" = "x86_64" ] && SUFFIXES=(x86_64_freebsd) ;;
    netbsd)  [ "$ARCH" = "x86_64" ] && SUFFIXES=(x86_64_netbsd) ;;
    openbsd) [ "$ARCH" = "x86_64" ] && SUFFIXES=(x86_64_openbsd) ;;
  esac
}

pick_asset() {
  # sets ASSET_FILENAME and ASSET_URL
  local name="$1" repo="$2" version="$3"
  get_suffixes
  if [ "${#SUFFIXES[@]}" -eq 0 ]; then
    err "'$name' has no prebuilt binaries for ${OS}/${ARCH}."
  fi
  local ext="tar.gz"
  [ "$OS" = "windows" ] && ext="zip"
  local suf filename url
  for suf in "${SUFFIXES[@]}"; do
    filename="${name}-${suf}.${ext}"
    url="https://github.com/${repo}/releases/download/${version}/${filename}"
    info "Checking for ${filename} (${version})..."
    if url_exists "$url"; then
      ASSET_FILENAME="$filename"
      ASSET_URL="$url"
      return 0
    fi
  done
  warn "Tried candidates: ${SUFFIXES[*]}"
  warn "Assets actually published for ${repo}@${version}:"
  list_release_assets_hint "$repo" "$version"
  err "Could not find a '$name' release asset for ${OS}/${ARCH} at version ${version}."
}

# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

extract_archive() {
  local archive="$1" dest="$2"
  case "$archive" in
    *.tar.gz|*.tgz)
      tar -xzf "$archive" -C "$dest"
      ;;
    *.zip)
      if need_cmd unzip; then
        unzip -q -o "$archive" -d "$dest"
      elif need_cmd bsdtar; then
        bsdtar -xf "$archive" -C "$dest"
      elif need_cmd tar && tar -tf "$archive" >/dev/null 2>&1; then
        # Git for Windows / MSYS ship libarchive's bsdtar as plain `tar`,
        # which extracts .zip too even though it's not named `bsdtar`.
        tar -xf "$archive" -C "$dest"
      elif need_cmd python3; then
        python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$archive" "$dest"
      elif need_cmd powershell.exe; then
        powershell.exe -NoProfile -Command \
          "Expand-Archive -LiteralPath '$archive' -DestinationPath '$dest' -Force"
      else
        err "No tool available to extract .zip archives (need unzip, bsdtar, python3, or powershell.exe)."
      fi
      ;;
    *) err "Don't know how to extract archive: $archive" ;;
  esac
}

# ---------------------------------------------------------------------------
# Locating and removing pre-existing installations
# ---------------------------------------------------------------------------

find_existing() {
  # prints one absolute path per line for every place `name` (or name.exe on
  # Windows) is found, deduplicated.
  local name="$1" exe="$name"
  [ "$OS" = "windows" ] && exe="${name}.exe"

  local -a search_dirs=()
  local old_ifs="$IFS"
  IFS=':'
  for d in $PATH; do search_dirs+=("$d"); done
  IFS="$old_ifs"
  search_dirs+=(
    /usr/local/bin /usr/bin /bin /usr/local/sbin /usr/sbin /sbin
    /opt/homebrew/bin /opt/local/bin
    "$HOME/.local/bin" "$HOME/bin" "$HOME/.cargo/bin"
  )
  [ -n "$INSTALL_DIR" ] && search_dirs+=("$INSTALL_DIR")

  local -a found=()
  local dir cand real already
  for dir in "${search_dirs[@]}"; do
    [ -n "$dir" ] || continue
    for cand in "$dir/$name" "$dir/$exe"; do
      if [ -f "$cand" ]; then
        real=$(realpath "$cand" 2>/dev/null || readlink -f "$cand" 2>/dev/null || echo "$cand")
        already=0
        for f in "${found[@]-}"; do
          [ "$f" = "$real" ] && already=1 && break
        done
        [ "$already" -eq 0 ] && found+=("$real")
      fi
    done
  done
  printf '%s\n' "${found[@]-}"
}

ensure_sudo() {
  [ "$SUDO_OK" = "1" ] && return 0
  if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
    SUDO_OK=1
    return 0
  fi
  if ! need_cmd sudo; then
    err "Administrator privileges are required but 'sudo' is not available."
  fi
  info "Administrator privileges are required. You may be asked for your password."
  sudo -v || err "Failed to obtain sudo privileges."
  SUDO_OK=1
}

is_writable_as_target() {
  # true if the *directory* of $1 is writable without elevation
  local dir
  dir="$(dirname "$1")"
  [ -w "$dir" ]
}

remove_paths() {
  local p
  for p in "$@"; do
    [ -n "$p" ] || continue
    info "Removing existing binary: $p"
    if is_writable_as_target "$p"; then
      rm -f "$p"
    else
      ensure_sudo
      sudo rm -f "$p"
    fi
  done
}

# ---------------------------------------------------------------------------
# Install directory selection
# ---------------------------------------------------------------------------

choose_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    return 0
  fi
  if [ "$OS" = "windows" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    return 0
  fi
  if [ -w "/usr/local/bin" ] || need_cmd sudo || [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
    warn "No write access to /usr/local/bin and no sudo available; installing to $INSTALL_DIR instead."
  fi
}

ensure_path_persisted() {
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) export PATH="$PATH"; return 0 ;;
  esac

  local export_line="export PATH=\"$INSTALL_DIR:\$PATH\""
  local -a rc_files=()
  case "$OS" in
    macos)   rc_files=("$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile") ;;
    windows) rc_files=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile") ;;
    *)       rc_files=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile") ;;
  esac

  local f updated=0
  for f in "${rc_files[@]}"; do
    [ -e "$f" ] || continue
    grep -Fq "$INSTALL_DIR" "$f" 2>/dev/null && continue
    { printf '\n# added by aloo installer.sh\n%s\n' "$export_line"; } >> "$f"
    info "Added $INSTALL_DIR to PATH in $f"
    updated=1
  done

  if [ -d "$HOME/.config/fish" ] || need_cmd fish; then
    local fish_cfg="$HOME/.config/fish/config.fish"
    mkdir -p "$HOME/.config/fish"
    if ! grep -Fq "$INSTALL_DIR" "$fish_cfg" 2>/dev/null; then
      {
        printf '\n# added by aloo installer.sh\n'
        printf 'if not contains %s $PATH\n    set -gx PATH %s $PATH\nend\n' "$INSTALL_DIR" "$INSTALL_DIR"
      } >> "$fish_cfg"
      info "Added $INSTALL_DIR to PATH in $fish_cfg"
      updated=1
    fi
  fi

  # On Windows, the .bashrc/.profile edits above only cover Git Bash / MSYS
  # shells. cmd.exe and PowerShell read the PATH stored in the registry, so
  # update that too (per-user, no admin rights required) when we can form a
  # proper Windows-style path for it.
  if [ "$OS" = "windows" ] && need_cmd cygpath && need_cmd powershell.exe; then
    local win_dir
    win_dir="$(cygpath -w "$INSTALL_DIR")"
    if INSTALL_DIR_WIN="$win_dir" powershell.exe -NoProfile -NonInteractive -Command '
        $dir = $env:INSTALL_DIR_WIN
        $cur = [Environment]::GetEnvironmentVariable("Path","User")
        if ([string]::IsNullOrEmpty($cur)) {
          [Environment]::SetEnvironmentVariable("Path", $dir, "User")
        } elseif (($cur -split ";") -notcontains $dir) {
          [Environment]::SetEnvironmentVariable("Path", "$cur;$dir", "User")
        }
      ' 2>/dev/null; then
      info "Added $win_dir to the Windows user PATH (new cmd.exe/PowerShell windows will see it)."
      updated=1
    else
      warn "Could not update the native Windows PATH via PowerShell; 'aloo'/'otp' will still work from this Git Bash/MSYS shell."
    fi
  elif [ "$OS" = "windows" ]; then
    warn "cygpath/powershell.exe not found; only Git Bash/MSYS shells will see 'aloo'/'otp' on PATH."
  fi

  export PATH="$INSTALL_DIR:$PATH"
  PATH_NEEDS_RELOAD=$updated
}

install_binary() {
  local src="$1" name="$2"
  local dest_name="$name"
  [ "$OS" = "windows" ] && dest_name="${name}.exe"
  local dest="$INSTALL_DIR/$dest_name"

  if [ ! -d "$INSTALL_DIR" ]; then
    if [ -w "$(dirname "$INSTALL_DIR")" ] 2>/dev/null; then
      mkdir -p "$INSTALL_DIR"
    else
      ensure_sudo
      sudo mkdir -p "$INSTALL_DIR"
    fi
  fi

  chmod +x "$src"
  if is_writable_as_target "$dest"; then
    cp "$src" "$dest"
  else
    ensure_sudo
    sudo cp "$src" "$dest"
    sudo chmod +x "$dest"
  fi
  info "Installed $name -> $dest"
}

# ---------------------------------------------------------------------------
# Compile from source
# ---------------------------------------------------------------------------

install_man_page() {
  # best-effort, non-fatal: installs otp's man page next to $INSTALL_DIR
  local src_man="$1"
  [ -f "$src_man" ] || return 0
  [ "$OS" = "windows" ] && return 0

  local man_dir
  case "$INSTALL_DIR" in
    */bin) man_dir="${INSTALL_DIR%/bin}/share/man/man1" ;;
    *)     man_dir="/usr/local/share/man/man1" ;;
  esac

  if mkdir -p "$man_dir" 2>/dev/null && cp "$src_man" "$man_dir/otp.1" 2>/dev/null; then
    info "Man page installed to $man_dir/otp.1"
    return 0
  fi
  if need_cmd sudo; then
    ensure_sudo
    if sudo mkdir -p "$man_dir" && sudo cp "$src_man" "$man_dir/otp.1"; then
      info "Man page installed to $man_dir/otp.1"
      return 0
    fi
  fi
  warn "Could not install man page to $man_dir (non-fatal)."
}

compile_otp() {
  local repo="$1" version="$2" workdir="$3"
  local url="https://github.com/${repo}.git"
  local src="$workdir/otp-toolkit"
  local bin_name="otp"
  [ "$OS" = "windows" ] && bin_name="otp.exe"

  info "Cloning ${url} (tag ${version})..."
  git clone --quiet --depth 1 --branch "$version" "$url" "$src" \
    || err "Failed to clone otp-toolkit at tag '${version}'."

  (
    cd "$src"
    mkdir -p bin
    info "Compiling otp-toolkit with ${CC_BIN} (equivalent to 'make build', without make)..."
    if [ "$CC_BIN" = "cl" ]; then
      cl /O2 /Wall "/Fe:bin/${bin_name}" src/cli.c src/keychain.c src/cipher.c src/commit.c
    else
      "$CC_BIN" -O2 -Wall -D_FILE_OFFSET_BITS=64 -o "bin/${bin_name}" \
        src/cli.c src/keychain.c src/cipher.c src/commit.c
    fi
    info "Running otp-toolkit's own test suite before installing..."
    if ! sh test/report.sh >/dev/null; then
      rm -f "bin/${bin_name}"
      exit 1
    fi
  ) || err "Compiling or testing otp-toolkit failed."

  [ -f "$src/bin/$bin_name" ] || err "otp-toolkit build did not produce bin/${bin_name}."
  install_binary "$src/bin/$bin_name" otp
  install_man_page "$src/otp.1"
}

compile_aloo() {
  local repo="$1" version="$2" workdir="$3"
  local url="https://github.com/${repo}.git"
  local src="$workdir/aloo"
  local bin_name="aloo"
  [ "$OS" = "windows" ] && bin_name="aloo.exe"

  info "Cloning ${url} (tag ${version})..."
  git clone --quiet --depth 1 --branch "$version" "$url" "$src" \
    || err "Failed to clone aloo at tag '${version}'."

  (
    cd "$src"
    info "Compiling aloo with 'cargo build --release' (this may take a while)..."
    cargo build --release
  ) || err "Compiling aloo failed."

  [ -f "$src/target/release/$bin_name" ] || err "cargo build did not produce target/release/${bin_name}."
  install_binary "$src/target/release/$bin_name" aloo
}

# ---------------------------------------------------------------------------
# Per-component install flow
# ---------------------------------------------------------------------------

process_component() {
  local name="$1" repo="$2" version="$3"

  info "== ${name} (${version}) [${INSTALL_MODE}] =="

  local -a existing=()
  while IFS= read -r line; do
    [ -n "$line" ] && existing+=("$line")
  done < <(find_existing "$name")

  if [ "${#existing[@]}" -gt 0 ]; then
    warn "'$name' is already installed at:"
    local p
    for p in "${existing[@]}"; do warn "  - $p"; done
    if ! confirm "Overwrite the existing '$name' installation(s) with ${version}?"; then
      info "Skipping '$name' (keeping existing installation)."
      return 0
    fi
    remove_paths "${existing[@]}"
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  NEED_CLEANUP+=("$tmpdir")

  if [ "$INSTALL_MODE" = "source" ]; then
    case "$name" in
      aloo) compile_aloo "$repo" "$version" "$tmpdir" ;;
      otp)  compile_otp  "$repo" "$version" "$tmpdir" ;;
    esac
    return 0
  fi

  pick_asset "$name" "$repo" "$version"

  local archive="$tmpdir/$ASSET_FILENAME"
  info "Downloading $ASSET_URL"
  fetch_to "$ASSET_URL" "$archive"

  local extracted="$tmpdir/extracted"
  mkdir -p "$extracted"
  extract_archive "$archive" "$extracted"

  local bin
  bin="$(find "$extracted" -type f \( -iname "$name" -o -iname "${name}.exe" \) | head -n1)"
  [ -n "$bin" ] || err "Could not locate the '$name' binary inside $ASSET_FILENAME."

  install_binary "$bin" "$name"
}

# ---------------------------------------------------------------------------
# ~/.aloo backup
# ---------------------------------------------------------------------------

backup_aloo_home() {
  local src="$HOME/.aloo"
  [ -d "$src" ] || return 0
  local dest="$HOME/.aloo-backup"
  if [ -e "$dest" ]; then
    dest="${dest}-$(date +%Y%m%d%H%M%S)"
  fi
  mv "$src" "$dest"
  warn "Existing ~/.aloo directory found and backed up to: $dest"
  warn "You can manually migrate your keys and settings back into ~/.aloo if needed."
}

# ---------------------------------------------------------------------------
# Emoji font support
#
# aloo's interface uses emoji. macOS (Apple Color Emoji) and Windows (Segoe
# UI Emoji) ship a working emoji font out of the box; most Linux/BSD systems
# don't, and need a package installed plus a font-cache refresh (e.g. on Arch
# that's `pacman -S noto-fonts-emoji && fc-cache -f`). This mirrors that
# across the package managers of the OSes aloo targets.
# ---------------------------------------------------------------------------

has_emoji_font() {
  need_cmd fc-list || return 1
  fc-list 2>/dev/null | grep -qiE 'emoji'
}

ensure_emoji_font() {
  case "$OS" in
    macos|windows) return 0 ;;
  esac
  [ "$SKIP_EMOJI_FONTS" = "1" ] && return 0
  has_emoji_font && return 0

  warn "No emoji-capable font detected. aloo's interface uses emoji and may show boxes/question marks without one."
  if ! confirm "Install an emoji font (Noto Color Emoji, or the closest equivalent) now?"; then
    info "Skipping emoji font installation. You can install one manually later."
    return 0
  fi

  local installed=0
  case "$OS" in
    linux)
      if need_cmd pacman; then
        ensure_sudo
        sudo pacman -Sy --needed --noconfirm noto-fonts-emoji && installed=1
      elif need_cmd apt-get; then
        ensure_sudo
        sudo apt-get update && sudo apt-get install -y fonts-noto-color-emoji && installed=1
      elif need_cmd dnf; then
        ensure_sudo
        sudo dnf install -y google-noto-emoji-color-fonts 2>/dev/null && installed=1
        [ "$installed" = "1" ] || { sudo dnf install -y google-noto-emoji-fonts && installed=1; }
      elif need_cmd yum; then
        ensure_sudo
        sudo yum install -y google-noto-emoji-color-fonts 2>/dev/null && installed=1
        [ "$installed" = "1" ] || { sudo yum install -y google-noto-emoji-fonts && installed=1; }
      elif need_cmd zypper; then
        ensure_sudo
        sudo zypper --non-interactive install noto-coloremoji-fonts && installed=1
      elif need_cmd apk; then
        ensure_sudo
        sudo apk add font-noto-emoji && installed=1
      else
        warn "Unrecognized Linux package manager; install an emoji font manually (e.g. Noto Color Emoji)."
      fi
      ;;
    freebsd)
      ensure_sudo
      sudo pkg install -y noto-emoji && installed=1
      ;;
    netbsd)
      if need_cmd pkgin; then
        ensure_sudo
        sudo pkgin -y install noto-emoji && installed=1
      else
        warn "pkgin not found; install an emoji font manually (e.g. noto-emoji from pkgsrc)."
      fi
      ;;
    openbsd)
      if need_cmd doas; then
        doas pkg_add noto-emoji && installed=1
      else
        ensure_sudo
        sudo pkg_add noto-emoji && installed=1
      fi
      ;;
  esac

  if [ "$installed" = "1" ]; then
    if need_cmd fc-cache; then
      info "Refreshing font cache..."
      fc-cache -f >/dev/null 2>&1 || true
    fi
    info "Emoji font installed. You may need to restart your terminal for it to take effect."
  else
    warn "Could not install an emoji font automatically. Install one manually (e.g. Noto Color Emoji) and run 'fc-cache -f'."
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  detect_os
  detect_arch
  choose_install_dir
  detect_can_compile

  info "Detected platform: ${OS}/${ARCH}"
  info "Install directory: ${INSTALL_DIR}"

  if [ -n "$INSTALL_MODE" ]; then
    case "$INSTALL_MODE" in
      binary|source) ;;
      *) err "Invalid install mode '$INSTALL_MODE' (expected 'binary' or 'source')." ;;
    esac
    if [ "$INSTALL_MODE" = "source" ] && [ "$CAN_COMPILE" != "1" ]; then
      err "Cannot compile from source, missing: ${MISSING_COMPILE_TOOLS[*]}"
    fi
  elif [ "$CAN_COMPILE" = "1" ]; then
    INSTALL_MODE="$(ask_install_mode)"
  else
    INSTALL_MODE="binary"
  fi
  info "Install mode: ${INSTALL_MODE}$([ "$INSTALL_MODE" = "source" ] && echo " (${CC_BIN}, cargo, git)")"

  backup_aloo_home

  process_component aloo "$ALOO_REPO" "$ALOO_VERSION"
  process_component otp  "$OTP_REPO"  "$OTP_VERSION"

  ensure_emoji_font

  PATH_NEEDS_RELOAD=0
  ensure_path_persisted

  info "Verifying installation:"
  local ok=1
  local name
  for name in aloo otp; do
    if command -v "$name" >/dev/null 2>&1; then
      info "  $name -> $(command -v "$name")"
    else
      warn "  $name was not found on PATH (it may have been skipped above)."
      ok=0
    fi
  done

  if [ "$PATH_NEEDS_RELOAD" = "1" ]; then
    warn "PATH was updated for future shells. To use 'aloo'/'otp' in THIS shell right now, run:"
    warn "  export PATH=\"$INSTALL_DIR:\$PATH\""
  fi

  if [ "$ok" = "1" ]; then
    info "Done. Both 'aloo' and 'otp' are installed."
  else
    warn "Done, with warnings above."
  fi
}

main "$@"
