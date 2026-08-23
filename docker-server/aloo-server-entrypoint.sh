#!/bin/sh
# Writes ~/.aloo/settings from ALOO_* env vars (TLS, registration, SMTP -
# none of which are `aloo --server` flags any more, only settings), runs
# any one-off `--register-user` accounts named by ALOO_REGISTER_USERS, then
# supervises `aloo --server --bind --port` with a capped exponential
# backoff restart on crash.
set -u

child_pid=""
stopping=0

on_term() {
    stopping=1
    [ -n "$child_pid" ] && kill -TERM "$child_pid" 2>/dev/null
}
trap on_term TERM INT

settings_dir="${HOME:-/home/aloo}/.aloo"
settings_file="$settings_dir/settings"
mkdir -p "$settings_dir"

# Merging write: replace a key's line if present, append it if not - the
# same "read what's there, edit only the named keys" rule
# `settings::Settings::update` follows, so a value nobody set here (or one
# `aloo --server` itself wrote, like `server_bind`) survives a restart.
set_setting() {
    key="$1"
    value="$2"
    touch "$settings_file"
    if grep -q "^${key}=" "$settings_file" 2>/dev/null; then
        sed -i "s#^${key}=.*#${key}=${value}#" "$settings_file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$settings_file"
    fi
}

if [ -n "${ALOO_SSL:-}" ]; then
    set_setting server_ssl "$ALOO_SSL"
    [ -n "${ALOO_SSL_FULLCHAIN:-}" ] && set_setting server_ssl_fullchain "$ALOO_SSL_FULLCHAIN"
    [ -n "${ALOO_SSL_PRIVKEY:-}" ] && set_setting server_ssl_privkey "$ALOO_SSL_PRIVKEY"
fi
if [ -n "${ALOO_ALLOW_REGISTRATION:-}" ]; then
    set_setting server_allow_registration "$ALOO_ALLOW_REGISTRATION"
    [ -n "${ALOO_SMTP_HOST:-}" ] && set_setting server_smtp_host "$ALOO_SMTP_HOST"
    [ -n "${ALOO_SMTP_PORT:-}" ] && set_setting server_smtp_port "$ALOO_SMTP_PORT"
    [ -n "${ALOO_SMTP_USERNAME:-}" ] && set_setting server_smtp_username "$ALOO_SMTP_USERNAME"
    [ -n "${ALOO_SMTP_PASSWORD:-}" ] && set_setting server_smtp_password "$ALOO_SMTP_PASSWORD"
    [ -n "${ALOO_ACTIVATION_PORT:-}" ] && set_setting server_activation_port "$ALOO_ACTIVATION_PORT"
    [ -n "${ALOO_ACTIVATION_URL:-}" ] && set_setting server_activation_url "$ALOO_ACTIVATION_URL"
fi

# One-off accounts, active immediately with no email: "alice:s3cret,bob:hunter2".
# Idempotent across restarts - registering a name that already exists in
# the mounted `~/.aloo/users` is refused, and that refusal is expected and
# ignored, not a startup failure.
if [ -n "${ALOO_REGISTER_USERS:-}" ]; then
    old_ifs="$IFS"
    IFS=','
    for pair in $ALOO_REGISTER_USERS; do
        nickname="${pair%%:*}"
        password="${pair#*:}"
        if [ -n "$nickname" ] && [ -n "$password" ] && [ "$nickname" != "$password" ]; then
            aloo --register-user "$nickname" "$password" 2>&1 | grep -v "already registered" || true
        fi
    done
    IFS="$old_ifs"
fi

set -- --server
[ -n "${ALOO_PORT:-}" ] && set -- "$@" --port "$ALOO_PORT"
[ -n "${ALOO_BIND:-}" ] && set -- "$@" --bind "$ALOO_BIND"

backoff=1
while [ "$stopping" -eq 0 ]; do
    aloo "$@" &
    child_pid=$!
    wait "$child_pid"
    status=$?
    child_pid=""

    [ "$stopping" -ne 0 ] && break

    if [ "$status" -eq 0 ]; then
        echo "aloo-server: exited cleanly, restarting" >&2
        backoff=1
    else
        echo "aloo-server: crashed (exit $status), restarting in ${backoff}s" >&2
        sleep "$backoff"
        [ "$backoff" -lt 30 ] && backoff=$((backoff * 2))
    fi
done

echo "aloo-server: received stop signal, shutting down" >&2
