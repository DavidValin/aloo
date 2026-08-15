#!/bin/sh
# Builds `aloo --server` flags from ALOO_* env vars, then supervises the
# process with a capped exponential backoff restart on crash.
set -u

child_pid=""
stopping=0

on_term() {
    stopping=1
    [ -n "$child_pid" ] && kill -TERM "$child_pid" 2>/dev/null
}
trap on_term TERM INT

set -- --server
[ -n "${ALOO_PORT:-}" ] && set -- "$@" --port "$ALOO_PORT"
[ -n "${ALOO_BIND:-}" ] && set -- "$@" --bind "$ALOO_BIND"

if [ -n "${ALOO_PASSWORD:-}" ] && { [ -n "${ALOO_ENC_TYPE:-}" ] || [ -n "${ALOO_ENC_KEYFILE:-}" ]; }; then
    echo "aloo-server: set either ALOO_PASSWORD or ALOO_ENC_TYPE/ALOO_ENC_KEYFILE, not both" >&2
    exit 1
fi
if [ -n "${ALOO_PASSWORD:-}" ]; then
    set -- "$@" --password "$ALOO_PASSWORD"
elif [ -n "${ALOO_ENC_TYPE:-}" ] || [ -n "${ALOO_ENC_KEYFILE:-}" ]; then
    if [ -z "${ALOO_ENC_TYPE:-}" ] || [ -z "${ALOO_ENC_KEYFILE:-}" ]; then
        echo "aloo-server: ALOO_ENC_TYPE and ALOO_ENC_KEYFILE must both be set" >&2
        exit 1
    fi
    set -- "$@" --enc "$ALOO_ENC_TYPE" "$ALOO_ENC_KEYFILE"
fi

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
