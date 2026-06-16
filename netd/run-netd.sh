#!/usr/bin/env bash
# run-netd.sh — stand up the netd egress door from squid.conf (the NETD.md
# reference, made runnable). netd = an allowlist-only forward proxy (squid) +
# a socat bridge that exposes it as the unix-socket door the launcher forwards
# (`claude-box … --net <sock>`). The box has --network=none and reaches the
# outside ONLY through this socket; squid enforces the destination allowlist and
# fails closed. The production end-state (NETD.md) is this as a PINNED OCI image
# in the pod (prx-zj8); this script is the local/reference runner.
#
#   ./netd/run-netd.sh up      # start squid + socat; serve $NETD_SOCK
#   ./netd/run-netd.sh test    # prove allowed host works, off-allowlist refused
#   ./netd/run-netd.sh down     # tear it down
#
# Then:  NETD_SOCK=$NETD_SOCK claude-box work --net --repo .
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${HERE}/squid.conf"
# Private (0700) socket dir — the launcher refuses a world-writable dir (#7).
SOCK="${NETD_SOCK:-${XDG_RUNTIME_DIR:-${HOME}/.claude-box}/netd.sock}"
PROXY_PORT="${PROXY_PORT:-3128}"
# Pin this by digest for real use (NETD.md); :latest only makes the ref runnable.
SQUID_IMAGE="${SQUID_IMAGE:-docker.io/ubuntu/squid:latest}"

die() { printf '\033[31mnetd: %s\033[0m\n' "$*" >&2; exit 1; }

up() {
  command -v podman >/dev/null || die "podman not found"
  command -v socat  >/dev/null || die "socat not found (brew install socat)"
  [ -f "$CONF" ] || die "missing $CONF"

  # Precheck: netd can only forward what the HOST can reach. ANY HTTP status
  # (even 404 — api.anthropic.com/ has no homepage) proves egress works; only a
  # connection/DNS/TLS failure (curl code 000) means the host truly can't get out.
  if [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 https://api.anthropic.com 2>/dev/null || echo 000)" = "000" ]; then
    die "the HOST cannot reach api.anthropic.com (no response at all) — fix host/VM egress first (this is why the box sees 'poor internet')"
  fi

  mkdir -p "$(dirname "$SOCK")"; chmod 700 "$(dirname "$SOCK")"

  podman rm -f netd >/dev/null 2>&1 || true
  podman run -d --name netd \
    -v "${CONF}:/etc/squid/squid.conf:ro" \
    -p "127.0.0.1:${PROXY_PORT}:3128" \
    "$SQUID_IMAGE" >/dev/null
  echo "netd: squid up on 127.0.0.1:${PROXY_PORT}"

  # Wait for squid to accept proxied requests (any status back = tunnel works).
  for _ in $(seq 1 30); do
    [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -x "http://127.0.0.1:${PROXY_PORT}" https://api.anthropic.com 2>/dev/null || echo 000)" != "000" ] && break
    sleep 1
  done

  # Front it with the unix-socket door (kill any stale bridge first).
  pkill -f "UNIX-LISTEN:${SOCK}" 2>/dev/null || true
  rm -f "$SOCK"
  socat "UNIX-LISTEN:${SOCK},fork,reuseaddr" "TCP:127.0.0.1:${PROXY_PORT}" &
  echo "netd: door socket ready — NETD_SOCK=${SOCK}"
  echo "next:  NETD_SOCK=${SOCK} claude-box work --net --repo ."
}

# Prove the policy: allowed reachable, off-allowlist refused (the --net ocap cases).
test_() {
  local px="http://127.0.0.1:${PROXY_PORT}"
  printf 'allowed (api.anthropic.com): '
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -x "$px" https://api.anthropic.com || true)
  { [ -n "$code" ] && [ "$code" != "000" ]; } && echo "reachable ✓ ($code)" || echo "unreachable ✗ (BAD — should connect)"
  printf 'denied  (example.com):       '
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -x "$px" https://example.com || true)
  if [ "$code" = "403" ] || [ -z "$code" ] || [ "$code" = "000" ]; then
    echo "refused ✓ ($code)"
  else
    echo "REACHED ($code) — allowlist LEAKING, investigate squid.conf"
  fi
}

down() {
  podman rm -f netd >/dev/null 2>&1 || true
  pkill -f "UNIX-LISTEN:${SOCK}" 2>/dev/null || true
  rm -f "$SOCK"
  echo "netd: down"
}

case "${1:-up}" in
  up)   up ;;
  test) test_ ;;
  down) down ;;
  *) die "usage: run-netd.sh {up|test|down}" ;;
esac
