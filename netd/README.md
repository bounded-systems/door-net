# netd — reference egress daemon

A concrete, runnable starting point for the **netd** egress door specified in
[../NETD.md](../NETD.md): an **allowlist-only forward proxy** behind the box's
`/run/netd.sock` door. It is the network twin of keeperd (writes) / scout
(reads). **Status: reference — unverified in CI** (needs a running squid + the
pod); wire it into the pinned-image pod (`prx-zj8`) for real use.

## What's here

- [`netd.ts`](./netd.ts) — **the daemon** (recommended): a pinned `bun` process
  that enforces the destination allowlist via `CONNECT`, no TLS MITM, fails
  closed, audits every decision. Replaces the squid + socat + brew chain with one
  process. Run it `nix run .#netd -- serve` (door socket) or `nix run .#netd --
  serve --port 3128` (host/pod TCP). **Verified host-side** (allow tunnels, deny
  → refused); default allowlist `api.anthropic.com,.anthropic.com`, override with
  `NETD_ALLOW`.
- [`squid.conf`](./squid.conf) — the **alternative** reference (squid +
  [`run-netd.sh`](./run-netd.sh)). Same policy; heavier (a container + a socat
  bridge). On macOS its container tends to exit and the port hop is fragile —
  `netd.ts` avoids both by running as a plain host/pod process.

## Run it (reference)

netd = the proxy + a `socat` bridge that exposes it as the unix-socket door the
launcher forwards (`claude-box … --net <sock>` → `-v <sock>:/run/netd.sock`):

```sh
# 1) the allowlist proxy
podman run -d --name netd \
  -v "$PWD/netd/squid.conf:/etc/squid/squid.conf:ro" \
  -p 127.0.0.1:3128:3128 \
  docker.io/ubuntu/squid:latest

# 2) expose it as the door socket the box mounts (private dir, 0700 — #7)
mkdir -p "$XDG_RUNTIME_DIR" 2>/dev/null || true
socat UNIX-LISTEN:"${XDG_RUNTIME_DIR:?set XDG_RUNTIME_DIR}/netd.sock",fork,reuseaddr \
      TCP:127.0.0.1:3128 &

# 3) the box routes egress through the door
claude-box work --net --repo .     # api.anthropic.com works; evil.com refused
```

The in-box side needs nothing extra: the image entrypoint already relays
`127.0.0.1:3128 → /run/netd.sock`, and the launcher sets `HTTPS_PROXY`.

## Verifying (the ocap tests this satisfies)

With netd up, the `test.todo`s in `tests/ocap.test.ts` become assertable:

```
# in a --net box:
curl -sS https://api.anthropic.com/ -o /dev/null   # allowed (200/4xx, reachable)
curl -sS https://example.com/        -o /dev/null   # DENIED by netd (no route)
```

## Notes / caveats

- **No MITM by design** — squid only sees the CONNECT host (SNI), tunnels bytes;
  end-to-end TLS is preserved, so netd is a *destination gate*, not a wiretap.
- **macOS** — the unix-socket-over-virtiofs path into the podman-machine VM is
  flaky (see CAPABILITIES.md transport table); fall back to host-gateway TCP or
  `ssh -L` and point `NETD_SOCK` at the relayed path.
- **Production** — the NETD.md end-state is a *pinned OCI image* in the pod, not
  `:latest`; this README uses `:latest` only to make the reference runnable.
