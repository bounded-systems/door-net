# door-net — the allowlist-egress capability door

`door-net` is **netd** packaged as a standalone, pinned OCI image. netd is the **only egress path**
for a box: the box runs `--network=none` and reaches the network solely through this door, a pinned
bun proxy that enforces a host allowlist (`NETD_ALLOW`, default `api.anthropic.com,.anthropic.com`).
Several reason-named instances can share one doors volume (`claude-netd`, `scout-netd`) via
`NETD_SOCK`. It's the egress half of the [claude-box](https://github.com/bounded-systems/claude-box)
door model (write: door-keeper; read: scoutd; resolution: concierged).

## Build / run

```sh
nix build .#netd-image && podman load -i result
podman run -v doors:/run/doors netd
```

`netd/run-netd.sh` wraps the macOS/podman-machine bring-up. `netd/squid.conf` is the original
squid+socat reference the pinned bun proxy replaced. Tests: `tests/netd.test.ts` (default
allowlist) + `tests/netd.proxy.test.ts` (proxy handlers).

## Pinned dependencies (vendored mirrors)

netd needs only the engine + the runtime helper (no provenance contract). Each is a PINNED input
and a generated mirror, kept honest by the `*-mirror` checks (`nix flake check`):

| Dir | Pinned input | Bump |
|---|---|---|
| `lib/runtime.ts` | [`door-kit`](https://github.com/bounded-systems/door-kit) `@a3ae40e` | `nix flake update door-kit` + `nix run .#sync-door-kit` |
| `guest-room/` | [`guest-room`](https://github.com/bounded-systems/guest-room) `@5bc85b6` | `nix flake update guest-room` + `nix run .#sync-guest-room` |

_Extracted from claude-box `netd/` — decomposition epic `prx-ii01`, card 2. (`peercred` is a
launcherd helper, not part of netd — it stays with the claude-room core.)_
