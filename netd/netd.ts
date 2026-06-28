#!/usr/bin/env bun
/**
 * netd.ts — allowlist-only egress proxy for the claude-box `--net` door.
 *
 * A pinned, nix-native replacement for the squid + socat reference: ONE bun
 * process that enforces a DESTINATION allowlist via HTTP CONNECT, with NO TLS
 * MITM (it only ever sees the host:port of the CONNECT line and tunnels raw
 * bytes — end-to-end TLS is preserved), FAILS CLOSED (anything not allowed →
 * 403), and AUDITS every decision. Contract: ../NETD.md.
 *
 *   nix run .#netd -- serve                     # listen on default socket
 *   nix run .#netd -- serve --socket /path.sock # custom socket path
 *   nix run .#netd -- serve --port 3128         # listen on TCP (for testing)
 *   NETD_ALLOW="api.anthropic.com,.anthropic.com" nix run .#netd -- serve
 *
 * Verify on a host (no container/VM needed):
 *   nix run .#netd -- serve --port 3128 &
 *   curl -x http://127.0.0.1:3128 https://api.anthropic.com   # allowed (tunnels)
 *   curl -x http://127.0.0.1:3128 https://example.com         # 403 (refused)
 *
 * In a pod (prx-zj8) it listens on the shared /run/netd.sock and the box reaches
 * it via the door; the door's host-socket-into-VM mount only works once netd and
 * the box are co-located in one runtime (a host unix socket cannot be bind-
 * mounted into the podman-machine VM on macOS — `statfs: operation not
 * supported`), which is exactly what the pod provides.
 */
import { connect, listen, type Socket } from "bun";
import { createPublicKey, verify as edVerify } from "node:crypto";

// Import shared daemon infrastructure
import {
  defaultSocketPath,
  prepareSocket,
  createLogger,
  call,
} from "../lib/runtime";
import { verifyGrantWithKeys, type IssuerKeys } from "../guest-room/mod.ts";

const log = createLogger("netd");

// ── Transit-grant gate (tcp/vsock only) ──────────────────────────────────────
// On a unix door the mounted socket IS authority (like scout/keeper's unix path).
// On tcp/vsock the kernel gives no peer identity, so a connecting client must
// present a SIGNED grant for the "net" door in the CONNECT's `Proxy-Authorization:
// Bearer <base64(grant)>` header — verified against the concierge's published keys
// (keyless, fetched + cached) before any tunnel opens. Set when serving tcp.
let grantRequired = false;

/** Whether the tcp/vsock serve path requires a signed grant. Default ON
 *  (fail-closed: an UNKNOWN remote netd must be granted — the transport-split
 *  rule for an untrusted peer). A LOCAL, co-located scoped netd the box reaches
 *  over the host loopback / pod gateway is trusted like a mount; it opts OUT with
 *  `NETD_REQUIRE_GRANT=0` (set by the launcher's `startScopedNetd`). Without the
 *  opt-out, a scoped netd would 407 the ungranted box it exists to serve. */
export function grantGateRequired(): boolean {
  return process.env.NETD_REQUIRE_GRANT !== "0";
}

function conciergeSocket(): string {
  if (process.env.CONCIERGE_SOCK) return process.env.CONCIERGE_SOCK;
  const runtime = process.env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/concierged.sock`;
  return `${process.env.HOME ?? "/tmp"}/.claude-box/concierged.sock`;
}

let issuerKeys: IssuerKeys | null = null;
async function fetchIssuerKeys(force = false): Promise<IssuerKeys> {
  if (issuerKeys && !force) return issuerKeys;
  issuerKeys = await call<IssuerKeys>(conciergeSocket(), "keys");
  return issuerKeys;
}

const grantVerifyWith = (data: string, signature: string, publicKeyPem: string): boolean =>
  edVerify(null, Buffer.from(data), createPublicKey(publicKeyPem), Buffer.from(signature, "base64"));

/** Test seams: drive the tcp grant gate without a live concierge. */
export function __setGrantRequired(v: boolean): void { grantRequired = v; }
export function __setIssuerKeys(k: IssuerKeys | null): void { issuerKeys = k; }

/** Case-insensitive HTTP header lookup from a request head. */
export function headerValue(headText: string, name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const line of headText.split("\r\n").slice(1)) {
    const i = line.indexOf(":");
    if (i > 0 && line.slice(0, i).trim().toLowerCase() === lower) return line.slice(i + 1).trim();
  }
  return undefined;
}

/** Verify the signed grant a tcp client presents (Proxy-Authorization: Bearer
 *  <base64 of the SignedGrant JSON>) for the "net" door. Re-fetches keys once on
 *  an unknown key (rotation). */
export async function verifyConnectGrant(authHeader: string | undefined): Promise<{ ok: boolean; reason?: string }> {
  if (!authHeader || !/^Bearer\s+/i.test(authHeader)) return { ok: false, reason: "no-grant" };
  let grant: { name?: string; binding?: unknown; signature?: string };
  try {
    grant = JSON.parse(Buffer.from(authHeader.replace(/^Bearer\s+/i, ""), "base64").toString("utf-8"));
  } catch {
    return { ok: false, reason: "malformed-grant" };
  }
  if (grant.name !== "net") return { ok: false, reason: "wrong-door" };
  const ctx = { audience: process.env.ROOM_ID ?? "", now: Date.now() };
  // deno-lint-ignore no-explicit-any
  let v = verifyGrantWithKeys(grant as any, ctx, await fetchIssuerKeys(), grantVerifyWith);
  if (!v.ok && v.reason === "unknown-key") {
    // deno-lint-ignore no-explicit-any
    v = verifyGrantWithKeys(grant as any, ctx, await fetchIssuerKeys(true), grantVerifyWith);
  }
  return v;
}

export const DEFAULT_ALLOW = ["api.anthropic.com", ".anthropic.com"];

/** Allowlist entry: exact host, or ".suffix" (matches the apex + any subdomain). */
function matchesPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  return p.startsWith(".") ? h === p.slice(1) || h.endsWith(p) : h === p;
}

/** Check if host matches any pattern in the list. */
function matchesAny(host: string, patterns: string[]): boolean {
  return patterns.some((p) => matchesPattern(host, p));
}

/**
 * Check a host against the built-in DEFAULT_ALLOW, ignoring any NETD_ALLOW /
 * NETD_CAVEATS env overrides. Pins the issue #6 invariant ("netd allowlist must
 * exclude writable sinks"): the default allowlist is Anthropic-only and must
 * default-deny writable sinks (github, gists, pastebins, npm registry, etc.).
 */
export function isAllowedByDefault(host: string): boolean {
  return matchesAny(host, DEFAULT_ALLOW);
}

/** Parse caveats from NETD_CAVEATS. Returns host patterns from host=... caveats. */
function parseCaveats(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((c) => {
      // Parse host=... or host:... caveats
      const eq = c.indexOf("=");
      const colon = c.indexOf(":");
      const sep = eq >= 0 && (colon < 0 || eq < colon) ? eq : colon;
      if (sep < 0) return null;
      const key = c.slice(0, sep);
      const val = c.slice(sep + 1);
      return key === "host" ? val : null;
    })
    .filter((h): h is string => h !== null);
}

/** Per-connection state: pre-tunnel header buffer, the upstream socket, tunnel flag. */
export type Cx = { head: Uint8Array; up?: Socket<unknown>; tunnel: boolean };

// Base allowlist from NETD_ALLOW (or default)
const ALLOW = (process.env.NETD_ALLOW?.split(",").map((s) => s.trim()).filter(Boolean) ?? [])
  .length
  ? process.env.NETD_ALLOW!.split(",").map((s) => s.trim()).filter(Boolean)
  : DEFAULT_ALLOW;

// Per-launch caveats from NETD_CAVEATS — narrows the allowlist
const CAVEATS = parseCaveats(process.env.NETD_CAVEATS);

/** Check if a host is allowed (must pass base allowlist AND caveats if present). */
function allowed(host: string): boolean {
  // Must be in the base allowlist
  if (!matchesAny(host, ALLOW)) return false;
  // If caveats present, must also match at least one caveat host
  if (CAVEATS.length > 0 && !matchesAny(host, CAVEATS)) return false;
  return true;
}

/** Parse the CONNECT request head and, if allowed, open the upstream tunnel. */
async function onHead(client: Socket<Cx>, headEnd: number): Promise<void> {
  const text = Buffer.from(client.data.head).toString("latin1");
  const leftover = client.data.head.slice(headEnd + 4); // bytes after \r\n\r\n
  const firstLine = text.slice(0, text.indexOf("\r\n"));
  const [method, target] = firstLine.split(" ");

  if (method !== "CONNECT") {
    log("DENY", `non-CONNECT ${method ?? "?"} ${target ?? ""}`);
    client.write("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
    client.end();
    return;
  }

  // Transit-grant gate (tcp/vsock only): no valid signed "net" grant ⇒ no tunnel.
  if (grantRequired) {
    const gate = await verifyConnectGrant(headerValue(text, "proxy-authorization"));
    if (!gate.ok) {
      log("DENY", `grant rejected: ${gate.reason}`);
      client.write(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer\r\nConnection: close\r\n\r\n",
      );
      client.end();
      return;
    }
  }

  const [host, portStr] = (target ?? "").split(":");
  const port = Number(portStr || "443");
  if (!host || !allowed(host)) {
    log("DENY", `${host ?? "?"}:${port}`);
    client.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    client.end();
    return;
  }

  connect({
    hostname: host,
    port,
    socket: {
      open(up) {
        client.data.up = up as Socket<unknown>;
        client.data.tunnel = true;
        log("ALLOW", `${host}:${port}`);
        client.write("HTTP/1.1 200 Connection established\r\n\r\n");
        if (leftover.length) up.write(leftover); // flush any early client bytes
      },
      data(_up, chunk) {
        client.write(chunk);
      },
      close() {
        client.end();
      },
      error(_up, e) {
        log("ERR", `upstream ${host}:${port} ${e}`);
        client.end();
      },
    },
  }).catch((e) => {
    log("ERR", `connect ${host}:${port} ${e}`);
    client.write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    client.end();
  });
}

/** Bun socket handlers for the proxy listener. Exported so the proxy can be
 *  driven in-process by tests (start with Bun.listen({ socket: handlers })). */
export const handlers = {
  open(client: Socket<Cx>) {
    client.data = { head: new Uint8Array(0), tunnel: false };
  },
  data(client: Socket<Cx>, chunk: Uint8Array) {
    if (client.data.tunnel) {
      client.data.up?.write(chunk); // raw passthrough once tunnelled
      return;
    }
    const merged = new Uint8Array(client.data.head.length + chunk.length);
    merged.set(client.data.head);
    merged.set(chunk, client.data.head.length);
    client.data.head = merged;
    const end = Buffer.from(merged).toString("latin1").indexOf("\r\n\r\n");
    if (end !== -1) onHead(client, end);
    else if (merged.length > 16384) client.end(); // oversized head → drop
  },
  close(client: Socket<Cx>) {
    client.data?.up?.end();
  },
  error(client: Socket<Cx>, e: Error) {
    log("ERR", `client ${e}`);
    client.data?.up?.end();
  },
};

// ── CLI ──────────────────────────────────────────────────────────────────────
// Aligned with keeperd/scoutd: `netd serve --socket PATH` (--unix kept as alias).
// Guarded by import.meta.main so importing this module (e.g. from tests) does
// not start a listener or process.exit on the test runner's argv.

function showUsage(): void {
  console.log(`netd — allowlist egress proxy for the claude-box --net door

Usage:
  netd serve                     start daemon (foreground, unix socket)
  netd serve --port PORT         listen on TCP (for host→VM relay)
  netd serve --socket PATH       custom socket path (--unix is alias)
  netd help                      show this help

Environment:
  NETD_SOCK      default unix socket path (fallback: ~/.claude-box/run/netd.sock)
  NETD_ALLOW     comma-separated allowlist (default: api.anthropic.com,.anthropic.com)
  NETD_CAVEATS   comma-separated caveats to narrow allowlist (e.g. host=github.com)
`);
}

const args = Bun.argv.slice(2);
const cmd = args[0];

if (!import.meta.main) {
  // Imported as a module (tests, other daemons) — skip the CLI dispatch.
} else if (cmd === "serve") {
  let socketPath = defaultSocketPath("netd");
  let port: number | undefined;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--socket" || args[i] === "-s" || args[i] === "--unix") {
      socketPath = args[++i]!;
    } else if (args[i] === "--port") {
      port = Number(args[++i]);
    }
  }
  const caveatInfo = CAVEATS.length ? ` caveats=${CAVEATS.join(",")}` : "";
  if (port) {
    // Bind to 0.0.0.0 so podman machine VM can reach us via host.containers.internal
    grantRequired = grantGateRequired(); // tcp/vsock has no kernel peer identity; gate unless a local scoped netd opts out
    listen<Cx>({ hostname: "0.0.0.0", port, socket: handlers });
    log("INFO", `listening tcp 0.0.0.0:${port} allow=${ALLOW.join(",")}${caveatInfo} (${grantRequired ? "signed-grant gate" : "no grant gate — local"}, allowlist fail-closed)`);
  } else {
    prepareSocket(socketPath);
    listen<Cx>({ unix: socketPath, socket: handlers });
    log("INFO", `listening unix ${socketPath} allow=${ALLOW.join(",")}${caveatInfo} (fail-closed)`);
  }
} else if (cmd === "help" || cmd === "--help" || cmd === "-h") {
  showUsage();
} else if (cmd === undefined) {
  // Backward compat: no subcommand → serve with legacy flag parsing
  let socketPath = defaultSocketPath("netd");
  let port: number | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--port") port = Number(args[++i]);
    else if (args[i] === "--unix" || args[i] === "--socket" || args[i] === "-s") socketPath = args[++i]!;
  }
  const caveatInfo = CAVEATS.length ? ` caveats=${CAVEATS.join(",")}` : "";
  if (port) {
    // Bind to 0.0.0.0 so podman machine VM can reach us via host.containers.internal
    grantRequired = grantGateRequired(); // tcp/vsock has no kernel peer identity; gate unless a local scoped netd opts out
    listen<Cx>({ hostname: "0.0.0.0", port, socket: handlers });
    log("INFO", `listening tcp 0.0.0.0:${port} allow=${ALLOW.join(",")}${caveatInfo} (${grantRequired ? "signed-grant gate" : "no grant gate — local"}, allowlist fail-closed)`);
  } else {
    prepareSocket(socketPath);
    listen<Cx>({ unix: socketPath, socket: handlers });
    log("INFO", `listening unix ${socketPath} allow=${ALLOW.join(",")}${caveatInfo} (fail-closed)`);
  }
} else {
  log("ERR", `unknown command "${cmd}"`);
  showUsage();
  process.exit(1);
}
