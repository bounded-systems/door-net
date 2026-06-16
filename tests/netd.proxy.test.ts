/**
 * netd proxy — integration tests that drive the REAL proxy end-to-end.
 *
 * Unlike netd.test.ts (which unit-tests the pure matcher functions), this file
 * starts an actual listener using netd's exported `handlers` and speaks raw
 * HTTP CONNECT to it over a TCP socket. It is the end-to-end teeth behind the
 * issue #6 invariant ("netd allowlist must exclude writable sinks"): a writable
 * sink must get a 403 from the LIVE proxy, not merely fail a unit matcher.
 *
 * The listener enforces the module's effective allowlist, which equals
 * DEFAULT_ALLOW when NETD_ALLOW / NETD_CAVEATS are unset (the default CI
 * environment). The allowed-host probe opens a real TCP connection to
 * api.anthropic.com — an established convention in this repo (see
 * tests/ocap.test.ts) — and degrades gracefully offline (502 instead of 200);
 * either way it is NOT a 403, which is what proves the allow gate let it through.
 *
 *   nix run nixpkgs#bun -- test tests/netd.proxy.test.ts
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { handlers, DEFAULT_ALLOW } from "../netd/netd";

// These tests assume the default allowlist is in force. If the environment
// overrides it, the in-process listener would enforce a different set.
const DEFAULT_ALLOWLIST_IN_FORCE = !process.env.NETD_ALLOW && !process.env.NETD_CAVEATS;

let proxyPort = 0;
let listener: { port: number; stop: (closeActive?: boolean) => void } | undefined;

beforeAll(() => {
  // Ephemeral port; handlers enforce the module's effective allowlist.
  listener = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: handlers as never }) as {
    port: number;
    stop: (closeActive?: boolean) => void;
  };
  proxyPort = listener!.port;
});

afterAll(() => {
  listener?.stop(true);
});

/** First status code returned by the proxy for a raw request line. */
function statusCode(line: string): number {
  const m = line.match(/^HTTP\/1\.1 (\d{3})/);
  return m ? Number(m[1]) : 0;
}

/** Send a raw request to the proxy and resolve with its first response line. */
function proxyRequest(request: string, timeoutMs = 8000): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new Error(`proxy timed out: ${request.split("\r\n")[0]}`))),
      timeoutMs,
    );
    Bun.connect({
      hostname: "127.0.0.1",
      port: proxyPort,
      socket: {
        open(s) {
          s.write(request);
        },
        data(s, chunk) {
          buf += Buffer.from(chunk).toString("latin1");
          const nl = buf.indexOf("\r\n");
          if (nl !== -1) {
            const line = buf.slice(0, nl);
            s.end();
            finish(() => resolve(line));
          }
        },
        error(_s, e) {
          finish(() => reject(e));
        },
      },
    }).catch((e) => finish(() => reject(e)));
  });
}

const connect = (host: string, port = 443) =>
  proxyRequest(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);

describe("netd proxy (integration, default allowlist)", () => {
  test("default allowlist is in force for these tests", () => {
    expect(DEFAULT_ALLOWLIST_IN_FORCE).toBe(true);
    expect(DEFAULT_ALLOW).toEqual(["api.anthropic.com", ".anthropic.com"]);
  });

  // The issue #6 invariant, end-to-end: every writable sink is refused by the
  // live proxy with a 403, not merely denied by the unit matcher.
  test.each([
    "api.github.com",
    "gist.github.com",
    "objects.githubusercontent.com",
    "pastebin.com",
    "registry.npmjs.org",
    "evil.com",
  ])("DENIES writable sink %s with 403", async (host) => {
    expect(statusCode(await connect(host))).toBe(403);
  });

  test("rejects non-CONNECT methods with 405", async () => {
    const line = await proxyRequest("GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n");
    expect(statusCode(line)).toBe(405);
  });

  test("ALLOWS api.anthropic.com through the gate (not 403)", async () => {
    // Allowed → the proxy opens an upstream tunnel: 200 when egress is available,
    // 502 when the TCP connect is blocked (offline CI). Crucially never 403.
    const code = statusCode(await connect("api.anthropic.com"));
    expect(code).not.toBe(403);
    expect([200, 502]).toContain(code);
  });
});
