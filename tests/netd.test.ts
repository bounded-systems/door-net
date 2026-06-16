/**
 * netd tests — allowlist and caveat enforcement.
 *
 * These are unit tests for the allowlist matching logic; they don't start the
 * actual proxy server. The live proxy is integration-tested in
 * tests/netd.proxy.test.ts (real listener + raw HTTP CONNECT).
 *
 *   nix run nixpkgs#bun -- test tests/netd.test.ts
 */
import { test, expect, describe } from "bun:test";

// The DEFAULT allowlist and its matcher come from the real module, so the
// regression test below pins the SHIPPED value rather than a re-declared copy.
import { DEFAULT_ALLOW, isAllowedByDefault } from "../netd/netd";

// We import the matching functions by evaluating them in a subprocess with
// controlled NETD_ALLOW and NETD_CAVEATS env vars, since they're module-level.
// For now, we test the pure logic inline.

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

/** Parse caveats from NETD_CAVEATS. Returns host patterns from host=... caveats. */
function parseCaveats(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((c) => {
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

/** Check if a host is allowed (must pass base allowlist AND caveats if present). */
function allowed(host: string, ALLOW: string[], CAVEATS: string[]): boolean {
  if (!matchesAny(host, ALLOW)) return false;
  if (CAVEATS.length > 0 && !matchesAny(host, CAVEATS)) return false;
  return true;
}

describe("matchesPattern", () => {
  test("exact match", () => {
    expect(matchesPattern("github.com", "github.com")).toBe(true);
    expect(matchesPattern("github.com", "gitlab.com")).toBe(false);
  });

  test("case insensitive", () => {
    expect(matchesPattern("GitHub.COM", "github.com")).toBe(true);
    expect(matchesPattern("github.com", "GITHUB.COM")).toBe(true);
  });

  test("suffix pattern matches apex and subdomains", () => {
    expect(matchesPattern("github.com", ".github.com")).toBe(true); // apex
    expect(matchesPattern("api.github.com", ".github.com")).toBe(true); // subdomain
    expect(matchesPattern("raw.githubusercontent.com", ".github.com")).toBe(false); // different domain
  });

  test("suffix pattern does not match partial names", () => {
    // notgithub.com should NOT match .github.com
    expect(matchesPattern("notgithub.com", ".github.com")).toBe(false);
    expect(matchesPattern("fakegithub.com", ".github.com")).toBe(false);
  });
});

describe("matchesAny", () => {
  test("matches against multiple patterns", () => {
    const patterns = ["api.anthropic.com", ".github.com"];
    expect(matchesAny("api.anthropic.com", patterns)).toBe(true);
    expect(matchesAny("github.com", patterns)).toBe(true);
    expect(matchesAny("api.github.com", patterns)).toBe(true);
    expect(matchesAny("evil.com", patterns)).toBe(false);
  });
});

describe("parseCaveats", () => {
  test("empty input returns empty array", () => {
    expect(parseCaveats(undefined)).toEqual([]);
    expect(parseCaveats("")).toEqual([]);
  });

  test("parses host= caveats", () => {
    expect(parseCaveats("host=github.com")).toEqual(["github.com"]);
    expect(parseCaveats("host=github.com,host=api.anthropic.com")).toEqual([
      "github.com",
      "api.anthropic.com",
    ]);
  });

  test("parses host: caveats (colon separator)", () => {
    expect(parseCaveats("host:github.com")).toEqual(["github.com"]);
  });

  test("ignores non-host caveats", () => {
    expect(parseCaveats("host=github.com,port=443,host=npm.org")).toEqual([
      "github.com",
      "npm.org",
    ]);
  });

  test("handles whitespace", () => {
    expect(parseCaveats("  host=github.com , host=npm.org  ")).toEqual([
      "github.com",
      "npm.org",
    ]);
  });
});

describe("default allowlist", () => {
  // Regression for issue #6 ("netd allowlist must exclude writable sinks").
  // Asserts against the SHIPPED DEFAULT_ALLOW (imported, not re-declared) that
  // the default-deny invariant holds: only Anthropic egress is permitted, and
  // every writable sink — where an agent could exfiltrate or persist data — is
  // refused. If someone widens DEFAULT_ALLOW to include a writable host, this
  // breaks.

  test("DEFAULT_ALLOW is Anthropic-only", () => {
    expect(DEFAULT_ALLOW).toEqual(["api.anthropic.com", ".anthropic.com"]);
  });

  test("ALLOWS Anthropic API and its subdomains", () => {
    expect(isAllowedByDefault("api.anthropic.com")).toBe(true);
    // .anthropic.com suffix covers subdomains like the console.
    expect(isAllowedByDefault("console.anthropic.com")).toBe(true);
  });

  test("DENIES writable sinks", () => {
    // Code hosting / gists — an agent could push or paste data here.
    expect(isAllowedByDefault("api.github.com")).toBe(false);
    expect(isAllowedByDefault("gist.github.com")).toBe(false);
    expect(isAllowedByDefault("objects.githubusercontent.com")).toBe(false);
    // Pastebins.
    expect(isAllowedByDefault("pastebin.com")).toBe(false);
    // Package registry — a publish target.
    expect(isAllowedByDefault("registry.npmjs.org")).toBe(false);
    // Generic untrusted host.
    expect(isAllowedByDefault("evil.com")).toBe(false);
  });
});

describe("allowed (with caveats)", () => {
  const ALLOW = ["api.anthropic.com", ".github.com", ".npmjs.org"];

  test("without caveats, respects base allowlist only", () => {
    expect(allowed("api.anthropic.com", ALLOW, [])).toBe(true);
    expect(allowed("github.com", ALLOW, [])).toBe(true);
    expect(allowed("api.github.com", ALLOW, [])).toBe(true);
    expect(allowed("evil.com", ALLOW, [])).toBe(false);
  });

  test("with caveats, narrows the allowlist", () => {
    const caveats = ["github.com", "api.github.com"];
    // In base allowlist AND in caveats → allowed
    expect(allowed("github.com", ALLOW, caveats)).toBe(true);
    expect(allowed("api.github.com", ALLOW, caveats)).toBe(true);
    // In base allowlist but NOT in caveats → denied
    expect(allowed("api.anthropic.com", ALLOW, caveats)).toBe(false);
    expect(allowed("registry.npmjs.org", ALLOW, caveats)).toBe(false);
  });

  test("caveats cannot widen beyond base allowlist", () => {
    // evil.com in caveats but not in base allowlist → still denied
    expect(allowed("evil.com", ALLOW, ["evil.com", "github.com"])).toBe(false);
  });

  test("caveats support suffix patterns too", () => {
    const caveats = [".github.com"]; // allow all github subdomains
    expect(allowed("github.com", ALLOW, caveats)).toBe(true);
    expect(allowed("api.github.com", ALLOW, caveats)).toBe(true);
    expect(allowed("raw.githubusercontent.com", ALLOW, caveats)).toBe(false); // not in base list anyway
    expect(allowed("api.anthropic.com", ALLOW, caveats)).toBe(false); // not in caveats
  });
});
