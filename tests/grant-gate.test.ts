// grant-gate tests (prx-kdia) — netd's transit-grant gate on the tcp/vsock path.
// netd is an HTTP CONNECT proxy, so the grant rides where proxy auth belongs: a
// `Proxy-Authorization: Bearer <base64(SignedGrant JSON)>` header on the CONNECT.
// On unix the mounted socket is authority (gate off).
//
//   nix run nixpkgs#bun -- test tests/grant-gate.test.ts
import { test, expect, describe, beforeEach, afterAll } from "bun:test";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { signGrant, unix, type DoorGrant, type GrantBinding, type IssuerKeys, type SignedGrant } from "../guest-room/mod.ts";
import { verifyConnectGrant, headerValue, grantGateRequired, __setGrantRequired, __setIssuerKeys } from "../netd/netd.ts";

const kp = generateKeyPairSync("ed25519");
const pem = kp.publicKey.export({ type: "spki", format: "pem" }) as string;
const sign = (d: string): string => nodeSign(null, Buffer.from(d), kp.privateKey).toString("base64");
const keys: IssuerKeys = { keys: [{ kid: "k1", publicKeyPem: pem }] };

const netDoor: DoorGrant = {
  name: "net",
  host: unix("/tmp/netd.sock"),
  guest: unix("/run/doors/netd.sock"),
  env: "NETD_SOCK",
  grants: "policed egress",
  use: "egress via net",
};
const grant = (over: Partial<GrantBinding> = {}, door = netDoor): SignedGrant =>
  signGrant(door, { audience: "room-A", exp: Date.now() + 60_000, nonce: "n1", keyId: "k1", ...over }, sign);
const bearer = (g: SignedGrant): string => `Bearer ${Buffer.from(JSON.stringify(g)).toString("base64")}`;

beforeEach(() => {
  process.env.ROOM_ID = "room-A";
  __setGrantRequired(true);
  __setIssuerKeys(keys);
});
afterAll(() => __setGrantRequired(false));

describe("grantGateRequired — the tcp gate is default-on, locally opt-out", () => {
  const saved = process.env.NETD_REQUIRE_GRANT;
  afterAll(() => {
    if (saved === undefined) delete process.env.NETD_REQUIRE_GRANT;
    else process.env.NETD_REQUIRE_GRANT = saved;
  });
  test("default (unset) → gate ON (fail-closed for an unknown remote netd)", () => {
    delete process.env.NETD_REQUIRE_GRANT;
    expect(grantGateRequired()).toBe(true);
  });
  test("NETD_REQUIRE_GRANT=0 → gate OFF (a local scoped netd the box reaches over loopback)", () => {
    process.env.NETD_REQUIRE_GRANT = "0";
    expect(grantGateRequired()).toBe(false);
  });
  test("any other value → gate ON", () => {
    process.env.NETD_REQUIRE_GRANT = "1";
    expect(grantGateRequired()).toBe(true);
  });
});

describe("headerValue", () => {
  test("parses a header case-insensitively, skipping the request line", () => {
    const head = "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer abc\r\n\r\n";
    expect(headerValue(head, "proxy-authorization")).toBe("Bearer abc");
    expect(headerValue(head, "x-missing")).toBeUndefined();
  });
});

describe("verifyConnectGrant (tcp net gate)", () => {
  test("accepts a valid net grant for this room", async () => {
    expect(await verifyConnectGrant(bearer(grant()))).toEqual({ ok: true });
  });

  test("no Proxy-Authorization → no-grant", async () => {
    expect(await verifyConnectGrant(undefined)).toEqual({ ok: false, reason: "no-grant" });
  });

  test("a scout grant cannot open egress through net (wrong door)", async () => {
    const scout = grant({}, { ...netDoor, name: "scout" });
    expect(await verifyConnectGrant(bearer(scout))).toEqual({ ok: false, reason: "wrong-door" });
  });

  test("a grant for another room is rejected (audience)", async () => {
    expect((await verifyConnectGrant(bearer(grant({ audience: "room-B" })))).reason).toBe("audience-mismatch");
  });

  test("an expired grant is rejected", async () => {
    expect((await verifyConnectGrant(bearer(grant({ exp: Date.now() - 1_000 })))).reason).toBe("expired");
  });

  test("a malformed bearer is rejected, not crashed", async () => {
    expect((await verifyConnectGrant("Bearer not-base64-json")).ok).toBe(false);
  });
});
