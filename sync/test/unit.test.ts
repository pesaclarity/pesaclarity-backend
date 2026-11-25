import assert from "node:assert/strict";
import { test } from "node:test";

import { Ed25519LicenceVerifier } from "../src/licence.ts";
import { MIN_KEEP_MS, checkSignature, fromB64url, b64url, isPaddedSize, paddedSize } from "../src/protocol.ts";
import { RateLimiter } from "../src/ratelimit.ts";
import { expiredBatches } from "../src/retention.ts";
import { licence, newMember, sign } from "./client.ts";

test("base64url round trip", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(33));
  assert.deepEqual(fromB64url(b64url(bytes)), bytes);
});

test("size steps", () => {
  assert.equal(paddedSize(1), 1024);
  assert.equal(paddedSize(1025), 2048);
  assert.equal(paddedSize(1024 * 1024), 1024 * 1024);
  assert.equal(paddedSize(1024 * 1024 + 1), null);
  assert.ok(isPaddedSize(4096));
  assert.ok(!isPaddedSize(4097));
});

test("signature: good, forged, changed body, old clock", async () => {
  const m = await newMember();
  const other = await newMember();
  const body = new TextEncoder().encode("{}");
  const now = Date.now();
  const p = await sign(m, "POST", "/v1/spaces/x", body, now);
  assert.deepEqual(await checkSignature(p, "POST", "/v1/spaces/x", body, now), { ok: true });
  assert.equal((await checkSignature({ ...p, key: other.key }, "POST", "/v1/spaces/x", body, now)).ok, false);
  assert.equal((await checkSignature(p, "POST", "/v1/spaces/y", body, now)).ok, false);
  assert.equal((await checkSignature(p, "POST", "/v1/spaces/x", new Uint8Array([1]), now)).ok, false);
  assert.deepEqual(await checkSignature(p, "POST", "/v1/spaces/x", body, now + 6 * 60_000), { ok: false, why: "clock" });
});

test("licence verifier", async () => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const v = new Ed25519LicenceVerifier(pub);
  const now = Date.now();
  const good = await licence(pair.privateKey, now + 1000);
  assert.deepEqual(await v.verify(good, now), { ok: true, validUntil: now + 1000 });
  assert.deepEqual(await v.verify(good, now + 2000), { ok: false, why: "expired" });
  assert.deepEqual(await v.verify(await licence(pair.privateKey, now + 1000, ["business"]), now), { ok: false, why: "feature" });
  const forged = good.slice(0, -4) + (good.endsWith("AAAA") ? "BBBB" : "AAAA");
  assert.equal((await v.verify(forged, now)).ok, false);
  assert.deepEqual(await v.verify(good, now).then(() => new Ed25519LicenceVerifier("").verify(good, now)), {
    ok: false,
    why: "no_key",
  });
  assert.deepEqual(await v.verify("nonsense", now), { ok: false, why: "malformed" });
});

test("retention keeps batches until read by everyone and 90 days old", () => {
  const now = 1_000 * MIN_KEEP_MS;
  const old = now - MIN_KEEP_MS - 1;
  const batches = [
    { cursor: 1, id: "a", author: "A", recipient: null, at: old },
    { cursor: 2, id: "b", author: "A", recipient: "B", at: old },
    { cursor: 3, id: "c", author: "A", recipient: "C", at: old },
    { cursor: 4, id: "d", author: "A", recipient: null, at: now - 1000 },
    { cursor: 5, id: "e", author: "B", recipient: "Gone", at: old },
  ];
  const acked = new Map([
    ["A", 0],
    ["B", 4],
    ["C", 1],
  ]);
  const gone = expiredBatches(batches, acked, now).map((b) => b.id);
  // a: B and C pulled past 1; b: B pulled past; c: C has not; d: too new; e: recipient removed
  assert.deepEqual(gone, ["a", "b", "e"]);
});

test("rate limiter refills over time", () => {
  const r = new RateLimiter(2, 60);
  assert.ok(r.take("k", 0));
  assert.ok(r.take("k", 0));
  assert.ok(!r.take("k", 0));
  assert.ok(r.take("k", 1000));
  assert.ok(r.take("other", 0));
});
