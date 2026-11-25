// End to end against a real `celld dev` node: needs celld and esbuild on
// PATH (npm install puts esbuild in node_modules/.bin). Starts from a clean
// local state each run, with a licence key made for this run only.

import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { b64url } from "../src/protocol.ts";
import { call, licence, newMember, padded, randomId, sign, type Member } from "./client.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const port = 9800 + Math.floor(Math.random() * 150);
const base = `http://127.0.0.1:${port}`;
let node: ChildProcess;
let licenceKey: CryptoKey;

before(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  licenceKey = pair.privateKey;
  const pub = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  writeFileSync(join(root, ".dev.vars"), `LICENCE_PUBLIC_KEY=${pub}\n`);
  node = spawn("celld", ["dev", "--clean", "--no-watch", "--port", String(port)], {
    cwd: root,
    env: { ...process.env, PATH: `${join(root, "node_modules/.bin")}:${process.env.PATH}`, NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  node.stdout!.on("data", (d) => (log += d));
  node.stderr!.on("data", (d) => (log += d));
  for (let i = 0; i < 120; i++) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`celld dev did not start:\n${log}`);
});

after(() => {
  node?.kill("SIGTERM");
  rmSync(join(root, ".dev.vars"), { force: true });
});

/** Bucket objects of [space] in celld dev's local object store. */
function objectsOf(space: string): number {
  const db = new DatabaseSync(join(root, ".celld/dev/objects.sqlite3"), { readOnly: true });
  try {
    const row = db.prepare("SELECT COUNT(*) AS n FROM objects WHERE key LIKE ?").get(`r2/%/spaces/${space}/%`) as { n: number };
    return row.n;
  } finally {
    db.close();
  }
}

async function newSpace(owner: Member, exp = Date.now() + 365 * 86_400_000) {
  const id = randomId();
  const r = await call(base, owner, "POST", `/v1/spaces/${id}`, { body: { licence: await licence(licenceKey, exp) } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return id;
}

const push = (m: Member, space: string, body: Uint8Array, id = randomId(), to?: string) =>
  call(base, m, "POST", `/v1/spaces/${space}/batches`, {
    body,
    headers: { "x-pc-batch": id, ...(to ? { "x-pc-to": to } : {}) },
  });

const pull = (m: Member, space: string, since = 0) => call(base, m, "GET", `/v1/spaces/${space}/batches?since=${since}`);

test("two members push and pull; live notify over WebSocket", async () => {
  const owner = await newMember();
  const jane = await newMember();
  const space = await newSpace(owner);
  assert.equal((await call(base, owner, "PUT", `/v1/spaces/${space}/members/${jane.key}`)).status, 201);

  // Jane listens.
  const path = `/v1/spaces/${space}/ws`;
  const p = await sign(jane, "GET", path, new Uint8Array());
  const ws = new WebSocket(`ws://127.0.0.1:${port}${path}?key=${p.key}&t=${p.time}&n=${p.nonce}&sig=${p.sig}`);
  await new Promise((ok, no) => {
    ws.onopen = ok;
    ws.onerror = no;
  });
  const heard = new Promise<any>((ok) => (ws.onmessage = (e) => ok(JSON.parse(String(e.data)))));

  const id = randomId();
  const first = await push(owner, space, padded(2048, 1), id, jane.key);
  assert.equal(first.status, 201);
  assert.equal((await heard).cursor, first.data.cursor);
  ws.close();

  // Same id and bytes again: the same cursor, not a second batch.
  const again = await push(owner, space, padded(2048, 1), id, jane.key);
  assert.equal(again.status, 200);
  assert.deepEqual(again.data, { cursor: first.data.cursor, duplicate: true });
  // Same id, other bytes: refused.
  assert.equal((await push(owner, space, padded(2048, 2), id, jane.key)).status, 409);

  assert.equal((await push(jane, space, padded(1024, 3))).status, 201);

  const janes = await pull(jane, space);
  assert.equal(janes.status, 200);
  assert.equal(janes.data.batches.length, 1);
  assert.equal(janes.data.batches[0].id, id);
  assert.equal(janes.data.batches[0].from, owner.key);
  assert.equal(Buffer.from(janes.data.batches[0].data, "base64url").length, 2048);

  const owners = await pull(owner, space);
  assert.equal(owners.data.batches.length, 1);
  assert.equal(owners.data.batches[0].from, jane.key);
  // Nothing new after the cursor.
  assert.equal((await pull(owner, space, owners.data.next)).data.batches.length, 0);

  // Unpadded sizes are refused.
  assert.equal((await push(jane, space, new Uint8Array(1000))).data.error, "not_padded");
});

test("forged, replayed and stale requests are refused", async () => {
  const owner = await newMember();
  const mallory = await newMember();
  const space = await newSpace(owner);

  // Mallory signs with her own key but claims the owner's.
  const forged = await call(base, mallory, "GET", `/v1/spaces/${space}/batches?since=0`, {
    tamper: (p) => (p.key = owner.key),
  });
  assert.equal(forged.status, 401);

  // A non-member with a good signature.
  assert.equal((await pull(mallory, space)).status, 403);

  // The same signed request twice.
  const once = await pull(owner, space);
  assert.equal(once.status, 200);
  const replay = await call(base, owner, "GET", `/v1/spaces/${space}/batches?since=0`, { reuse: once.signed });
  assert.equal(replay.data.error, "replay");

  // Ten minutes old.
  const stale = await call(base, owner, "GET", `/v1/spaces/${space}/batches?since=0`, { time: Date.now() - 600_000 });
  assert.equal(stale.data.error, "clock");

  // Only the owner changes members.
  const m = await newMember();
  assert.equal((await call(base, owner, "PUT", `/v1/spaces/${space}/members/${m.key}`)).status, 201);
  assert.equal((await call(base, m, "PUT", `/v1/spaces/${space}/members/${mallory.key}`)).data.error, "not_owner");

  // A space needs a licence signed with our key.
  const fake = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const bad = await call(base, owner, "POST", `/v1/spaces/${randomId()}`, {
    body: { licence: await licence(fake.privateKey, Date.now() + 86_400_000) },
  });
  assert.equal(bad.status, 402);
  assert.equal(bad.data.error, "licence_signature");
});

test("a removed member is refused", async () => {
  const owner = await newMember();
  const jane = await newMember();
  const space = await newSpace(owner);
  await call(base, owner, "PUT", `/v1/spaces/${space}/members/${jane.key}`);
  assert.equal((await push(jane, space, padded(1024))).status, 201);
  assert.equal((await call(base, owner, "DELETE", `/v1/spaces/${space}/members/${jane.key}`)).status, 200);
  assert.equal((await push(jane, space, padded(1024))).data.error, "not_member");
  assert.equal((await pull(jane, space)).data.error, "not_member");
  // The owner cannot be removed.
  assert.equal((await call(base, owner, "DELETE", `/v1/spaces/${space}/members/${owner.key}`)).status, 409);
});

test("an expired licence makes the space read-only; renewal opens it", async () => {
  const owner = await newMember();
  const jane = await newMember();
  const space = await newSpace(owner, Date.now() + 3000);
  await call(base, owner, "PUT", `/v1/spaces/${space}/members/${jane.key}`);
  assert.equal((await push(owner, space, padded(1024))).status, 201);
  await new Promise((r) => setTimeout(r, 3500));

  const refused = await push(owner, space, padded(1024));
  assert.equal(refused.status, 403);
  assert.equal(refused.data.error, "read_only");
  const pulled = await pull(jane, space);
  assert.equal(pulled.status, 200);
  assert.equal(pulled.data.batches.length, 1);
  assert.equal(pulled.data.readOnly, true);

  // An expired licence is not accepted as a renewal.
  const stillOld = await call(base, owner, "PUT", `/v1/spaces/${space}/licence`, {
    body: { licence: await licence(licenceKey, Date.now() - 1) },
  });
  assert.equal(stillOld.data.error, "licence_expired");
  const renewed = await call(base, owner, "PUT", `/v1/spaces/${space}/licence`, {
    body: { licence: await licence(licenceKey, Date.now() + 86_400_000) },
  });
  assert.equal(renewed.status, 200);
  assert.equal((await push(owner, space, padded(1024))).status, 201);
});

test("deleting a space removes the cell's data and its bucket objects", async () => {
  const owner = await newMember();
  const jane = await newMember();
  const space = await newSpace(owner);
  await call(base, owner, "PUT", `/v1/spaces/${space}/members/${jane.key}`);
  await push(owner, space, padded(1024));
  await push(owner, space, padded(4096));

  assert.equal(objectsOf(space), 2);
  assert.equal((await call(base, jane, "DELETE", `/v1/spaces/${space}`)).data.error, "not_owner");
  assert.equal((await call(base, owner, "DELETE", `/v1/spaces/${space}`)).status, 200);
  assert.equal(objectsOf(space), 0);
  assert.equal((await pull(jane, space)).data.error, "not_found");
  assert.equal((await pull(owner, space)).data.error, "not_found");
  // The id can be used again from scratch: nothing of the old space is left.
  const r = await call(base, owner, "POST", `/v1/spaces/${space}`, {
    body: { licence: await licence(licenceKey, Date.now() + 86_400_000) },
  });
  assert.equal(r.status, 201);
  const fresh = await call(base, owner, "GET", `/v1/spaces/${space}`);
  assert.deepEqual(fresh.data.members, [owner.key]);
  assert.equal(fresh.data.cursor, 0);
});

test("pushes are rate limited", async () => {
  const owner = await newMember();
  const space = await newSpace(owner);
  let limited = false;
  for (let i = 0; i < 40 && !limited; i++) {
    limited = (await push(owner, space, padded(1024))).status === 429;
  }
  assert.ok(limited);
});
