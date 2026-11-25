// One cell per shared space (decision 0033). It keeps the member keys, the
// list of change batches and each member's cursor in its own SQLite
// database; the batches themselves are ciphertext in the bucket. It has no
// keys and cannot read them. Merging happens on the phones.

import { Ed25519LicenceVerifier, type LicenceVerifier } from "./licence.ts";
import {
  H,
  MAX_MEMBERS,
  PULL_MAX_BATCHES,
  PULL_MAX_BYTES,
  b64url,
  checkSignature,
  isId,
  isKey,
  isPaddedSize,
  MAX_BATCH_BYTES,
  sha256,
  type SignedParts,
} from "./protocol.ts";
import { RateLimiter } from "./ratelimit.ts";
import { expiredBatches, type BatchRow } from "./retention.ts";

export interface Env {
  SPACES: DurableObjectNamespace;
  BATCHES: R2Bucket;
  LICENCE_PUBLIC_KEY?: string;
}

const DAY_MS = 24 * 60 * 60_000;

const json = (body: unknown, status = 200) => Response.json(body, { status });
const fail = (status: number, error: string) => json({ error }, status);

class Refused extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export class SpaceCell implements DurableObject {
  private readonly sql: SqlStorage;
  private readonly licences: LicenceVerifier;
  // Per member key: requests in general, and pushes.
  private readonly requests = new RateLimiter(120, 120);
  private readonly pushes = new RateLimiter(30, 30);

  private readonly ctx: DurableObjectState;
  private readonly env: Env;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    this.env = env;
    this.sql = ctx.storage.sql;
    this.licences = new Ed25519LicenceVerifier(env.LICENCE_PUBLIC_KEY);
    this.schema();
    // Pings answer themselves, so an idle socket never wakes the cell.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  // ------------------------------------------------------------ state

  private schema() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS members (
        key TEXT PRIMARY KEY, added_at INTEGER NOT NULL, acked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS batches (
        cursor INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
        author TEXT NOT NULL, recipient TEXT, size INTEGER NOT NULL,
        hash TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS nonces (n TEXT PRIMARY KEY, exp INTEGER NOT NULL);
    `);
  }

  private meta(k: string): string | null {
    const rows = this.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = ?", k).toArray();
    return rows.length ? rows[0].v : null;
  }

  private setMeta(k: string, v: string) {
    this.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, v);
  }

  private isMember(key: string): boolean {
    return this.sql.exec("SELECT 1 FROM members WHERE key = ?", key).toArray().length > 0;
  }

  private readOnly(now: number): boolean {
    return Number(this.meta("valid_until") ?? 0) <= now;
  }

  private objectKey(batchId: string): string {
    return `spaces/${this.meta("space")}/batches/${batchId}`;
  }

  // ------------------------------------------------------------ auth

  /** Checks the signature, clock and nonce; returns the signer's key. */
  private async authenticate(parts: SignedParts, method: string, path: string, body: Uint8Array) {
    const now = Date.now();
    const check = await checkSignature(parts, method, path, body, now);
    if (!check.ok) throw new Refused(401, check.why === "clock" ? "clock" : "unauthorized");
    this.sql.exec("DELETE FROM nonces WHERE exp < ?", now);
    const seen = this.sql.exec("SELECT 1 FROM nonces WHERE n = ?", parts.nonce).toArray().length;
    if (seen) throw new Refused(401, "replay");
    // Kept until the request could no longer pass the clock check.
    this.sql.exec("INSERT INTO nonces (n, exp) VALUES (?, ?)", parts.nonce, Number(parts.time) + 5 * 60_000 + 1);
    if (!this.requests.take(parts.key, now)) throw new Refused(429, "rate_limited");
    return parts.key;
  }

  private requireSpace() {
    if (this.meta("owner") === null) throw new Refused(404, "not_found");
  }

  private requireMember(key: string) {
    this.requireSpace();
    if (!this.isMember(key)) throw new Refused(403, "not_member");
  }

  private requireOwner(key: string) {
    this.requireSpace();
    if (this.meta("owner") !== key) throw new Refused(403, "not_owner");
  }

  // ------------------------------------------------------------ routes

  async fetch(request: Request): Promise<Response> {
    try {
      return await this.route(request);
    } catch (e) {
      if (e instanceof Refused) return fail(e.status, e.code);
      // No request details in logs: ids and outcomes only.
      console.error("cell error", e instanceof Error ? e.name : "unknown");
      return fail(500, "server_error");
    }
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const space = request.headers.get("x-pc-space") ?? "";
    const rest = url.pathname.slice(`/v1/spaces/${space}`.length);
    const method = request.method;

    if (rest === "/ws" && method === "GET") return this.openSocket(request, url);

    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length > MAX_BATCH_BYTES + 1024) throw new Refused(413, "too_large");
    const parts: SignedParts = {
      key: request.headers.get(H.key) ?? "",
      time: request.headers.get(H.time) ?? "",
      nonce: request.headers.get(H.nonce) ?? "",
      sig: request.headers.get(H.sig) ?? "",
    };
    const signer = await this.authenticate(parts, method, url.pathname + url.search, body);

    if (rest === "" && method === "POST") return this.create(space, signer, body);
    if (rest === "" && method === "GET") return this.status(signer);
    if (rest === "" && method === "DELETE") return this.remove(signer);
    if (rest === "/licence" && method === "PUT") return this.renew(signer, body);
    if (rest === "/batches" && method === "POST") return this.push(signer, request, body);
    if (rest === "/batches" && method === "GET") return this.pull(signer, url);
    const member = /^\/members\/([A-Za-z0-9_-]{43})$/.exec(rest);
    if (member && method === "PUT") return this.addMember(signer, member[1]);
    if (member && method === "DELETE") return this.removeMember(signer, member[1]);
    throw new Refused(404, "not_found");
  }

  private parse(body: Uint8Array): Record<string, unknown> {
    try {
      const v = JSON.parse(new TextDecoder().decode(body));
      if (v && typeof v === "object" && !Array.isArray(v)) return v;
    } catch {
      // fall through
    }
    throw new Refused(400, "bad_request");
  }

  private async checkLicence(token: unknown, now: number): Promise<number> {
    const result = await this.licences.verify(String(token ?? ""), now);
    if (!result.ok) throw new Refused(402, `licence_${result.why}`);
    return result.validUntil;
  }

  /** The owner makes the space with their licence; they are its first member. */
  private async create(space: string, owner: string, body: Uint8Array) {
    if (this.meta("owner") !== null) throw new Refused(409, "exists");
    const now = Date.now();
    const validUntil = await this.checkLicence(this.parse(body).licence, now);
    this.setMeta("space", space);
    this.setMeta("owner", owner);
    this.setMeta("valid_until", String(validUntil));
    this.sql.exec("INSERT INTO members (key, added_at) VALUES (?, ?)", owner, now);
    await this.ctx.storage.setAlarm(now + DAY_MS);
    return json({ space, validUntil }, 201);
  }

  private status(key: string) {
    this.requireMember(key);
    const now = Date.now();
    const last = this.sql.exec<{ c: number | null }>("SELECT MAX(cursor) AS c FROM batches").one().c ?? 0;
    return json({
      owner: this.meta("owner"),
      members: this.sql.exec<{ key: string }>("SELECT key FROM members ORDER BY added_at").toArray().map((r) => r.key),
      validUntil: Number(this.meta("valid_until")),
      readOnly: this.readOnly(now),
      cursor: last,
    });
  }

  private async renew(owner: string, body: Uint8Array) {
    this.requireOwner(owner);
    const validUntil = await this.checkLicence(this.parse(body).licence, Date.now());
    if (validUntil > Number(this.meta("valid_until"))) this.setMeta("valid_until", String(validUntil));
    return json({ validUntil: Number(this.meta("valid_until")) });
  }

  private addMember(owner: string, key: string) {
    this.requireOwner(owner);
    if (this.readOnly(Date.now())) throw new Refused(403, "read_only");
    if (this.isMember(key)) return json({ added: false });
    const count = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM members").one().n;
    if (count >= MAX_MEMBERS) throw new Refused(409, "space_full");
    // A new member starts at the latest cursor: older batches were sealed to
    // the others, and the owner's phone sends them what they need.
    const last = this.sql.exec<{ c: number | null }>("SELECT MAX(cursor) AS c FROM batches").one().c ?? 0;
    this.sql.exec("INSERT INTO members (key, added_at, acked) VALUES (?, ?, ?)", key, Date.now(), last);
    return json({ added: true, cursor: last }, 201);
  }

  /** Allowed even when read-only: the owner can always take someone out. */
  private removeMember(owner: string, key: string) {
    this.requireOwner(owner);
    if (key === owner) throw new Refused(409, "owner_stays");
    this.sql.exec("DELETE FROM members WHERE key = ?", key);
    for (const ws of this.ctx.getWebSockets(key)) ws.close(4003, "removed");
    return json({ removed: true });
  }

  private async push(author: string, request: Request, body: Uint8Array) {
    this.requireMember(author);
    const now = Date.now();
    if (this.readOnly(now)) throw new Refused(403, "read_only");
    if (!this.pushes.take(author, now)) throw new Refused(429, "rate_limited");
    const id = request.headers.get("x-pc-batch");
    const to = request.headers.get("x-pc-to");
    if (!isId(id)) throw new Refused(400, "bad_batch_id");
    if (to !== null && (!isKey(to) || !this.isMember(to))) throw new Refused(400, "bad_recipient");
    if (!isPaddedSize(body.length)) throw new Refused(400, "not_padded");
    const hash = await sha256(body);

    const existing = this.sql
      .exec<{ cursor: number; author: string; hash: string }>("SELECT cursor, author, hash FROM batches WHERE id = ?", id)
      .toArray();
    if (existing.length) {
      const e = existing[0];
      if (e.author !== author || e.hash !== hash) throw new Refused(409, "batch_id_taken");
      return json({ cursor: e.cursor, duplicate: true });
    }

    // Bucket first: a row never points at a missing object. An object left
    // by a failed insert goes with the space's prefix on delete.
    await this.env.BATCHES.put(this.objectKey(id), body);
    const cursor = this.sql
      .exec<{ cursor: number }>(
        "INSERT INTO batches (id, author, recipient, size, hash, at) VALUES (?, ?, ?, ?, ?, ?) RETURNING cursor",
        id,
        author,
        to,
        body.length,
        hash,
        now,
      )
      .one().cursor;

    const note = JSON.stringify({ type: "batch", cursor });
    for (const ws of this.ctx.getWebSockets()) {
      const [tag] = this.ctx.getTags(ws);
      if (tag === author || (to !== null && tag !== to)) continue;
      try {
        ws.send(note);
      } catch {
        // a closing socket; the phone pulls next time
      }
    }
    return json({ cursor, duplicate: false }, 201);
  }

  /** Everything for [key] after `since`. Asking from `since` also says the
   *  member holds everything up to it, which retention counts on. */
  private async pull(key: string, url: URL) {
    this.requireMember(key);
    const since = Number(url.searchParams.get("since") ?? "0");
    if (!Number.isSafeInteger(since) || since < 0) throw new Refused(400, "bad_cursor");
    this.sql.exec("UPDATE members SET acked = MAX(acked, ?) WHERE key = ?", since, key);
    const rows = this.sql
      .exec<BatchRow & { size: number }>(
        `SELECT cursor, id, author, recipient, size, at FROM batches
         WHERE cursor > ? AND author != ? AND (recipient IS NULL OR recipient = ?)
         ORDER BY cursor LIMIT ?`,
        since,
        key,
        key,
        PULL_MAX_BATCHES + 1,
      )
      .toArray();
    const out = [];
    let bytes = 0;
    for (const r of rows.slice(0, PULL_MAX_BATCHES)) {
      if (out.length && bytes + r.size > PULL_MAX_BYTES) break;
      const obj = await this.env.BATCHES.get(this.objectKey(r.id));
      if (!obj) continue; // removed by retention after this query; never expected
      bytes += r.size;
      out.push({
        cursor: r.cursor,
        id: r.id,
        from: r.author,
        at: r.at,
        data: b64url(new Uint8Array(await obj.arrayBuffer())),
      });
    }
    const more = out.length < rows.length;
    const last = this.sql.exec<{ c: number | null }>("SELECT MAX(cursor) AS c FROM batches").one().c ?? 0;
    return json({
      batches: out,
      // With nothing left for this member, the cursor jumps past others' batches.
      next: more ? out[out.length - 1].cursor : Math.max(since, last),
      more,
      readOnly: this.readOnly(Date.now()),
    });
  }

  /** The owner deletes the space: every bucket object, then the cell's data. */
  private async remove(owner: string) {
    this.requireOwner(owner);
    await this.deleteObjects(`spaces/${this.meta("space")}/`);
    for (const ws of this.ctx.getWebSockets()) ws.close(4004, "deleted");
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
    this.schema(); // an empty cell again, as if never made
    return json({ deleted: true });
  }

  private async deleteObjects(prefix: string) {
    for (;;) {
      const list = await this.env.BATCHES.list({ prefix, limit: 1000 });
      if (list.objects.length) await this.env.BATCHES.delete(list.objects.map((o) => o.key));
      if (!list.truncated) break;
    }
  }

  // ------------------------------------------------------------ live

  private async openSocket(request: Request, url: URL): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") throw new Refused(426, "upgrade");
    const q = url.searchParams;
    const parts: SignedParts = {
      key: q.get("key") ?? "",
      time: q.get("t") ?? "",
      nonce: q.get("n") ?? "",
      sig: q.get("sig") ?? "",
    };
    // Signed over the path alone: the query carries the signature itself.
    const key = await this.authenticate(parts, "GET", url.pathname, new Uint8Array());
    this.requireMember(key);
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1], [key]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  webSocketMessage(): void {
    // Phones only listen; "ping" is answered without waking the cell.
  }

  webSocketClose(ws: WebSocket, code: number): void {
    try {
      ws.close(code === 1005 ? 1000 : code, "bye");
    } catch {
      // already closed
    }
  }

  // ------------------------------------------------------------ retention

  async alarm(): Promise<void> {
    if (this.meta("owner") === null) return;
    const now = Date.now();
    this.sql.exec("DELETE FROM nonces WHERE exp < ?", now);
    const acked = new Map(
      this.sql.exec<{ key: string; acked: number }>("SELECT key, acked FROM members").toArray().map((r) => [r.key, r.acked]),
    );
    const batches = this.sql.exec<BatchRow>("SELECT cursor, id, author, recipient, at FROM batches").toArray();
    const gone = expiredBatches(batches, acked, now);
    for (let i = 0; i < gone.length; i += 500) {
      const chunk = gone.slice(i, i + 500);
      await this.env.BATCHES.delete(chunk.map((b) => this.objectKey(b.id)));
      for (const b of chunk) this.sql.exec("DELETE FROM batches WHERE cursor = ?", b.cursor);
    }
    console.log("retention", JSON.stringify({ deleted: gone.length, kept: batches.length - gone.length }));
    await this.ctx.storage.setAlarm(now + DAY_MS);
  }
}
