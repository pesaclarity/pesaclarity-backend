// The wire rules shared by the server and its tests: encodings, the signed
// request scheme, batch size steps and limits. Nothing here touches storage.

export const PROTOCOL = "pcsync v1";

/** A signed request must be within this much of the server's clock. */
export const CLOCK_WINDOW_MS = 5 * 60_000;

/** Batches are padded by the phone to one of these sizes, so their length
 *  says little about what changed. 1 KiB, 2 KiB, ... 1 MiB. */
export const SIZE_STEPS: readonly number[] = Array.from({ length: 11 }, (_, i) => 1024 << i);
export const MAX_BATCH_BYTES = SIZE_STEPS[SIZE_STEPS.length - 1];

/** The most members a shared space holds (a Savings group, decision 0031). */
export const MAX_MEMBERS = 30;

/** Batches are kept at least this long, and until every member pulled past them. */
export const MIN_KEEP_MS = 90 * 24 * 60 * 60_000;

/** How much one pull returns at most. */
export const PULL_MAX_BATCHES = 100;
export const PULL_MAX_BYTES = 4 * 1024 * 1024;

const ID = /^[A-Za-z0-9_-]{16,64}$/;
/** Space ids and batch ids: random, url-safe. */
export const isId = (s: unknown): s is string => typeof s === "string" && ID.test(s);

/** A member key is its 32-byte Ed25519 public key, base64url without padding. */
export const isKey = (s: unknown): s is string =>
  typeof s === "string" && /^[A-Za-z0-9_-]{43}$/.test(s);

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** What a member signs: method, path with query, time, nonce and the body's
 *  SHA-256, one per line. */
export function signingString(
  method: string,
  path: string,
  time: string,
  nonce: string,
  bodyHash: string,
): string {
  return [PROTOCOL, method.toUpperCase(), path, time, nonce, bodyHash].join("\n");
}

export async function verifyEd25519(key: string, message: Uint8Array, sig: string): Promise<boolean> {
  try {
    const pub = await crypto.subtle.importKey("raw", fromB64url(key), { name: "Ed25519" }, false, [
      "verify",
    ]);
    return await crypto.subtle.verify("Ed25519", pub, fromB64url(sig), message);
  } catch {
    return false;
  }
}

/** Whether [size] is one of the padding steps. */
export const isPaddedSize = (size: number): boolean => SIZE_STEPS.includes(size);

/** The step a payload of [size] bytes is padded up to, or null when too big. */
export function paddedSize(size: number): number | null {
  return SIZE_STEPS.find((s) => s >= size) ?? null;
}

/** Signature headers (a WebSocket sends the same names as query parameters). */
export const H = {
  key: "x-pc-key",
  time: "x-pc-time",
  nonce: "x-pc-nonce",
  sig: "x-pc-sig",
} as const;

export interface SignedParts {
  key: string;
  time: string;
  nonce: string;
  sig: string;
}

export type Check = { ok: true } | { ok: false; why: "clock" | "signature" | "malformed" };

/** Checks the clock and signature of a request; the nonce's freshness is the
 *  caller's job, since it needs storage. */
export async function checkSignature(
  parts: SignedParts,
  method: string,
  path: string,
  body: Uint8Array,
  now: number,
): Promise<Check> {
  const { key, time, nonce, sig } = parts;
  if (!isKey(key) || !/^\d{1,16}$/.test(time) || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || !sig) {
    return { ok: false, why: "malformed" };
  }
  if (Math.abs(now - Number(time)) > CLOCK_WINDOW_MS) return { ok: false, why: "clock" };
  const msg = new TextEncoder().encode(signingString(method, path, time, nonce, await sha256(body)));
  return (await verifyEd25519(key, msg, sig)) ? { ok: true } : { ok: false, why: "signature" };
}
