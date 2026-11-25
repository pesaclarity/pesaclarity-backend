// A small signing client for the tests, as the phone signs requests.

import { H, b64url, sha256, signingString } from "../src/protocol.ts";

export interface Member {
  key: string;
  priv: CryptoKey;
}

export async function newMember(): Promise<Member> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { key: b64url(raw), priv: pair.privateKey };
}

export const randomId = (n = 16) => b64url(crypto.getRandomValues(new Uint8Array(n)));

export async function sign(m: Member, method: string, path: string, body: Uint8Array, time = Date.now()) {
  const nonce = randomId();
  const msg = signingString(method, path, String(time), nonce, await sha256(body));
  const sig = b64url(new Uint8Array(await crypto.subtle.sign("Ed25519", m.priv, new TextEncoder().encode(msg))));
  return { key: m.key, time: String(time), nonce, sig };
}

export interface CallOptions {
  body?: Uint8Array | object;
  headers?: Record<string, string>;
  time?: number;
  /** Replace the signature parts after signing (forgery tests). */
  tamper?: (p: { key: string; time: string; nonce: string; sig: string }) => void;
  /** Reuse these exact signature headers (replay tests). */
  reuse?: Record<string, string>;
}

export async function call(base: string, m: Member, method: string, path: string, o: CallOptions = {}) {
  const body =
    o.body === undefined
      ? new Uint8Array()
      : o.body instanceof Uint8Array
        ? o.body
        : new TextEncoder().encode(JSON.stringify(o.body));
  const parts = await sign(m, method, path, body, o.time);
  o.tamper?.(parts);
  const signed = o.reuse ?? { [H.key]: parts.key, [H.time]: parts.time, [H.nonce]: parts.nonce, [H.sig]: parts.sig };
  const res = await fetch(base + path, {
    method,
    headers: { ...signed, ...(o.headers ?? {}) },
    body: method === "GET" || method === "HEAD" ? undefined : body,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: res.status, data, signed };
}

/** A licence in the planned format, signed with the test licence key. */
export async function licence(priv: CryptoKey, exp: number, features = ["group-sync"]) {
  const payload = b64url(
    new TextEncoder().encode(JSON.stringify({ v: 1, acct: "test-account", plan: "premium", features, iat: Date.now(), exp })),
  );
  const signed = `pclic.1.${payload}`;
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", priv, new TextEncoder().encode(signed)));
  return `${signed}.${b64url(sig)}`;
}

/** A batch padded to a size step, as the phone pads it. */
export function padded(size: number, fill = 7) {
  return new Uint8Array(size).fill(fill);
}
