// The space owner's licence (decision 0032), checked offline in the cell.
//
// Licence issuing is not built yet. This is the planned format, behind an
// interface so the real issuer can change it without touching the cell:
//
//   pclic.1.<payload>.<signature>
//
// payload is base64url JSON {"v":1,"acct":"...","plan":"premium",
// "features":["group-sync",...],"iat":<ms>,"exp":<ms>}; signature is
// Ed25519 over the ASCII text "pclic.1.<payload>", base64url, made with the
// licence key whose public half is LICENCE_PUBLIC_KEY. Only "valid until"
// is kept by the cell; the account id is read and dropped.

import { fromB64url, verifyEd25519 } from "./protocol.ts";

export const SYNC_FEATURE = "group-sync";

export type LicenceResult =
  | { ok: true; validUntil: number }
  | { ok: false; why: "malformed" | "signature" | "expired" | "feature" | "no_key" };

export interface LicenceVerifier {
  verify(token: string, now: number): Promise<LicenceResult>;
}

export class Ed25519LicenceVerifier implements LicenceVerifier {
  private readonly publicKey: string | undefined;

  constructor(publicKey: string | undefined) {
    this.publicKey = publicKey;
  }

  async verify(token: string, now: number): Promise<LicenceResult> {
    // No key configured: refuse every licence rather than accept any.
    if (!this.publicKey) return { ok: false, why: "no_key" };
    const parts = typeof token === "string" ? token.split(".") : [];
    if (parts.length !== 4 || parts[0] !== "pclic" || parts[1] !== "1" || token.length > 4096) {
      return { ok: false, why: "malformed" };
    }
    const signed = new TextEncoder().encode(`pclic.1.${parts[2]}`);
    if (!(await verifyEd25519(this.publicKey, signed, parts[3]))) {
      return { ok: false, why: "signature" };
    }
    let body: { v?: unknown; exp?: unknown; features?: unknown };
    try {
      body = JSON.parse(new TextDecoder().decode(fromB64url(parts[2])));
    } catch {
      return { ok: false, why: "malformed" };
    }
    if (body.v !== 1 || typeof body.exp !== "number") return { ok: false, why: "malformed" };
    if (!Array.isArray(body.features) || !body.features.includes(SYNC_FEATURE)) {
      return { ok: false, why: "feature" };
    }
    if (body.exp <= now) return { ok: false, why: "expired" };
    return { ok: true, validUntil: body.exp };
  }
}
