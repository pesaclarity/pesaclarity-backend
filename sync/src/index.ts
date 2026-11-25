// The Worker in front of the space cells: checks the path, applies a coarse
// per-address limit, and hands the request to the space's cell. It logs no
// addresses and no bodies.

import { isId } from "./protocol.ts";
import { RateLimiter } from "./ratelimit.ts";
import type { Env } from "./space.ts";

export { SpaceCell } from "./space.ts";

// Per isolate, by address: a backstop against floods before a cell wakes.
// The address is used only as an in-memory key and never stored.
const perAddress = new RateLimiter(300, 300);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return new Response("ok");
    const m = /^\/v1\/spaces\/([^/]+)(\/.*)?$/.exec(url.pathname);
    if (!m || !isId(m[1])) return Response.json({ error: "not_found" }, { status: 404 });
    const address = request.headers.get("cf-connecting-ip") ?? request.headers.get("x-forwarded-for") ?? "?";
    if (!perAddress.take(address, Date.now())) {
      return Response.json({ error: "rate_limited" }, { status: 429 });
    }
    const headers = new Headers(request.headers);
    headers.set("x-pc-space", m[1]);
    const stub = env.SPACES.get(env.SPACES.idFromName(m[1]));
    return stub.fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;
