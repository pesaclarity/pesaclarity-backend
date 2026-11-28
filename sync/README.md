# Group sync server

> **Replaced.** Group sync is now served by the backend itself, at the same paths and with the same wire protocol ([decision 0035](https://github.com/pesaclarity/docs/blob/main/decisions/0035-group-sync-through-the-backend.md); `src/ngome/groupsync/` and "Group sync" in the [README](../README.md#group-sync)). This Worker will not be deployed: there are to be no celld nodes, no separate domain and no separate bucket. It stays here as the reference for the protocol and its tests. The one thing it has that the backend does not is the WebSocket for live notices.

The relay for shared spaces that sync through a server ([decision 0033](https://github.com/pesaclarity/docs/blob/main/decisions/0033-group-sync-server-on-celld.md)). It is a Cloudflare-style Worker with one Durable Object per shared space. It runs on our own [celld](https://github.com/denoland/celld) nodes, pinned to **v0.6.3**.

It stores and passes on **ciphertext only**: the phone seals each batch the same way as a `.pcshare` file. The server has no keys. It does not merge anything. Merging happens on the phones, by HLC order, as in 0031.

It is separate from the Python backend in this repository. It shares no code, database or deploy with it.

## What it does

| Call | Who | What |
| --- | --- | --- |
| `POST /v1/spaces/{space}` `{"licence": "..."}` | owner | Makes the space. The signer becomes its owner and first member. Needs a valid licence with the `group-sync` feature. |
| `GET /v1/spaces/{space}` | member | Members, owner, `validUntil`, `readOnly`, latest cursor. |
| `PUT /v1/spaces/{space}/licence` `{"licence": "..."}` | owner | Renews the licence. |
| `PUT` / `DELETE /v1/spaces/{space}/members/{key}` | owner | Adds or removes a member key. The owner can always remove someone, even when the space is read-only. |
| `POST /v1/spaces/{space}/batches` | member | Pushes one batch. The body is the padded ciphertext. Headers: `X-PC-Batch` (batch id, makes the call idempotent) and `X-PC-To` (optional recipient key). |
| `GET /v1/spaces/{space}/batches?since=N` | member | Returns the batches for this member after cursor `N`, with `next` and `more`. Asking from `N` also tells the server the member holds everything up to `N`. |
| `GET /v1/spaces/{space}/ws?key=&t=&n=&sig=` | member | A WebSocket for live notices (`{"type":"batch","cursor":N}`). It uses hibernation, so `ping` gets `pong` without waking the cell. |
| `DELETE /v1/spaces/{space}` | owner | Deletes every bucket object of the space, then all of the cell's data. |

Errors look like `{"error": "code"}`. The codes are `unauthorized`, `clock`, `replay` (401), `licence_*` (402), `not_member`, `not_owner`, `read_only` (403), `not_found` (404), `exists`, `batch_id_taken`, `space_full`, `owner_stays` (409), `not_padded`, `bad_*` (400), `too_large` (413) and `rate_limited` (429).

### Signed requests

Each request is signed with the member's Ed25519 key. The app derives this key from the member's share seed (`ShareSigner` in the app). Its base64url public key is the member's key id. Four headers carry the signature: `X-PC-Key`, `X-PC-Time` (ms), `X-PC-Nonce` (random, 16 to 64 base64url characters) and `X-PC-Sig`. The signature covers:

```
pcsync v1
METHOD
/path?query
time
nonce
base64url(SHA-256(body))
```

The time must be within 5 minutes of the server's clock. A nonce is refused if the space has seen it within that window. A WebSocket sends the same values as query parameters and signs `GET` and the path alone.

### Rules from 0033

- **Read-only on expiry.** When the owner's licence has expired, pulls still work and pushes and new members are refused. Only "valid until" is stored, and the account id in the licence is dropped.
- **Padding.** A batch must be exactly 1, 2, 4 … 1024 KiB long. The phone pads it.
- **Retention.** A daily alarm in each cell deletes a batch once every member it is for has pulled past it, and only once it is at least 90 days old. Snapshots are not built yet.
- **Rate limits.** In each cell, per key: 120 requests and 30 pushes a minute. In the Worker: 300 requests a minute per address. The address is used only as a key in memory and is never stored.
- **Logs.** The server logs no bodies and no addresses, only ids, counts and outcomes. Caddy writes no access log. Keep the host's log retention at 7 days or less.

### Licence

Licence issuing (0032) is not built. `src/licence.ts` checks the planned format, `pclic.1.<payload>.<sig>`, behind the `LicenceVerifier` interface. The payload is base64url JSON `{v, acct, plan, features, iat, exp}`, and the signature is Ed25519 over `pclic.1.<payload>`. The public key goes in `vars.LICENCE_PUBLIC_KEY` in `wrangler.json`. It is a public key, so committing it is fine. While it is empty, every licence is refused.

## Develop and test

You need Node 22.6 or later, and `celld` 0.6.3 on `PATH`. Install celld with `curl -fsSL https://celld.dev/install.sh | sh`, or take the binary from the [GitHub release](https://github.com/denoland/celld/releases/tag/v0.6.3).

```sh
cd sync
npm ci
npm test          # typecheck, unit tests, then end to end on a fresh `celld dev`
npm run dev       # celld dev on http://127.0.0.1:9876
```

The end-to-end tests start `celld dev --clean`. Each run makes its own licence key in `.dev.vars`, which is ignored by git and removed after the run. The tests cover two members pushing and pulling with a live notice, idempotent pushes, forged, replayed and stale signatures, a removed member, an expired licence that makes the space read-only and then renewal, delete (including the bucket objects) and rate limits.

`tool/check` at the repository root runs these tests when `celld` is on `PATH`.

## Deploy

celld is **beta**. Put TLS in front of it and keep port 8081 (peer and operator traffic) on a private network.

1. **Bucket.** Make a Google Cloud Storage bucket with versioning on, and give a service account `roles/storage.objectAdmin` on it. Cloudflare R2 is the fallback: use an `s3://` bucket with `S3_ENDPOINT`. Copy the bucket daily to a second bucket for backups.
2. **Licence key.** Put the licence public key in `wrangler.json` → `vars.LICENCE_PUBLIC_KEY`.
3. **Deploy the Worker** into the bucket. Running nodes pick up the new version without restarting:
   ```sh
   cd sync && npm ci
   PATH="$PWD/node_modules/.bin:$PATH" celld deploy . --bucket gs://NAME
   ```
4. **Run the nodes** behind Caddy. `deploy/compose.yaml` runs two nodes on one host, with Caddy getting the certificate:
   ```sh
   cd sync/deploy
   cp .env.example .env      # SYNC_DOMAIN, CELLD_BUCKET, credentials; never commit .env
   docker compose up -d
   curl https://$SYNC_DOMAIN/healthz
   ```
   For nodes on separate machines, run `ghcr.io/denoland/celld:0.6.3` with `--internal-listen` and `--advertise` set to a private address on each machine, or use WireGuard or Tailscale. Point Caddy, or the Cloud Run load balancer, at port 8080 on each node.
5. **Monitor** node health (`/healthz`), cell count, push and pull errors and latency, and bucket size. `celld diagnose --bucket gs://NAME` checks the fleet.

To upgrade celld, change the pinned version here and in `compose.yaml`, and test on staging first.
