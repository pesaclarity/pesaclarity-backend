# pesaclarity-backend

The server for [Pesa Clarity](https://github.com/pesaclarity/docs), the free, ad-free app for Android and iPhone that turns M-Pesa and bank messages into a daily plan. All analysis runs on the phone, so this server never sees a transaction. It has a few narrow jobs: sign people in (a one-time code sent by email, or Google on the Play Store build), keep a backup vault of files the phone has already encrypted and that the server cannot read, combine clipped, noised federated model updates under secure aggregation, answer the app's signed update check, and count installs and take crash reports without identifiers ([ADR 0024](https://github.com/pesaclarity/docs/blob/main/decisions/0024-counting-installs-and-crash-reports.md)).

**Codename:** ngome, Swahili for "fortress".

**Status:** pre-alpha, running on Google Cloud Run and deployed from `main` ([docs/deploying.md](docs/deploying.md)). The API may change without notice before 1.0.

The product spec and brand live in [pesaclarity/docs](https://github.com/pesaclarity/docs); see "Architecture, privacy and data model" and "Federated learning and model licensing".

## What the server holds

| Service | Stores | Never stores |
| --- | --- | --- |
| Auth | Account id, a keyed hash of the sign-in contact, devices, sign-up, sign-in and sign-out events | The email address or Google id in readable form, any financial data |
| Backup vault | Ciphertext (AES-256-GCM, keyed on the phone with Argon2id) in object storage under a random key; its size, SHA-256 and upload time in Postgres | Keys, passphrases or anything readable; account ids in object keys |
| Federated learning | Aggregated model updates | Raw data or individual updates in the clear |
| App status | The notices the team sends (updates, news), and how many check-ins got each one per day | Anything about who asked: no address, account or device id |
| Install counts | Per open day and month, a random key and keyed digests of the phones' random monthly counting tokens, deleted when the period closes; totals by version, build and (months only, when country lookup is on) country | The token itself, the address, or any link between a total and a phone |
| Crash reports | Reports people chose to send: app version and build, system version, chip, the kind of error and the stack as code offsets, with the day received (90 days); groups of them with counts and dates (a year after last seen) | Messages, amounts, names, numbers, file paths, the time, the address, any account or install id |
| Admin dashboard | One admin user: username, Argon2id password hash, the authenticator secret encrypted with `NGOME_ADMIN_SECRET_KEY`, keyed hashes of recovery and emailed codes, optional passkeys (credential id, public key, counter, label); sessions and browsers as digests; failure counters and a 90-day audit log keyed by a hash of the address, with country and browser family | The password, codes or secret in plain text, full addresses, or a Google account |

Accounts are optional: the app works fully without one, and only the vault needs sign-in.

## Quick start

Needs [uv](https://docs.astral.sh/uv/) and Docker.

```sh
cp .env.example .env               # then replace both secrets
uv sync --all-extras
docker compose up -d db
uv run alembic upgrade head
uv run uvicorn ngome.api.app:create_app --factory --reload
```

The API is then on http://localhost:8000, with interactive docs at `/docs` outside production. In development, sign-in codes are printed to the server's console instead of emailed.

To run everything in containers instead: `docker compose up --build`.

### API at a glance

| Method and path | Purpose |
| --- | --- |
| `GET /health`, `GET /health/ready` | Liveness and database readiness |
| `POST /v1/auth/email/start`, `POST /v1/auth/email/verify` | Email sign-in with a one-time code |
| `POST /v1/auth/google` | Google sign-in (Play Store build; off unless enabled with client ids) |
| `POST /v1/auth/refresh` | Rotate tokens; reusing an old refresh token signs that device out |
| `POST /v1/auth/sign-out` | Sign this device out |
| `GET /v1/auth/devices`, `DELETE /v1/auth/devices/{id}` | Device list and remote sign-out |
| `GET /v1/account`, `DELETE /v1/account` | What we hold, and immediate deletion of all of it |
| `POST /v1/vault/backups` | Upload ciphertext (`application/octet-stream`, optional `X-Content-SHA256`, optional `X-Backup-Space` naming which of the phone's spaces it copies; each space keeps its own newest `NGOME_VAULT_KEEP_BACKUPS`) |
| `POST /v1/privacy/copy` | Email the signed-in person a copy of the privacy policy, as text and a PDF. The address is used once and never stored or logged. Only text whose SHA-256 is in `NGOME_PRIVACY_POLICY_SHA256` is sent, at most `NGOME_PRIVACY_COPY_MAX_PER_DAY` copies a day per account. Get the digest with `sha256sum assets/policy/privacy_policy.md` in pesaclarity-app. |
| `GET /v1/vault/backups`, `GET` / `DELETE /v1/vault/backups/{id}` | List, download and delete backups |
| `GET /v1/app-status?version=&build=&platform=` | The newest app version and active notices for that build, signed with Ed25519. No account; nothing about the caller is logged or stored |
| `POST` / `GET /v1/admin/app-notices`, `POST /v1/admin/app-notices/{id}/disable` | Create, list and stop notices (admin token) |
| `POST /v1/crash-reports` | A crash report the person chose to send: exactly the schema below, 16 KB at most. No account, no cookie |
| `POST /v1/admin/starter-user` | Make the dashboard's admin user with a temporary password, shown once; with `"reset": true`, start sign-in over (admin token) |
| `GET /v1/admin/client-address` | The client address the server sees for this request, to check `NGOME_PROXY_HOPS` (admin token) |
| `GET /v1/admin/passkeys`, `DELETE /v1/admin/passkeys/{id}` | List and remove the dashboard's passkeys (admin token) |
| `GET /admin` (and `/admin/installs`, `/admin/crashes`, `/admin/notices`, `/admin/learning`, `/admin/security`) | The owner's dashboard, opened with a password and a second factor (off until `NGOME_ADMIN_ORIGIN` is set) |
| `GET /admin/installs.csv`, `/admin/adoption.csv`, `/admin/monthly.csv` | The dashboard's tables as CSV, exactly as shown: small cells are `<10` or `hidden`, never the stored count. Each needs a second factor from the last 10 minutes |

Access tokens last 10 minutes; refresh tokens rotate on every use and expire after 30 days. The vault keeps the newest 10 backups per account, up to 256 MiB in total.

Google sign-in is off by default. To turn it on, set `NGOME_GOOGLE_SIGN_IN_ENABLED=true` and list the accepted OAuth client ids in `NGOME_GOOGLE_CLIENT_IDS`. ID tokens are checked against Google's published signing keys (cached, and refetched when Google rotates them), plus audience, issuer and expiry. Only the token's subject is kept, as a keyed hash.

### Retention

`ngome-purge` deletes one-time codes 24 hours after they expire and sign-in events after 90 days, then retries any backup objects still queued for deletion. It also deletes counting digests and keys when their period closes (a day's once the next day is over; a month's on the 2nd of the next month), daily install totals, notice reach and flood marks after 13 months (`NGOME_RETENTION_DAILY_COUNT_DAYS`), crash reports after 90 days (`NGOME_RETENTION_CRASH_REPORT_DAYS`), crash groups a year after they were last seen (`NGOME_RETENTION_CRASH_GROUP_DAYS`), and expired dashboard sessions, enrolment links and challenges. Monthly install totals are kept; they name no one. The periods are `NGOME_RETENTION_OTP_CHALLENGE_HOURS` and `NGOME_RETENTION_AUTH_EVENT_DAYS`; the defaults are provisional until the privacy policy fixes them, and the two must always agree. The job is safe to run more than once or concurrently, and exits non-zero if the purge fails or a queued object could not be deleted (it stays queued for the next run).

Run it once a day with the same environment as the API. On Cloud Run it is a job that Cloud Scheduler starts daily ([docs/deploying.md](docs/deploying.md)); elsewhere, pick whichever scheduler you already use.

cron, with Docker Compose:

```cron
17 3 * * * cd /srv/ngome && docker compose run --rm api ngome-purge
```

systemd, as `/etc/systemd/system/ngome-purge.service` and `ngome-purge.timer`:

```ini
[Unit]
Description=Pesa Clarity retention purge

[Service]
Type=oneshot
EnvironmentFile=/etc/ngome/ngome.env
ExecStart=/opt/ngome/.venv/bin/ngome-purge
```

```ini
[Unit]
Description=Daily Pesa Clarity retention purge

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl enable --now ngome-purge.timer`.

Kubernetes:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ngome-purge
spec:
  schedule: "17 3 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: purge
              image: registry.example.com/ngome:0.1.0  # the image you run the API from
              command: ["ngome-purge"]
              envFrom:
                - secretRef:
                    name: ngome-env  # the same NGOME_* settings as the API
```

### App status and notices

The app asks `GET /v1/app-status?version=0.3.0&build=play&platform=android` when it opens, at most once a day, without an account. `build` is `play`, `foss`, `ios` or `website`; `platform` is `android` or `ios`. The server logs only the route and status, never the caller's address, the query or the headers. It adds one to each notice's reach for the day, and counts the phone's `Count-Token` header if there is one ([Counting installs](#counting-installs)); nothing else about the request is stored. Responses may be cached (`NGOME_APP_STATUS_CACHE_SECONDS`, default 300).

The body is `{"alg": "Ed25519", "payload": <base64>, "signature": <base64>}`. The signature covers the bytes `pesaclarity.app-status.v1\n` followed by the decoded payload, which is JSON:

```json
{"format": 1, "issued_at": "2026-11-17T08:00:00Z", "version": "0.3.0", "build": "play",
 "platform": "android", "latest_version": "0.4.0",
 "notices": [{"id": "…", "kind": "update", "title": "Pesa Clarity 0.4.0 is ready",
   "body": "Reads Equity card payments and fixes Fuliza totals.", "latest_version": "0.4.0",
   "min_version": null, "required_reason": null, "reread_from": null}]}
```

The app pins the public key in its source, checks the signature, and refuses a payload that names another version, build or platform, or whose `issued_at` is old or older than one it has already seen, so an old notice cannot be replayed. A response it cannot verify shows nothing; it never blocks the app.

Notices are created by the team with the admin routes, which take `Authorization: Bearer $NGOME_ADMIN_TOKEN` (compared in constant time; unset turns the routes off):

```sh
curl -X POST "$API/v1/admin/app-notices" -H "Authorization: Bearer $NGOME_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"kind": "update", "title": "Pesa Clarity 0.4.0 is ready",
  "body": "Reads Equity card payments and fixes Fuliza totals.", "latest_version": "0.4.0",
  "builds": ["play", "foss", "ios", "website"]}'
```

| Field | Meaning |
| --- | --- |
| `kind` | `update` (needs `latest_version`; shown to builds older than it) or `info` (news, shown to every version) |
| `title`, `body` | Up to 80 and 500 characters |
| `min_version` | Update only: builds older than this must update |
| `required_reason` | `amounts_wrong` only, with `min_version`. The app blocks older builds only for a bug that makes amounts wrong; without it the update shows as the usual card |
| `builds` | Any of `play`, `foss`, `ios`, `website` |
| `reread_from` | Optional date: asks the app to read its messages again from that day |
| `starts_at`, `ends_at` | Optional, with a time zone. Shown from `starts_at` (default now) until `ends_at` |

`GET /v1/admin/app-notices` lists them all; `POST /v1/admin/app-notices/{id}/disable` stops one.

**Signing key.** `uv run ngome-app-status-key` prints a new seed and its public key. Set the seed as the secret `NGOME_APP_STATUS_SIGNING_SEED` (base64 of 32 bytes; unset turns app status off) and add the public key to the app's pinned list in a release before the server signs with it. Never commit a seed; the tests make throwaway keys.

### Counting installs

[ADR 0024](https://github.com/pesaclarity/docs/blob/main/decisions/0024-counting-installs-and-crash-reports.md) counts active installs without identifiers. The app makes a counting token from 128 random bits, new each calendar month (UTC) and never derived from the phone or the person, and sends it only on the app status check-in, in a `Count-Token` header (22 base64url characters), so request logs, which record the URL, never hold it. The person can switch it off in the app; the check-in carries on without it.

`ngome.counting` keeps, per open day and per month, one random 32-byte key (`count_keys`) and, for each token seen, the first 16 bytes of HMAC-SHA-256 of the token under that key (`count_seen`). When a digest is new in its period, it adds one to that period's totals (`count_totals`) for `all`, the build, the version and, for months only, the country. So each period counts a token once, under the version it had when first seen; the day and month keys differ, so a day's digest cannot be matched to the month's. `ngome-purge` deletes the sets and keys when the period closes, after which nothing links a total to a phone.

- **Country** is off (`NGOME_COUNTRY_LOOKUP_ENABLED=false`) until the owner has confirmed on db-ip.com that DB-IP IP to Country Lite is licensed under CC BY 4.0. When on, the caller's address (Cloud Run's `X-Forwarded-For`, through Uvicorn's `--proxy-headers`) is looked up in the MMDB file at `NGOME_COUNTRY_DB_PATH`, held in memory, and dropped; only the two-letter code is used, for the month's totals, and an address the database does not place counts as Unknown. The dashboard and the policy credit "IP Geolocation by DB-IP" with a link to db-ip.com. To ship the file in the image, build with `--build-arg DBIP_COUNTRY_LITE_MONTH=2026-11` (the month's file name on db-ip.com); refresh it monthly.
- **Small numbers** are hidden on display, never in storage: the dashboard shows a count under 10 as "<10", and when only one cell in a table is hidden it hides the next smallest too, shown as "hidden", so the total cannot give it away. A sum shown beside a table ("Older" versions, "earlier releases" in a stacked bar, a platform's builds) is hidden when it holds exactly one hidden cell, and a bar's two parts are hidden together. Country is shown by month only, one dimension at a time.
- **Abuse.** Anyone can make up tokens. A malformed token is ignored and the check-in still answered. Each instance counts at most `NGOME_COUNTING_MAX_NEW_PER_HOUR` (600) new tokens an hour; above that, tokens are not counted and the hour is marked as a flood on the dashboard (`count_floods`). A day or month counts at most `NGOME_COUNTING_MAX_PER_PERIOD` tokens. Nothing is limited per address, since that would mean keeping the address. The counts drive nothing automatically.
- `NGOME_COUNTING_ENABLED=false` ignores the header altogether.

### Crash reports

`POST /v1/crash-reports` takes a report the person chose to send after seeing it. It needs no account, sets no cookie and is not linked to the counting token. The body must be exactly this, 16 KB at most, or it is refused with `422` (and the refusal does not echo it):

```json
{"format": 1, "app": "0.5.2", "build_number": 412, "build": "play", "os": "Android 13",
 "cpu": "arm64", "error": "TypeError", "build_id": "b6f1c4e09a2d7f35",
 "stack": ["#00 pc 0x2f4b3c", "#01 pc 0x2f49e0"]}
```

`error` is one of `TypeError`, `StateError`, `RangeError`, `ArgumentError`, `FormatException`, `SqliteException`, `TimeoutException`, `FileSystemException`, `PlatformException` or `Other`, never a message. `os` is `Android <version>` or `iOS <version>`; `cpu` is `arm64`, `arm`, `x64`, `ia32` or `riscv64`. `stack` holds up to 64 frames, each either an offset in the app's instructions (`#00 pc 0x2f4b3c`, from an obfuscated release) or, from an unobfuscated build, a dotted function name and a `package:` or `dart:` location; any other line is refused. Every field is checked with its own pattern (`ngome.crashes.schemas`), and the tests plant amounts, phone numbers, emails, names, message text and file paths to check none gets through.

The server keeps the day it received a report, not the time. Reports with the same error, build id and first three frames share a group (`crash_groups`), which keeps its daily counts (`crash_group_days`) after its reports are deleted. At most `NGOME_CRASH_REPORTS_MAX_PER_DAY` (2,000) reports are taken a day; then `429`. `NGOME_CRASH_REPORTS_ENABLED=false` turns the route off.

Decoding offsets into our code's names needs each release's `--split-debug-info` symbols and the decode job that ADR 0024 plans (symbols in Cloudflare R2, the job on Cloud Run); neither is built yet, so the dashboard shows reports as not decoded and groups an obfuscated build's reports per build id. `crash_groups.decoded_function` and `decoded_location`, and `crash_reports.decoded`, are where the job will write.

### Admin dashboard

The owner's read-only dashboard is served under `/admin`: monthly active installs over six months (split by newest release or by build), daily active installs over 30 or 90 days, versions and builds, notice reach, GitHub release downloads (read from `stats/downloads.csv` on the `stats` branch of pesaclarity/.github, public, `NGOME_DOWNLOADS_CSV_URL`), installs by country, version or build with six months of version adoption, the flood check, and crash groups with reports per day, versions affected and one report exactly as received. Every page takes the same filters (`month`, `days`, `build`, `platform`, `version`), and a crash group's page keeps the list's. The crash rate is reports per 1,000 installs in one calendar month on both sides; reports are opt-in, so it is a floor, not a crash-free rate. Pages are rendered on the server with charts as inline SVG; the only script runs passkeys and small conveniences (every form works without it), and the fonts are served from the dashboard itself, so it makes no third-party requests. Every `/admin` response carries `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Notices are still sent with the admin token.

It is off (every route `404`) until `NGOME_ADMIN_ORIGIN` is set to the dashboard's exact origin, such as `https://ngome-xxxx.a.run.app`, with `NGOME_ADMIN_EMAIL` (the owner's address for codes and alerts) and `NGOME_ADMIN_SECRET_KEY` (base64 of 32 random bytes that encrypt the authenticator secret). Until both are set, the rest of the server runs as usual and the dashboard refuses sign-in with a page naming what is missing (`503`; the starter command too), so deploying first locks nothing in: set them, sync, and sign in. To serve it on more addresses too (a custom domain beside the `run.app` one), list them in `NGOME_ADMIN_EXTRA_ORIGINS` as JSON, such as `["https://admin.example.org"]`. Each POST must come from one of these origins, and passkey ceremonies use that origin's host, so a passkey works only on the address it was added on.

**Sign-in** ([ADR 0025](https://github.com/pesaclarity/docs/blob/main/decisions/0025-admin-sign-in-password-and-second-factor.md)) is a username and password, then a second factor, every time:

- **Password**: Argon2id (`argon2-cffi`, m = 46 MiB, t = 1, p = 1, at most two hashes at once per instance), at least 15 characters, and refused when it holds the username, `pesaclarity` or the host, or is on the bundled list of 47,023 common passwords (zxcvbn's list, MIT; `src/ngome/admin/data/`). A full breached-password check does not fit in the image and would need an outside call, so there is none.
- **Authenticator app** (TOTP, RFC 6238: SHA-1, 6 digits, 30 seconds, one step either side): required, set up by QR code at the first sign-in. Each code works once (the last accepted step is stored). The secret is stored encrypted with AES-256-GCM.
- **Passkey** (optional, the only phishing-proof factor): added from Security after a fresh check; never on its own, always after the password.
- **Email code** (fallback): 6 digits through Brevo to `NGOME_ADMIN_EMAIL`, never a link; one a minute, three per sign-in, `NGOME_OTP_MAX_PER_HOUR` an hour, `NGOME_ADMIN_EMAIL_CODES_PER_DAY` a day. A session signed in this way can read and download, but not change sign-in settings.
- **Recovery codes**: ten, shown once, kept as keyed hashes, each usable once.

**Limits** are counted in Postgres, so every instance shares them: 5 wrong passwords for a username from a browser not seen before (10 from a known one, which has its own count) or 20 an hour from one address pause sign-in for 15 minutes, doubling with each pause in 24 hours up to a day (`NGOME_ADMIN_PAUSE_MINUTES` and the `NGOME_ADMIN_*_MAX_FAILURES` settings). 5 wrong codes end a sign-in; 10 in 24 hours pause the second step for an hour. Messages are the same whether the username or the password was wrong. The address is the entry Cloud Run appends to `X-Forwarded-For` (`NGOME_PROXY_HOPS`), never one the caller wrote, and is kept only as a keyed hash.

**Sessions**: a random id in a `__Host-ngome_admin` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), 8 hours at most (`NGOME_ADMIN_SESSION_HOURS`) and ending after 30 minutes idle (`NGOME_ADMIN_IDLE_MINUTES`); the server keeps only its digest. CSV downloads and every sign-in change need a second factor from the last 10 minutes (`NGOME_ADMIN_REAUTH_MINUTES`); sign-in changes take the authenticator or a passkey, not an emailed code. Every POST checks `Origin` (a plain form post from these `no-referrer` pages sends `Origin: null`, accepted only with `Sec-Fetch-Site: same-origin`).

**Audit and alerts**: sign-ins, failures, pauses and changes are logged in `admin_events` for 90 days (`NGOME_RETENTION_AUTH_EVENT_DAYS`) with a short keyed hash of the address, country and browser family, and never a password, code, secret or the username tried. The owner is emailed when sign-in is paused, after the right password with wrong codes, on a sign-in from a browser not seen before, on any sign-in change, when a recovery code is used (each at most once an hour), and every time the starter command runs.

**The first sign-in.** With the admin token, from a terminal (it never reaches a browser):

```sh
curl -X POST "$API/v1/admin/starter-user" -H "Authorization: Bearer $NGOME_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"username": "<your username>"}'
```

It prints the username and a random 24-character temporary password, once. Open `/admin/sign-in` within 24 hours (`NGOME_ADMIN_STARTER_HOURS`) and sign in with them; the server emails a code to `NGOME_ADMIN_EMAIL`, so the admin token alone cannot open the dashboard. Then, before anything else opens, choose your own password, set up the authenticator app (scan the QR code or type the key, then type a code from the app), and save the ten recovery codes. Running the command again replaces a temporary password; once a real password exists it is refused (`409`) unless the body says `"reset": true`, which replaces the password, wipes the authenticator, recovery codes and every session (passkeys stay) and starts the first sign-in over. The username is 3 to 32 characters of `a-z`, `0-9`, `.`, `_`, `-`; `admin`, `root` and the like are refused.

`GET /v1/admin/passkeys` lists the passkeys and `DELETE /v1/admin/passkeys/{id}` removes one.

### Backup storage

Backup bytes go to a blob store chosen by `NGOME_VAULT_BLOB_STORE`: `postgres` (the default, for development and tests), `filesystem` (files under `NGOME_VAULT_FS_ROOT`, for development or a single-node install) or `s3`, which works with AWS S3, Cloudflare R2 and MinIO. The server only stores and returns ciphertext; it never holds a key that could decrypt it. Uploads and downloads stream, with the size cap, the account quota and the checksum checked on the way in. Metadata always stays in Postgres.

Each backup is capped at `NGOME_VAULT_MAX_BACKUP_BYTES`, and each account at `NGOME_VAULT_MAX_ACCOUNT_BYTES` across the backups it keeps (the new one plus the newest `NGOME_VAULT_KEEP_BACKUPS - 1`, since older ones are pruned). An upload over either limit gets `413`.

When a backup goes (deleted, pruned, or with its account), its object is queued for deletion in the same transaction and removed straight after; any object the store fails to delete stays queued, is logged as a count and is retried on the next vault deletion and by the daily `ngome-purge`.

To try object storage locally, `docker compose up -d minio minio-init` starts MinIO on port 9000 (console on 9001) with `ngome-backups` and `ngome-test` buckets; then set `NGOME_VAULT_BLOB_STORE=s3` and the MinIO credentials from `docker-compose.yml` in `.env`.

### Play Integrity

Play builds send `X-Pesaclarity-Integrity` with each vault upload: a Play Integrity token bound to the body's SHA-256 (sent as `X-Content-SHA256`, which the upload checksum then ties to the stored bytes). With `NGOME_PLAY_INTEGRITY_ENABLED=true` the server decodes the token with the Play Integrity API, as the service account it runs as, and accepts it only if it was made for this request and package, `appRecognitionVerdict` is `PLAY_RECOGNIZED`, the device verdict includes `NGOME_PLAY_INTEGRITY_DEVICE_VERDICT`, and it is no older than `NGOME_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS`. A failing token gets `403`; if Google cannot be reached the upload gets `503` with `Retry-After`.

iPhone builds use Apple App Attest instead (`src/ngome/integrity/apple.py`). An install registers a key once: `POST /v1/integrity/app-attest/challenges` returns a one-time challenge (valid `NGOME_APP_ATTEST_CHALLENGE_SECONDS`, 300 by default), and `POST /v1/integrity/app-attest/keys` takes the key id, Apple's attestation over that challenge and the challenge. The server checks the certificate chain against Apple's App Attestation root (bundled, `apple_app_attestation_root_ca.pem`), the nonce, the key id, `NGOME_APP_ATTEST_APP_ID` (Apple team id and bundle id, such as `ABCDE12345.com.pesaclarity.app`) and `NGOME_APP_ATTEST_ENVIRONMENT` (`production` for TestFlight and App Store builds, `development` for Xcode builds), then keeps the public key for the account. Each upload then sends `X-Pesaclarity-Integrity: appattest <key id> <assertion>`: the key's signature over the same `requestHash`, with a counter that must rise, so it cannot be replayed or moved to other bytes. Keys go when the account is deleted.

F-Droid builds cannot attest, and nothing stops a client leaving the header out, so uploads without a token follow `NGOME_VAULT_UNATTESTED_UPLOADS`: `allow` or `reject`. It is required once Play Integrity or App Attest is enabled; a proof whose check is off counts as none.

Before enabling it: enable `playintegrity.googleapis.com` in the Cloud project the server runs in, and link that project to the app in Play Console (**App integrity → Play Integrity API**). The app's build gets the same project number as `PESACLARITY_PLAY_CLOUD_PROJECT`.

### Federated learning

`ngome.fl.server:app` is a Flower `ServerApp` running FedAvg under SecAgg+, with updates clipped on the phone and Gaussian noise added on the server. It needs the `fl` extra and runs on a Flower SuperLink, separately from the API. Its settings (`NGOME_FL_*` in `.env.example`) are placeholders until pesaclarity-ml publishes a privacy budget.

## Branches and releases

Every push to `main` deploys, so `main` takes only tested, approved changes.

1. Pull requests go to `dev` and are rebase-merged, so every commit lands on `dev` as is and each needs a [Conventional Commits](https://www.conventionalcommits.org) title (`feat: …`, `fix: …`, `feat!: …` for a breaking change; `docs`, `test`, `ci`, `chore`, `refactor`, `build`, `perf`, `style`, `revert` too). Use `feat` or `fix` for changes users see, and a hidden type (`refactor`, `test`, `style`, `chore`, `docs`, `ci`, `build`) for review follow-ups they don't, as new commits rather than `fixup!` ones. Checks run on your machine, not on GitHub: the pre-push hook runs `tool/check` and checks the titles of the commits you push (see [Testing](#testing)).
2. When `dev` is ready, open a pull request from `dev` to `main`. The `Release gate` check allows only `dev` (or the release pull request) into `main`, and its QA job waits for a reviewer in the `qa` environment. Merge it with a merge commit, not a squash, so each change keeps its own title.
3. On `main`, release-please keeps a release pull request open with the next version (SemVer from the commit titles: `feat` bumps the minor, `fix` the patch; before 1.0 a breaking change bumps the minor) in `pyproject.toml`, `uv.lock` and `ngome.__version__`, and the `CHANGELOG.md` entry. Merging it tags `vX.Y.Z` and merges the release back into `dev`.

## Deploying to Cloud Run

Production runs in the EU: the API on Google Cloud Run, Postgres on [Neon](https://neon.tech), and sign-in emails through [Brevo](https://www.brevo.com) over SMTP, with backup ciphertext moving to Cloudflare R2 (EU jurisdiction) later. At proof-of-concept traffic all of them fit their free tiers. Cloud Run scales to zero, so the first request after a quiet spell takes a second or two.

- **Deploys:** Cloud Run deploys `main` itself. Each push builds the Dockerfile on Cloud Build and swaps the service's image.
- **Settings:** kept in this repository's `production` environment on GitHub, with secrets as environment secrets. The **Sync settings** workflow checks them and applies them to Cloud Run, with the secrets held in Secret Manager.
- **Migrations:** each new revision applies them as it starts, before it takes traffic. A Cloud Run job can also run them by hand.
- **Jobs:** the daily retention purge runs as a Cloud Run job.

[docs/deploying.md](docs/deploying.md) has the setup and the day-to-day commands: deploying, changing a setting, migrations, rollback and adding R2.

The Flower aggregation server is not deployed yet. When it is, it can run as a separate Cloud Run service, which carries gRPC.

## Project layout

```
src/ngome/
  api/      app factory, shared dependencies, health and account routes
  auth/     email and Google sign-in, tokens, devices, email (SMTP) and Google providers
  vault/    encrypted backup metadata, blob stores (Postgres, filesystem, S3-compatible) and deletion queue
  appstatus/ signed app status and admin notices
  counting/ install counts from the monthly counting token, country lookup, suppression
  crashes/  crash report schema, intake and grouping
  admin/    the dashboard: sign-in, second factors, limits, audit, pages, templates and static files
  fl/       Flower aggregation server and its settings
  core/     settings, logging with redaction, token and hashing primitives
  db/       SQLAlchemy base, engine and model registry
migrations/ Alembic migrations
tests/      pytest suite (SQLite in a temp file; no Postgres needed)
```

## Testing

GitHub runs no checks; they run on your machine. Enable the pre-push hook once per clone:

```sh
tool/setup-hooks
```

`tool/check` runs everything: ruff lint and format, mypy, the unit tests, the migrations on Postgres (upgrade, `alembic check` that models and migrations agree, downgrade, concurrent migrations), the object storage tests on MinIO and the Docker build. `tool/check --fast` runs only lint, format, types and unit tests. The unit tests always run; for the rest start the services first:

```sh
docker compose up -d --wait db minio   # or: tool/check --up
tool/check
```

Without them those steps are skipped with a notice. The migration steps use a scratch `ngome_check` database on the compose Postgres, so your development data is untouched; `NGOME_CHECK_POSTGRES_URL` and `NGOME_TEST_S3_ENDPOINT_URL` point them elsewhere.

## Not done yet

Named `TODO` markers in the code cover loading and publishing the federated model. Play Integrity checks on federated updates come with the Flower deployment. From ADR 0024: uploading release symbols and the crash decode job, and the dashboard's federated-learning card, which fills in once the aggregator stores its rounds.

## Get involved

- **Star [the app](https://github.com/pesaclarity/pesaclarity-app)** so more people find a private money app that runs on their phone.
- Python and FastAPI help is welcome: deployment, retention jobs, and federated learning (see the open issues).
- **Pick a first issue:** [good first issues](https://github.com/pesaclarity/pesaclarity-backend/issues?q=is%3Aopen+label%3A%22good+first+issue%22) or [help wanted](https://github.com/pesaclarity/pesaclarity-backend/issues?q=is%3Aopen+label%3A%22help+wanted%22).
- **Read [CONTRIBUTING.md](CONTRIBUTING.md)** before your first pull request. Never include real messages, statements or phone numbers.

## Licence

AGPL-3.0; see [LICENSE](LICENSE). If you run a modified version as a network service, you must offer its source to its users. A commercial licence is available on request for organisations that cannot accept the AGPL. The Pesa Clarity name and logo are trademarks and are not covered by the code licence.
