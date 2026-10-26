# pesaclarity-backend

The server for [Pesa Clarity](https://github.com/pesaclarity/docs), the free, ad-free Android app that turns M-Pesa and bank messages into a daily plan. All analysis runs on the phone, so this server never sees a transaction. It has three narrow jobs: sign people in (phone number with an SMS code, or Google on the Play Store build), keep a backup vault of files the phone has already encrypted and that the server cannot read, and combine clipped, noised federated model updates under secure aggregation.

**Codename:** ngome, Swahili for "fortress".

**Status:** pre-alpha. The API may change without notice before 1.0.

The product spec and brand live in [pesaclarity/docs](https://github.com/pesaclarity/docs); see "Architecture, privacy and data model" and "Federated learning and model licensing".

## What the server holds

| Service | Stores | Never stores |
| --- | --- | --- |
| Auth | Account id, a keyed hash of the sign-in contact, devices, sign-up, sign-in and sign-out events | The phone number or Google id in readable form, any financial data |
| Backup vault | Ciphertext (AES-256-GCM, keyed on the phone with Argon2id) in object storage under a random key; its size, SHA-256 and upload time in Postgres | Keys, passphrases or anything readable; account ids in object keys |
| Federated learning | Aggregated model updates | Raw data or individual updates in the clear |

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

The API is then on http://localhost:8000, with interactive docs at `/docs` outside production. In development, sign-in codes are printed to the server's console instead of sent by SMS.

To run everything in containers instead: `docker compose up --build`.

### API at a glance

| Method and path | Purpose |
| --- | --- |
| `GET /health`, `GET /health/ready` | Liveness and database readiness |
| `POST /v1/auth/phone/start`, `POST /v1/auth/phone/verify` | Phone sign-in with a one-time code |
| `POST /v1/auth/google` | Google sign-in (Play Store build; off unless enabled with client ids) |
| `POST /v1/auth/refresh` | Rotate tokens; reusing an old refresh token signs that device out |
| `POST /v1/auth/sign-out` | Sign this device out |
| `GET /v1/auth/devices`, `DELETE /v1/auth/devices/{id}` | Device list and remote sign-out |
| `GET /v1/account`, `DELETE /v1/account` | What we hold, and immediate deletion of all of it |
| `POST /v1/vault/backups` | Upload ciphertext (`application/octet-stream`, optional `X-Content-SHA256`) |
| `GET /v1/vault/backups`, `GET` / `DELETE /v1/vault/backups/{id}` | List, download and delete backups |

Access tokens last 10 minutes; refresh tokens rotate on every use and expire after 30 days. The vault keeps the newest 10 backups per account, up to 256 MiB in total.

Google sign-in is off by default. To turn it on, set `NGOME_GOOGLE_SIGN_IN_ENABLED=true` and list the accepted OAuth client ids in `NGOME_GOOGLE_CLIENT_IDS`. ID tokens are checked against Google's published signing keys (cached, and refetched when Google rotates them), plus audience, issuer and expiry. Only the token's subject is kept, as a keyed hash.

### Retention

`ngome-purge` deletes one-time codes 24 hours after they expire and sign-in events after 90 days, then retries any backup objects still queued for deletion. The periods are `NGOME_RETENTION_OTP_CHALLENGE_HOURS` and `NGOME_RETENTION_AUTH_EVENT_DAYS`; the defaults are provisional until the privacy policy fixes them, and the two must always agree. The job is safe to run more than once or concurrently, and exits non-zero if the purge fails or a queued object could not be deleted (it stays queued for the next run).

Run it once a day with the same environment as the API. Nothing here is deployed for you; pick whichever scheduler you already use.

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

### Backup storage

Backup bytes go to a blob store chosen by `NGOME_VAULT_BLOB_STORE`: `postgres` (the default, for development and tests), `filesystem` (files under `NGOME_VAULT_FS_ROOT`, for development or a single-node install) or `s3`, which works with AWS S3, Cloudflare R2 and MinIO. The server only stores and returns ciphertext; it never holds a key that could decrypt it. Uploads and downloads stream, with the size cap, the account quota and the checksum checked on the way in. Metadata always stays in Postgres.

Each backup is capped at `NGOME_VAULT_MAX_BACKUP_BYTES`, and each account at `NGOME_VAULT_MAX_ACCOUNT_BYTES` across the backups it keeps (the new one plus the newest `NGOME_VAULT_KEEP_BACKUPS - 1`, since older ones are pruned). An upload over either limit gets `413`.

When a backup goes (deleted, pruned, or with its account), its object is queued for deletion in the same transaction and removed straight after; any object the store fails to delete stays queued, is logged as a count and is retried on the next vault deletion and by the daily `ngome-purge`.

To try object storage locally, `docker compose up -d minio minio-init` starts MinIO on port 9000 (console on 9001) with `ngome-backups` and `ngome-test` buckets; then set `NGOME_VAULT_BLOB_STORE=s3` and the MinIO credentials from `docker-compose.yml` in `.env`.

### Federated learning

`ngome.fl.server:app` is a Flower `ServerApp` running FedAvg under SecAgg+, with updates clipped on the phone and Gaussian noise added on the server. It needs the `fl` extra and runs on a Flower SuperLink, separately from the API. Its settings (`NGOME_FL_*` in `.env.example`) are placeholders until pesaclarity-ml publishes a privacy budget.

## Project layout

```
src/ngome/
  api/      app factory, shared dependencies, health and account routes
  auth/     phone and Google sign-in, tokens, devices, SMS and Google provider interfaces
  vault/    encrypted backup metadata, blob stores (Postgres, filesystem, S3-compatible) and deletion queue
  fl/       Flower aggregation server and its settings
  core/     settings, logging with redaction, token and hashing primitives
  db/       SQLAlchemy base, engine and model registry
migrations/ Alembic migrations
tests/      pytest suite (SQLite in a temp file; no Postgres needed)
```

## Testing

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

The object storage tests skip unless `NGOME_TEST_S3_ENDPOINT_URL` is set. With the compose MinIO running:

```sh
NGOME_TEST_S3_ENDPOINT_URL=http://localhost:9000 uv run pytest -m object_storage
```

CI also runs those against MinIO, applies the migrations to Postgres, checks they match the models and builds the Docker image.

## Not done yet

Named `TODO` markers in the code cover: a real SMS provider, Play Integrity checks on uploads, and loading and publishing the federated model.

## Licence

AGPL-3.0; see [LICENSE](LICENSE). If you run a modified version as a network service, you must offer its source to its users. A commercial licence is available on request for organisations that cannot accept the AGPL. The Pesa Clarity name and logo are trademarks and are not covered by the code licence.
