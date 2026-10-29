# pesaclarity-backend

The server for [Pesa Clarity](https://github.com/pesaclarity/docs), the free, ad-free Android app that turns M-Pesa and bank messages into a daily plan. All analysis runs on the phone, so this server never sees a transaction. It has three narrow jobs: sign people in (a one-time code sent by email, or Google on the Play Store build), keep a backup vault of files the phone has already encrypted and that the server cannot read, and combine clipped, noised federated model updates under secure aggregation.

**Codename:** ngome, Swahili for "fortress".

**Status:** pre-alpha. The API may change without notice before 1.0.

The product spec and brand live in [pesaclarity/docs](https://github.com/pesaclarity/docs); see "Architecture, privacy and data model" and "Federated learning and model licensing".

## What the server holds

| Service | Stores | Never stores |
| --- | --- | --- |
| Auth | Account id, a keyed hash of the sign-in contact, devices, sign-up, sign-in and sign-out events | The email address or Google id in readable form, any financial data |
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

### Play Integrity

Play builds send `X-Pesaclarity-Integrity` with each vault upload: a Play Integrity token bound to the body's SHA-256 (sent as `X-Content-SHA256`, which the upload checksum then ties to the stored bytes). With `NGOME_PLAY_INTEGRITY_ENABLED=true` the server decodes the token with the Play Integrity API, as the service account it runs as, and accepts it only if it was made for this request and package, `appRecognitionVerdict` is `PLAY_RECOGNIZED`, the device verdict includes `NGOME_PLAY_INTEGRITY_DEVICE_VERDICT`, and it is no older than `NGOME_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS`. A failing token gets `403`; if Google cannot be reached the upload gets `503` with `Retry-After`.

iPhone builds use Apple App Attest instead (`src/ngome/integrity/apple.py`). An install registers a key once: `POST /v1/integrity/app-attest/challenges` returns a one-time challenge (valid `NGOME_APP_ATTEST_CHALLENGE_SECONDS`, 300 by default), and `POST /v1/integrity/app-attest/keys` takes the key id, Apple's attestation over that challenge and the challenge. The server checks the certificate chain against Apple's App Attestation root (bundled, `apple_app_attestation_root_ca.pem`), the nonce, the key id, `NGOME_APP_ATTEST_APP_ID` (Apple team id and bundle id, such as `ABCDE12345.com.pesaclarity.app`) and `NGOME_APP_ATTEST_ENVIRONMENT` (`production` for TestFlight and App Store builds, `development` for Xcode builds), then keeps the public key for the account. Each upload then sends `X-Pesaclarity-Integrity: appattest <key id> <assertion>`: the key's signature over the same `requestHash`, with a counter that must rise, so it cannot be replayed or moved to other bytes. Keys go when the account is deleted.

F-Droid builds cannot attest, and nothing stops a client leaving the header out, so uploads without a token follow `NGOME_VAULT_UNATTESTED_UPLOADS`: `allow` or `reject`. It is required once Play Integrity or App Attest is enabled; a proof whose check is off counts as none.

Before enabling it: enable `playintegrity.googleapis.com` in the Cloud project the server runs in, and link that project to the app in Play Console (**App integrity → Play Integrity API**). The app's build gets the same project number as `PESACLARITY_PLAY_CLOUD_PROJECT`.

### Federated learning

`ngome.fl.server:app` is a Flower `ServerApp` running FedAvg under SecAgg+, with updates clipped on the phone and Gaussian noise added on the server. It needs the `fl` extra and runs on a Flower SuperLink, separately from the API. Its settings (`NGOME_FL_*` in `.env.example`) are placeholders until pesaclarity-ml publishes a privacy budget.

## Branches and releases

Every push to `main` deploys, so `main` takes only tested, approved changes.

1. Pull requests go to `dev`, with a [Conventional Commits](https://www.conventionalcommits.org) title (`feat: …`, `fix: …`, `feat!: …` for a breaking change; `docs`, `test`, `ci`, `chore`, `refactor`, `build`, `perf`, `style`, `revert` too). The `PR title` check enforces it, and squash merges keep the title as the commit message. CI runs on every push to `dev`.
2. When `dev` is ready, open a pull request from `dev` to `main`. The `Release gate` check allows only `dev` (or the release pull request) into `main`, and its QA job waits for a reviewer in the `qa` environment. Merge it with a merge commit, not a squash, so each change keeps its own title.
3. On `main`, release-please keeps a release pull request open with the next version (SemVer from the titles: `feat` bumps the minor, `fix` the patch; before 1.0 a breaking change bumps the minor) in `pyproject.toml`, `uv.lock` and `ngome.__version__`, and the `CHANGELOG.md` entry. Merging it tags `vX.Y.Z` and merges the release back into `dev`.

## Deploying to Cloud Run

The intended production setup runs in the EU: the API on Google Cloud Run, Postgres on [Neon](https://neon.tech), backup ciphertext on Cloudflare R2 with EU jurisdiction, and sign-in emails through [Brevo](https://www.brevo.com) over SMTP. At proof-of-concept traffic all four fit their free tiers; Cloud Run scales to zero, so the first request after a quiet spell takes a second or two.

`.github/workflows/deploy-cloud-run.yml` deploys `main` each time CI passes. It signs in to Google Cloud without a stored key, builds the image, runs the migrations as a Cloud Run job, releases the API only if they pass, refreshes the purge job and checks `/health/ready`.

Nothing about the deployment lives in the code: every name, region, size, provider setting and the sign-in email wording come from repository variables and Secret Manager. The job is skipped until `GCP_PROJECT_ID` exists and stops with a list of whatever else is missing.

### One-time setup

Pick your own names first; the commands below use these shell variables.

```sh
PROJECT=<project-id> REGION=<region, e.g. europe-west1> REPO=<owner>/pesaclarity-backend
AR_REPO=<artifact registry repository> RUNTIME_NAME=<runtime account> DEPLOY_NAME=<deploy account>
POOL_ID=<workload identity pool> PROVIDER_ID=<pool provider>
```

1. **Neon:** create a project in an EU region and copy the direct (not pooled) connection string. The server converts its `sslmode` options for asyncpg.
2. **Cloudflare R2:** create a bucket with the EU jurisdiction and an API token with read and write access to it. The endpoint is `https://<account-id>.eu.r2.cloudflarestorage.com`.
3. **Brevo:** verify a sender address or domain, then copy the SMTP host, port, login and an SMTP key from SMTP & API settings.
4. **Google Cloud** (a project with billing and a budget alert):

   ```sh
   gcloud config set project "$PROJECT"
   gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
     secretmanager.googleapis.com cloudscheduler.googleapis.com iamcredentials.googleapis.com \
     playintegrity.googleapis.com
   gcloud artifacts repositories create "$AR_REPO" --repository-format docker --location "$REGION"

   # Who the API runs as, and who GitHub deploys as.
   gcloud iam service-accounts create "$RUNTIME_NAME"
   gcloud iam service-accounts create "$DEPLOY_NAME"
   RUNTIME=$RUNTIME_NAME@$PROJECT.iam.gserviceaccount.com
   DEPLOY=$DEPLOY_NAME@$PROJECT.iam.gserviceaccount.com
   gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$RUNTIME" --role roles/secretmanager.secretAccessor
   for role in roles/run.admin roles/artifactregistry.writer; do
     gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$DEPLOY" --role "$role"
   done
   gcloud iam service-accounts add-iam-policy-binding "$RUNTIME" --member "serviceAccount:$DEPLOY" --role roles/iam.serviceAccountUser

   # Keyless sign-in for this repository's workflows only.
   gcloud iam workload-identity-pools create "$POOL_ID" --location global
   gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" --location global \
     --workload-identity-pool "$POOL_ID" --issuer-uri https://token.actions.githubusercontent.com \
     --attribute-mapping google.subject=assertion.sub,attribute.repository=assertion.repository \
     --attribute-condition "assertion.repository == '$REPO'"
   POOL=$(gcloud iam workload-identity-pools describe "$POOL_ID" --location global --format 'value(name)')
   gcloud iam service-accounts add-iam-policy-binding "$DEPLOY" --role roles/iam.workloadIdentityUser \
     --member "principalSet://iam.googleapis.com/$POOL/attribute.repository/$REPO"
   gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" --location global \
     --workload-identity-pool "$POOL_ID" --format 'value(name)'   # -> GCP_WORKLOAD_IDENTITY_PROVIDER

   # One secret per sensitive setting, named as you like.
   # NGOME_CONTACT_PEPPER must never change once accounts exist: keep a copy offline.
   new() { printf '%s' "$2" | gcloud secrets create "$1" --data-file -; }
   new <database-url-secret> '<neon connection string>'
   new <jwt-secret> "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
   new <contact-pepper-secret> "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
   new <smtp-password-secret> '<brevo smtp key>'
   new <s3-access-key-id-secret> '<r2 access key id>'
   new <s3-secret-access-key-secret> '<r2 secret access key>'
   ```

5. **GitHub repository variables** (Settings → Secrets and variables → Actions → Variables):

   | Variable | What it holds |
   | --- | --- |
   | `GCP_PROJECT_ID`, `GCP_REGION` | The project and region |
   | `GCP_WORKLOAD_IDENTITY_PROVIDER` | The provider name printed above |
   | `GCP_DEPLOY_SERVICE_ACCOUNT`, `GCP_RUNTIME_SERVICE_ACCOUNT` | The two service account emails |
   | `GCP_IMAGE` | Image path without a tag: `<region>-docker.pkg.dev/<project>/<ar-repo>/<image>` |
   | `CLOUD_RUN_SERVICE`, `CLOUD_RUN_MIGRATE_JOB`, `CLOUD_RUN_PURGE_JOB` | Names for the API service and the two jobs |
   | `CLOUD_RUN_SERVICE_FLAGS` | Extra `gcloud run deploy` flags, for example `--port 8000 --allow-unauthenticated --cpu 1 --memory 512Mi --min-instances 0 --max-instances 3 --concurrency 40` |
   | `CLOUD_RUN_JOB_FLAGS` | Extra `gcloud run jobs deploy` flags, for example `--max-retries 0 --task-timeout 10m` |
   | `CLOUD_RUN_SECRETS` | `ENV=secret:version` pairs, comma-separated: `NGOME_DATABASE_URL`, `NGOME_JWT_SECRET`, `NGOME_CONTACT_PEPPER`, `NGOME_SMTP_PASSWORD`, `NGOME_VAULT_S3_ACCESS_KEY_ID`, `NGOME_VAULT_S3_SECRET_ACCESS_KEY` |
   | `CLOUD_RUN_ENV_YAML` | Every other setting, as YAML (below) |

   `CLOUD_RUN_ENV_YAML` holds the non-secret settings from `.env.example`. A variable can span several lines, so the email wording can too:

   ```yaml
   NGOME_ENVIRONMENT: production
   NGOME_LOG_JSON: "true"
   NGOME_EMAIL_PROVIDER: smtp
   NGOME_EMAIL_FROM: "<Name> <sender@your-domain>"
   NGOME_EMAIL_CODE_SUBJECT: "<subject with {code}>"
   NGOME_EMAIL_CODE_BODY: |
     <body with {code} and {minutes}>
   NGOME_SMTP_HOST: "<smtp host>"
   NGOME_SMTP_PORT: "<smtp port>"
   NGOME_SMTP_USERNAME: "<smtp login>"
   NGOME_SMTP_TIMEOUT_SECONDS: "<seconds>"
   NGOME_VAULT_BLOB_STORE: s3
   NGOME_VAULT_S3_BUCKET: "<bucket>"
   NGOME_VAULT_S3_ENDPOINT_URL: "<endpoint>"
   NGOME_VAULT_S3_REGION: "<region, auto for R2>"
   NGOME_GOOGLE_SIGN_IN_ENABLED: "<true or false>"
   NGOME_GOOGLE_CLIENT_IDS: '["<web client id>"]'
   NGOME_PLAY_INTEGRITY_ENABLED: "<true or false>"
   NGOME_PLAY_INTEGRITY_PACKAGE_NAME: "<application id>"
   NGOME_PLAY_INTEGRITY_DEVICE_VERDICT: "<MEETS_BASIC_INTEGRITY, MEETS_DEVICE_INTEGRITY or MEETS_STRONG_INTEGRITY>"
   NGOME_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS: "<seconds>"
   NGOME_APP_ATTEST_ENABLED: "<true or false>"
   NGOME_APP_ATTEST_APP_ID: "<Apple team id>.com.pesaclarity.app"
   NGOME_APP_ATTEST_ENVIRONMENT: "<production or development>"
   NGOME_VAULT_UNATTESTED_UPLOADS: "<allow or reject>"
   FORWARDED_ALLOW_IPS: "*"
   ```

   Then run the workflow from the Actions tab.
6. **Daily purge**, once the first deploy has created the purge job:

   ```sh
   PURGE_JOB=<CLOUD_RUN_PURGE_JOB> SCHEDULER_NAME=<scheduler account> SCHEDULE='<cron, e.g. 15 2 * * *>'
   gcloud iam service-accounts create "$SCHEDULER_NAME"
   SCHEDULER=$SCHEDULER_NAME@$PROJECT.iam.gserviceaccount.com
   gcloud run jobs add-iam-policy-binding "$PURGE_JOB" --region "$REGION" --member "serviceAccount:$SCHEDULER" --role roles/run.invoker
   gcloud scheduler jobs create http "$PURGE_JOB-daily" --location "$REGION" --schedule "$SCHEDULE" \
     --uri "https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/jobs/$PURGE_JOB:run" \
     --http-method POST --oauth-service-account-email "$SCHEDULER"
   ```

The Flower aggregation server is not deployed yet; when it is, it can run as a separate Cloud Run service, which carries gRPC.

## Project layout

```
src/ngome/
  api/      app factory, shared dependencies, health and account routes
  auth/     email and Google sign-in, tokens, devices, email (SMTP) and Google providers
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

Named `TODO` markers in the code cover loading and publishing the federated model. Play Integrity checks on federated updates come with the Flower deployment.

## Licence

AGPL-3.0; see [LICENSE](LICENSE). If you run a modified version as a network service, you must offer its source to its users. A commercial licence is available on request for organisations that cannot accept the AGPL. The Pesa Clarity name and logo are trademarks and are not covered by the code licence.
