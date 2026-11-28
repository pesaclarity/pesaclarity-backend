# Deploying to Cloud Run

How the server runs in production, and the commands to set it up and look after it. Everything here runs from a terminal with `gcloud`, `gh` and `jq`, plus a few clicks in the Cloud Run and GitHub consoles. The design is in [specs 0001](specs/0001-settings-live-on-cloud-run.md) and [0002](specs/0002-github-holds-settings.md).

## How it fits together

| Piece | Where | How it changes |
| --- | --- | --- |
| API | Cloud Run service | Cloud Run's auto-deploy: every push to `main` builds the `Dockerfile` on Cloud Build and swaps the service's image. Nothing else on the service changes. |
| Settings | GitHub, `production` environment: secrets as environment secrets, everything else as environment variables | Edit them in GitHub, then run the **Sync settings** workflow. It checks them, puts secrets in Secret Manager and applies everything to the service and both jobs. |
| Database | Postgres on Neon | Each new revision migrates as it starts, before it takes traffic ([Migrations](#migrations)). The migrate job (`alembic upgrade head`) does the same by hand. |
| Retention | The purge job (`ngome-purge`) | Cloud Scheduler starts it daily |
| Sign-in email | Brevo, over SMTP | |
| Backups | Postgres for now; Cloudflare R2 later ([Adding R2](#adding-r2)) | |
| Group sync | The same service, database and blob store: nothing of its own to host ([Group sync](#group-sync-decision-0035)) | Off until `NGOME_LICENCE_PUBLIC_KEY` is set |

GitHub wins: a setting edited directly on Cloud Run is replaced by the next sync. GitHub won't show a secret's value back; to read one, use Secret Manager (`gcloud secrets versions access latest --secret <name>`).

The workflow reads names from the `production` environment's variables: `GCP_PROJECT_ID`, `GCP_REGION`, `CLOUD_RUN_SERVICE`, `CLOUD_RUN_MIGRATE_JOB`, `CLOUD_RUN_PURGE_JOB`, `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_DEPLOY_SERVICE_ACCOUNT`. The commands below use the same names as shell variables. Set them first:

```sh
GCP_PROJECT_ID=<project-id> GCP_REGION=<region, e.g. europe-west1>
CLOUD_RUN_SERVICE=<service> CLOUD_RUN_MIGRATE_JOB=<migrate job> CLOUD_RUN_PURGE_JOB=<purge job>
RUNTIME=<runtime account>@$GCP_PROJECT_ID.iam.gserviceaccount.com
gcloud config set project "$GCP_PROJECT_ID"
```

## Day to day

### Deploy

Merge to `main` (README, "Branches and releases"). To watch the build: `gcloud builds list --limit 3`. A failed build, a failed migration, or a revision that doesn't start leaves the previous revision serving.

### Change a setting

1. In GitHub, go to Settings → Environments → `production` and edit the variable or secret. Or from a terminal:

   ```sh
   gh variable set NGOME_LOG_LEVEL --env production --body DEBUG
   gh secret set NGOME_SMTP_PASSWORD --env production   # asks for the value without showing it
   ```

2. Run **Sync settings** from the Actions tab, or with `gh workflow run "Sync settings"` and then `gh run watch`.

   - If a setting is invalid, the run stops at "Check the settings" and nothing changes. The error names the setting, never its value.
   - A secret gets a new Secret Manager version only when its value changed.
   - Removing a variable or secret in GitHub removes it from Cloud Run on the next sync.

The workflow names each secret it reads: the nine secret settings the server has (database URL, JWT secret, contact pepper, SMTP password, the two R2 keys, the admin token, the app status signing seed and the admin secret key). A new secret setting has to be added to `.github/workflows/sync-settings.yml` as well.

GitHub may hold a Sync settings run for approval when it flags a workflow as potentially malicious. Approve the run on its page in the Actions tab, signed in with write access.

**Never change `NGOME_CONTACT_PEPPER`.** It keys every account, and the sync refuses to apply a new value. If a run fails on it, put the original value back: `gcloud secrets versions access 1 --secret <pepper secret>`.

### Migrations

The image sets `NGOME_MIGRATE_ON_START=true`, so a new revision runs `alembic upgrade head` as it starts, before it opens its port. Cloud Run sends it no traffic until then.

- **All or nothing.** Every pending migration runs in one transaction. If one fails, nothing is applied, the revision doesn't start and the previous one keeps serving. `gcloud run services logs read` shows the error.
- **One at a time.** Several instances of a new revision, or an instance and the migrate job, can start together. They take turns on a Postgres advisory lock (`migrations/env.py`); the first applies the migrations and the rest find nothing to do.
- **The previous release keeps serving** on the new schema until the new revision takes over, so a migration must work with both. Add columns and tables in one release and remove the old ones in a later one.
- **Keep them quick.** A starting container gets about four minutes before Cloud Run gives up on it, and the revision then doesn't start. Keep slow data changes out of migrations.

To migrate only with the job, set `NGOME_MIGRATE_ON_START` to `false` in GitHub and run **Sync settings**.

### After a deploy: the jobs' image

Auto-deploy only updates the service. When a change touches the purge, or you want the migrate job on the new code, point both jobs at the service's image:

```sh
img="$(gcloud run services describe "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --format 'value(spec.template.spec.containers[0].image)')"
gcloud run jobs update "$CLOUD_RUN_PURGE_JOB" --region "$GCP_REGION" --image "$img"
gcloud run jobs update "$CLOUD_RUN_MIGRATE_JOB" --region "$GCP_REGION" --image "$img"
```

### Roll back

```sh
gcloud run revisions list --service "$CLOUD_RUN_SERVICE" --region "$GCP_REGION"
gcloud run services update-traffic "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --to-revisions <revision>=100
```

While traffic is pinned to a revision, new deploys don't get any. When the fix is out, run `gcloud run services update-traffic "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --to-latest`.

Migrations don't roll back with a revision, so only roll back to a release that works with the current schema.

### Logs

```sh
gcloud run services logs read "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --limit 50
gcloud run jobs executions list --job "$CLOUD_RUN_PURGE_JOB" --region "$GCP_REGION" --limit 5
```

## Install counts, crash reports and the dashboard (ADR 0024)

**Request logs.** The owner decided that Google keeps no request logs for the two routes that count and take crash reports. Add a Cloud Logging exclusion once (it also covers future revisions):

```sh
gcloud logging sinks update _Default --project "$GCP_PROJECT_ID" \
  --add-exclusion=name=ngome-no-request-logs,description="ADR 0024: no request logs for app status and crash reports",filter='resource.type="cloud_run_revision" AND resource.labels.service_name="'"$CLOUD_RUN_SERVICE"'" AND log_id("run.googleapis.com/requests") AND (httpRequest.requestUrl:"/v1/app-status" OR httpRequest.requestUrl:"/v1/crash-reports")'
gcloud logging sinks describe _Default --project "$GCP_PROJECT_ID"   # check it is listed
```

Those two routes lose their security logs; the token format check, the flood ceiling and its dashboard flag, and the crash reports' size and daily caps still apply. The server's own log line for them carries only the route template, status and duration.

**The dashboard.** Set its origin (the service's URL, or a custom domain mapped to it), the owner's email address and the key that encrypts the authenticator secret, sync, then make the admin user from a terminal (README, "Admin dashboard"). Set the email and key before the release with ADR 0025 deploys if you can; if it deploys first, passkey-only sign-in has already ended and the dashboard shows "Sign-in isn't configured" (`503`) until they are set and synced, while the app's API carries on:

```sh
gh variable set NGOME_ADMIN_ORIGIN --env production --body "https://<service url host>"
gh variable set NGOME_ADMIN_EMAIL --env production --body "<the owner's address>"
python3 -c 'import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode(), end="")' \
  | gh secret set NGOME_ADMIN_SECRET_KEY --env production
gh workflow run "Sync settings"
```

After the deploy, check that the server reads the caller's address from the entry Google appends, not one the caller wrote: the answer must be your own address, not `203.0.113.7`.

```sh
curl -s "$API/v1/admin/client-address" -H "Authorization: Bearer $NGOME_ADMIN_TOKEN" \
  -H 'X-Forwarded-For: 203.0.113.7'
```

If it shows `203.0.113.7`, or an address of Google's, set `NGOME_PROXY_HOPS` (2 behind a load balancer) and sync again. Then make the starter user and sign in:

```sh
curl -X POST "$API/v1/admin/starter-user" -H "Authorization: Bearer $NGOME_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"username": "<your username>"}'
```

It prints a temporary password once; clear the terminal afterwards. Within 24 hours open `https://<service url host>/admin/sign-in`, sign in with it, type the code emailed to `NGOME_ADMIN_EMAIL`, choose your own password (15 characters or more; a passphrase from your password manager), scan the QR code with your authenticator app and type its code, and save the ten recovery codes away from the computer. Passkeys enrolled before ADR 0025 stay, and work as a second factor after the password. Lost the password or the authenticator and every recovery code? Run the command again with `"reset": true` (the owner is emailed). Keep an offline copy of `NGOME_ADMIN_SECRET_KEY`: without it the authenticator has to be set up again.

Passkeys are bound to the origin's host name: moving the dashboard to another host means adding them again.

To open it on another address as well, such as a custom domain mapped to the service, add that origin and sync. The password and the authenticator work on every address; a passkey works only on the address it was added on, so sign in there and add one from Security if you want it:

```sh
gh variable set NGOME_ADMIN_EXTRA_ORIGINS --env production --body '["https://<other host>"]'
gh workflow run "Sync settings"
```

**Country.** Off until DB-IP Lite's CC BY 4.0 licence is confirmed on db-ip.com. Then build the image with `--build-arg DBIP_COUNTRY_LITE_MONTH=<YYYY-MM>` (add it to the Cloud Build trigger and `tool/cloudbuild.yaml`), set `NGOME_COUNTRY_LOOKUP_ENABLED=true` and `NGOME_COUNTRY_DB_PATH=/app/data/dbip-country-lite.mmdb`, and refresh the month in each month's first deploy.

**The purge job** now also deletes closed counting periods, old crash reports, expired dashboard sessions and codes, idle sign-in limits and audit entries over 90 days old, so point it at the new image after the deploy (see "After a deploy: the jobs' image").

## Group sync (decision 0035)

The routes under `/v1/spaces` ship with the server (README, "Group sync"). Until the licence key is set they refuse every licence, so no shared space can be made. Before turning it on, in this order:

1. **Request logs.** The server's own log lines carry no space id, member key or address. Google's request log does record each request's URL, which holds the space id and, for `…/members/{key}`, a member's key, and the caller's address, and keeps them for 30 days by default. Decision 0033 allows no address in logs beyond 7 days. Excluding these routes, as for app status and crash reports, keeps that rule. It is the owner's call, since the routes then leave no request log to look back at:

   ```sh
   gcloud logging sinks update _Default --project "$GCP_PROJECT_ID" \
     --add-exclusion=name=ngome-no-sync-request-logs,description="Decision 0035: no request logs for group sync",filter='resource.type="cloud_run_revision" AND resource.labels.service_name="'"$CLOUD_RUN_SERVICE"'" AND log_id("run.googleapis.com/requests") AND httpRequest.requestUrl:"/v1/spaces/"'
   ```

2. **Object storage first.** Batches go to the blob store the vault uses. The server reads from one store at a time, so [add R2](#adding-r2) before the first space is made; batches left in Postgres could not be read after the move.
3. **The purge job's image.** The daily purge now also deletes old nonces, batches everyone has pulled once they are 90 days old, and objects left by a push that died. Point it at the new image (see "After a deploy: the jobs' image").
4. **The licence key.** Make the pair on your own machine, and keep the private key file offline; it goes nowhere near GitHub or Cloud Run until the licence issuer (decision 0032) needs it. The public key is not a secret, so it is a plain variable and needs no change to the Sync settings workflow:

   ```sh
   uv run ngome-licence-key new licence.key      # prints NGOME_LICENCE_PUBLIC_KEY=<key>
   gh variable set NGOME_LICENCE_PUBLIC_KEY --env production --body "<key>"
   gh workflow run "Sync settings"
   ```

   To turn group sync off again, remove the variable and sync. No new space can be made and none can be renewed; spaces that exist carry on until their licence runs out, then go read-only.

The limits (`NGOME_GROUP_SYNC_KEY_REQUESTS_PER_MINUTE`, `NGOME_GROUP_SYNC_KEY_PUSHES_PER_MINUTE`, `NGOME_GROUP_SYNC_ADDRESS_REQUESTS_PER_MINUTE`) are kept in each instance's memory, so with the service's maximum of 3 instances a caller can get up to three times each. Many phones can share one address on a mobile network; raise the per-address limit if phones report `rate_limited`.

To try it against a test build of the app, mint a licence with the private key (`uv run ngome-licence-key mint --key-file licence.key --days 30`). The app has no place to hold a licence yet (decision 0032), so a test build needs a small change to send it.

## Adding R2

1. In Cloudflare, create an R2 bucket with the EU jurisdiction, and an API token with Object Read & Write on that bucket only.
2. Put the settings in GitHub and sync:

   ```sh
   gh variable set NGOME_VAULT_BLOB_STORE --env production --body s3
   gh variable set NGOME_VAULT_S3_BUCKET --env production --body <bucket>
   gh variable set NGOME_VAULT_S3_ENDPOINT_URL --env production --body https://<account-id>.eu.r2.cloudflarestorage.com
   gh variable set NGOME_VAULT_S3_REGION --env production --body auto
   gh secret set NGOME_VAULT_S3_ACCESS_KEY_ID --env production
   gh secret set NGOME_VAULT_S3_SECRET_ACCESS_KEY --env production
   gh workflow run "Sync settings"
   ```

   The sync creates the two new Secret Manager secrets.

Switch before people start backing up. The server reads from one store at a time, so backups already in Postgres stay there and can't be read once it's on R2.

## One-time setup

### 1. Providers

- **Neon:** create a project in an EU region, used only by Pesa Clarity. Copy the **direct** connection string, whose host has no `-pooler`. The server converts its `sslmode` options for asyncpg.
- **Brevo:**
  1. Verify a sender. A domain you own gets the best delivery; a single address works for testing.
  2. Copy the SMTP login and an SMTP key from SMTP & API → SMTP.
  3. Under Settings → Security → Authorized IPs, deactivate blocking for SMTP keys. Cloud Run has no fixed outgoing address, and Brevo otherwise refuses the login with `525 5.7.1 Unauthorized IP address`.

### 2. Google Cloud accounts

```sh
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com \
  secretmanager.googleapis.com cloudscheduler.googleapis.com playintegrity.googleapis.com

# The API and both jobs run as this account. It can read secrets and nothing else.
gcloud iam service-accounts create "${RUNTIME%%@*}" --display-name "Pesa Clarity API"
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" --condition=None \
  --member "serviceAccount:$RUNTIME" --role roles/secretmanager.secretAccessor

# Keyless sign-in for the Sync settings workflow, from this repository's production environment only.
NUMBER="$(gcloud projects describe "$GCP_PROJECT_ID" --format 'value(projectNumber)')"
REPO=pesaclarity/pesaclarity-backend DEPLOY=<deploy account>@$GCP_PROJECT_ID.iam.gserviceaccount.com
gcloud iam workload-identity-pools create github --location global --display-name GitHub
gcloud iam workload-identity-pools providers create-oidc pesaclarity-backend --location global \
  --workload-identity-pool github --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.environment=assertion.environment \
  --attribute-condition "assertion.repository == '$REPO' && assertion.environment == 'production'"
gcloud iam service-accounts create "${DEPLOY%%@*}" --display-name "Pesa Clarity settings sync"
gcloud iam service-accounts add-iam-policy-binding "$DEPLOY" --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/$REPO"
# artifactregistry.reader: Cloud Run checks that whoever updates the service can read its image.
for role in roles/run.developer roles/secretmanager.admin roles/artifactregistry.reader; do
  gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" --condition=None --member "serviceAccount:$DEPLOY" --role "$role"
done
gcloud iam service-accounts add-iam-policy-binding "$RUNTIME" --role roles/iam.serviceAccountUser \
  --member "serviceAccount:$DEPLOY"
```

### 3. The service and auto-deploy

1. In the Cloud Run console, create a service with **Continuously deploy from a repository**:
   - Set it up with Cloud Build, using GitHub, this repository, branch `^main$` and the Dockerfile build type.
   - Allow public access, since the app calls the API without Google credentials.
   - Set the container port to `8000`, memory to 512 MiB and the maximum to 3 instances.

   Cloud Run creates the service with a placeholder image, plus a Cloud Build trigger.

2. Switch the service to the runtime account:

   ```sh
   gcloud run services update "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --service-account "$RUNTIME"
   ```

3. Turn on BuildKit in the trigger. It builds with Docker's legacy builder, and the Dockerfile's cache mounts need BuildKit; without it the build fails with `the --mount option requires BuildKit`.

   ```sh
   TRIGGER="$(gcloud builds triggers list --filter 'github.name=pesaclarity-backend' --format 'value(name)')"
   gcloud builds triggers describe "$TRIGGER" --format json \
     | jq '(.build.steps[] | select(.id == "Build")) += {env: ["DOCKER_BUILDKIT=1"]}' > trigger.json
   gcloud builds triggers import --source trigger.json && rm trigger.json
   ```

### 4. Settings in GitHub

Restrict the `production` environment to `main`, so no other branch's workflow can read its secrets:

```sh
gh api -X PUT repos/{owner}/{repo}/environments/production --input - <<'EOF'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
EOF
gh api -X POST repos/{owner}/{repo}/environments/production/deployment-branch-policies -f name=main -f type=branch
```

Then set the names the workflow uses: the seven `GCP_*` and `CLOUD_RUN_*` variables listed under [How it fits together](#how-it-fits-together). For example: `gh variable set GCP_REGION --env production --body "$GCP_REGION"`.

**Secrets**

```sh
gh secret set NGOME_DATABASE_URL --env production    # the Neon direct connection string
gh secret set NGOME_SMTP_PASSWORD --env production   # the Brevo SMTP key
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' | gh secret set NGOME_JWT_SECRET --env production
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' | gh secret set NGOME_CONTACT_PEPPER --env production
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' | gh secret set NGOME_ADMIN_TOKEN --env production
python3 -c 'import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode(), end="")' | gh secret set NGOME_ADMIN_SECRET_KEY --env production
```

The app status signing key (README, "App status and notices"): make a pair with `uv run ngome-app-status-key`, set the seed with `gh secret set NGOME_APP_STATUS_SIGNING_SEED --env production` (paste it when asked) and put the public key in the app's pinned list. Keep an offline copy of the seed: a new seed needs an app release that pins its public key first.

After the first sync, Secret Manager holds the contact pepper as version 1. Keep an offline copy as well.

**Variables.** Set each with `gh variable set <name> --env production --body <value>`:

| Variable | Value |
| --- | --- |
| `NGOME_ENVIRONMENT` | `production` |
| `NGOME_LOG_JSON` | `true` |
| `NGOME_EMAIL_PROVIDER` | `smtp` |
| `NGOME_EMAIL_FROM` | `Pesa Clarity <sender@your-domain>`, the verified Brevo sender |
| `NGOME_SMTP_HOST`, `NGOME_SMTP_PORT` | `smtp-relay.brevo.com`, `587` |
| `NGOME_SMTP_USERNAME` | The Brevo SMTP login |
| `NGOME_SMTP_TIMEOUT_SECONDS` | `10` |
| `NGOME_EMAIL_CODE_SUBJECT` | `Your Pesa Clarity code: {code}` |
| `NGOME_EMAIL_CODE_BODY` | The email text, with `{code}` and `{minutes}`. It spans several lines, so set it from a file: `gh variable set NGOME_EMAIL_CODE_BODY --env production < body.txt` |
| `NGOME_GOOGLE_SIGN_IN_ENABLED` | `false`, until there's a web OAuth client id. Then `true`, plus `NGOME_GOOGLE_CLIENT_IDS` as `["<id>.apps.googleusercontent.com"]` |
| `NGOME_PLAY_INTEGRITY_ENABLED` | `true` |
| `NGOME_PLAY_INTEGRITY_PACKAGE_NAME` | `com.pesaclarity.app` |
| `NGOME_PLAY_INTEGRITY_DEVICE_VERDICT` | `MEETS_DEVICE_INTEGRITY` |
| `NGOME_PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS` | `300` |
| `NGOME_APP_ATTEST_ENABLED` | `false`, until there's an Apple team id. Then `true`, plus `NGOME_APP_ATTEST_APP_ID` (`<team id>.com.pesaclarity.app`) and `NGOME_APP_ATTEST_ENVIRONMENT` (`production`) |
| `NGOME_VAULT_UNATTESTED_UPLOADS` | `allow`, because F-Droid builds can't attest |
| `NGOME_VAULT_BLOB_STORE` | `postgres` until [R2](#adding-r2) |
| `NGOME_LICENCE_PUBLIC_KEY` | Unset until group sync is turned on ([Group sync](#group-sync-decision-0035)). Then the licence key's public half, base64url |
| `NGOME_PRIVACY_POLICY_SHA256` | The SHA-256 of each approved privacy policy, as a JSON list: `["<digest>"]`, where the digest is `sha256sum assets/policy/privacy_policy.md` in pesaclarity-app. Add each new version's digest when the app ships it, and keep older ones while older app versions are in use. Unset keeps the policy email off |
| `FORWARDED_ALLOW_IPS` | `*` |
| `NGOME_PROXY_HOPS` | `1` (the default). Where the caller's address sits in `X-Forwarded-For`, counted from the right: Cloud Run appends it last, and anything to its left is written by the caller. Set `2` only behind a Google load balancer |

Anything not listed keeps its default from `src/ngome/core/config.py`.

Now run **Sync settings** (`gh workflow run "Sync settings"`). It creates the Secret Manager secrets and puts every setting on the service. It skips the two jobs, since they don't exist yet.

### 5. First deploy, migrations and the daily purge

```sh
gcloud builds triggers run "$TRIGGER" --branch main   # or push to main
gcloud builds list --limit 1                         # wait for SUCCESS

# Create both jobs from the deployed image, with the service's settings.
img="$(gcloud run services describe "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --format 'value(spec.template.spec.containers[0].image)')"
settings="$(mktemp)"
secrets="$(tool/cloud_run_settings.sh "$GCP_PROJECT_ID" "$GCP_REGION" "$CLOUD_RUN_SERVICE" "$settings")"
gcloud run jobs deploy "$CLOUD_RUN_MIGRATE_JOB" --region "$GCP_REGION" --image "$img" \
  --command alembic --args upgrade,head --service-account "$RUNTIME" \
  --env-vars-file "$settings" --set-secrets "$secrets" --max-retries 0 --task-timeout 10m --memory 512Mi
gcloud run jobs deploy "$CLOUD_RUN_PURGE_JOB" --region "$GCP_REGION" --image "$img" \
  --command ngome-purge --service-account "$RUNTIME" \
  --env-vars-file "$settings" --set-secrets "$secrets" --max-retries 1 --task-timeout 10m --memory 512Mi
rm "$settings"
gcloud run jobs execute "$CLOUD_RUN_MIGRATE_JOB" --region "$GCP_REGION" --wait

# Daily at 03:17 Nairobi time. Runs as the default compute account, which can already start jobs.
gcloud scheduler jobs create http "$CLOUD_RUN_PURGE_JOB-daily" --location "$GCP_REGION" \
  --schedule "17 3 * * *" --time-zone Africa/Nairobi \
  --uri "https://run.googleapis.com/v2/projects/$GCP_PROJECT_ID/locations/$GCP_REGION/jobs/$CLOUD_RUN_PURGE_JOB:run" \
  --http-method POST --oauth-service-account-email "$NUMBER-compute@developer.gserviceaccount.com"
```

### 6. Check it

```sh
URL="$(gcloud run services describe "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --format 'value(status.url)')"
curl -fsS "$URL/health/ready"   # {"status":"ok"}
curl -sS -X POST "$URL/v1/auth/email/start" -H 'content-type: application/json' -d '{"email":"<you@example.org>"}'
```

The second command should answer with a `challenge_id`, and a code should arrive by email. `/docs` returns 404 in production, by design.

## Other ways to deploy

`tool/deploy_cloud_run.sh` builds on Cloud Build from your machine, migrates, releases and refreshes the purge job in one go, keeping the service's settings. It reads names from `deploy.env` (see `deploy.env.example`).

The GitHub workflow "Deploy to Cloud Run" does the same from Actions. It's disabled, because Cloud Run's auto-deploy does that job. Run only one of them.
