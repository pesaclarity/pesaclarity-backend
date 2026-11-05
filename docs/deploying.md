# Deploying to Cloud Run

How the server runs in production, and the commands to set it up and look after it. Everything here runs from a terminal with `gcloud`, `gh` and `jq`, plus a few clicks in the Cloud Run and GitHub consoles. The design is in [specs 0001](specs/0001-settings-live-on-cloud-run.md) and [0002](specs/0002-github-holds-settings.md).

## How it fits together

| Piece | Where | How it changes |
| --- | --- | --- |
| API | Cloud Run service | Cloud Run's auto-deploy: every push to `main` builds the `Dockerfile` on Cloud Build and swaps the service's image. Nothing else on the service changes. |
| Settings | GitHub, `production` environment: secrets as environment secrets, everything else as environment variables | Edit them in GitHub, then run the **Sync settings** workflow. It checks them, puts secrets in Secret Manager and applies everything to the service and both jobs. |
| Database | Postgres on Neon | The migrate job (`alembic upgrade head`), run by hand when a change adds a migration |
| Retention | The purge job (`ngome-purge`) | Cloud Scheduler starts it daily |
| Sign-in email | Brevo, over SMTP | |
| Backups | Postgres for now; Cloudflare R2 later ([Adding R2](#adding-r2)) | |

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

Merge to `main` (README, "Branches and releases"). To watch the build: `gcloud builds list --limit 3`. A failed build, or a revision that doesn't start, leaves the previous revision serving.

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

The workflow names each secret it reads: the six secret settings the server has (database URL, JWT secret, contact pepper, SMTP password and the two R2 keys). A new secret setting has to be added to `.github/workflows/sync-settings.yml` as well.

GitHub may hold a Sync settings run for approval when it flags a workflow as potentially malicious. Approve the run on its page in the Actions tab, signed in with write access.

**Never change `NGOME_CONTACT_PEPPER`.** It keys every account, and the sync refuses to apply a new value. If a run fails on it, put the original value back: `gcloud secrets versions access 1 --secret <pepper secret>`.

### When a change adds a migration

Auto-deploy doesn't run migrations. Run them right after the deploy finishes; until then, the new code is running on the old schema.

```sh
img="$(gcloud run services describe "$CLOUD_RUN_SERVICE" --region "$GCP_REGION" --format 'value(spec.template.spec.containers[0].image)')"
gcloud run jobs update "$CLOUD_RUN_PURGE_JOB" --region "$GCP_REGION" --image "$img"
gcloud run jobs update "$CLOUD_RUN_MIGRATE_JOB" --region "$GCP_REGION" --image "$img"
gcloud run jobs execute "$CLOUD_RUN_MIGRATE_JOB" --region "$GCP_REGION" --wait
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
```

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
| `NGOME_PRIVACY_POLICY_SHA256` | The SHA-256 of each approved privacy policy, as a JSON list: `["<digest>"]`, where the digest is `sha256sum assets/policy/privacy_policy.md` in pesaclarity-app. Add each new version's digest when the app ships it, and keep older ones while older app versions are in use. Unset keeps the policy email off |
| `FORWARDED_ALLOW_IPS` | `*` |

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
