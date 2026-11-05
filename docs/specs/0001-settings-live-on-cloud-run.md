# 0001 — Settings live on the Cloud Run service

**Status:** Implemented, then amended
**Date:** 2026-11-02

> **As built.** Production deploys turned out to be Cloud Run's auto-deploy (a Cloud Build trigger on `main` that swaps only the image) rather than this script or workflow. The GitHub workflow is disabled. Settings are on the service as designed, and `tool/cloud_run_settings.sh` copies them onto the jobs. [0002](0002-github-holds-settings.md) moves where the values are managed to GitHub. The script and workflow changes below still stand for anyone deploying that way.

## Problem

The server's settings (`NGOME_*` env vars and Secret Manager references) live in a local, git-ignored `cloud-run.env.yaml` plus a `CLOUD_RUN_SECRETS` string. Both deploy paths (`tool/deploy_cloud_run.sh` and `.github/workflows/deploy-cloud-run.yml`) pass them with `--env-vars-file` and `--set-secrets`, and both flags *replace* every env var and secret on the target. Any setting changed in the Cloud Run console or with `gcloud run services update` is wiped on the next deploy, and the settings exist only on whichever laptop holds the YAML file.

We want the settings to be set once on Cloud Run and edited there. Deploys should only swap the image.

Nothing is deployed yet. The Google Cloud project exists. No GitHub repository variables are set, so the workflow is skipped today.

## Goals / Non-goals

Goals

- The Cloud Run **service** is the only place the settings live. Edit them in the console (Edit & deploy new revision → Variables & Secrets) or with `gcloud run services update --update-env-vars / --update-secrets`.
- Deploys keep the service's settings and change only its image (plus the existing service flags).
- The migrate and purge jobs run with exactly the service's settings. Both load the full `Settings` (see `migrations/env.py` and `ngome.auth.retention`), so they need everything the API needs.
- Secrets stay as Secret Manager references, never plain env values.

Non-goals

- Secrets mounted as files (volume secrets), sidecar containers, or settings on more than one container.
- A staging environment.
- Turning on the GitHub Actions deploy (it stays dormant until repository variables are set; see Open questions).
- Changing any application code or `Settings` defaults.

## Approach

**Single source: the service.** On every deploy, after building the image, the deploy reads the service's current settings and copies them onto both jobs:

1. `gcloud run services describe "$SERVICE" --format json`, then, from `.spec.template.spec.containers[0].env`:
   - plain vars (`value`, or no value meaning empty) go to a JSON object file `{"NAME": "value", …}`. JSON is valid YAML, so it goes straight to `--env-vars-file`. Newlines in values (the email body) and commas survive.
   - secret refs (`valueFrom.secretKeyRef {name, key}`) become `NAME=secret:version,…` for `--set-secrets`.
2. Migrate job: `gcloud run jobs deploy … --env-vars-file <that file> --set-secrets <those refs>`, then execute it. The replace semantics now work for us: the job becomes an exact mirror.
3. Service: `gcloud run deploy "$SERVICE" --image … --service-account … $CLOUD_RUN_SERVICE_FLAGS`, with **no** env or secret flags, so its settings stay as they are.
4. Purge job: mirrored the same way as step 2.

The read-and-convert logic lives in one helper, `tool/cloud_run_settings.sh <project> <region> <service> <env file to write>`. It writes the env file and prints the `--set-secrets` value. Both the script and the workflow call it, so the jq filters exist once. The helper fails if the service doesn't exist ("create it first, see README") or has no secret references. Without that check, a service with no secrets would quietly produce jobs with no `NGOME_JWT_SECRET` or `NGOME_CONTACT_PEPPER`.

The deploy script runs the "service exists" check **before** Cloud Build, so a missing service fails in seconds, not after a build.

**First-time setup (once per environment).** A service needs an image before it can hold settings, and ours doesn't exist until the first build. So we create the service once with Google's placeholder image and the settings:

```sh
gcloud run deploy "$SERVICE" --region "$REGION" --image us-docker.pkg.dev/cloudrun/container/hello \
  --port 8000 --no-allow-unauthenticated --service-account "$RUNTIME" \
  --env-vars-file cloud-run.env.yaml --set-secrets "$SECRETS"
rm cloud-run.env.yaml   # the settings now live on the service
```

The placeholder listens on `$PORT`, and it stays private until the first real deploy applies `CLOUD_RUN_SERVICE_FLAGS` (which carries `--allow-unauthenticated`). The README documents this step, and it's the only time a settings file exists.

**Secret versions.** `NGOME_CONTACT_PEPPER` is pinned to version `1`. A new version would orphan every account, so a pinned reference makes that hard to do by accident. Every other secret uses `latest`, so a rotated value is picked up by new instances and the next job run without editing the reference.

## Alternatives considered

- **Keep settings in files and re-apply them on every deploy (current setup).** Reproducible, but settings are tied to one laptop's untracked file and console edits get wiped. You chose to keep settings on Cloud Run instead.
- **Bootstrap inside the deploy script: if the service is missing, read `cloud-run.env.yaml`.** That's one command instead of two, but it keeps two sources of settings in the code. Someone editing a leftover `cloud-run.env.yaml` would see nothing change. Rejected for that footgun.
- **Settings as one Secret Manager secret (a YAML blob) that every deploy reads.** You get version history and rollback of settings for free, and everything stays in one place. But it can't be edited in the Cloud Run console, which is the point of this change. Worth revisiting if settings history starts to matter.
- **Set settings on each of the three resources by hand.** No code, but the jobs drift silently. A rotated database URL on the service would break the next migration.

## Changes

- `tool/cloud_run_settings.sh` (new): read the service's settings, write the env file, print the secret refs. Exits non-zero if the service is missing or has no secret refs.
- `tool/deploy_cloud_run.sh`: drop `CLOUD_RUN_SECRETS` / `CLOUD_RUN_ENV_YAML_FILE` from the required list and the file check. Check that the service exists before building. Mirror settings onto both jobs. Deploy the service with no env or secret flags.
- `.github/workflows/deploy-cloud-run.yml`: drop the `CLOUD_RUN_SECRETS` / `CLOUD_RUN_ENV_YAML` variables and the "Write the service settings" step. Add a "Read the service settings" step that uses the helper. Jobs take the mirrored settings, and the service deploy passes no env flags. **Changes the repository variables the workflow requires** (two fewer).
- `deploy.env.example`: remove `CLOUD_RUN_SECRETS` and `CLOUD_RUN_ENV_YAML_FILE`, and note that settings live on the service.
- `README.md`, "Deploying to Cloud Run": replace the `CLOUD_RUN_SECRETS` / `CLOUD_RUN_ENV_YAML` rows and the YAML block with a "Settings on Cloud Run" subsection covering first-time setup, the settings list (same YAML as today), how to edit them later, and that the jobs pick them up on the next deploy. Drop the `$EDITOR cloud-run.env.yaml` line from "Deploying without GitHub Actions".
- `.gitignore`: unchanged. `cloud-run.env.yaml` stays ignored because the one-time setup still uses it.

## Acceptance criteria

- [ ] After a deploy, `gcloud run services describe` shows the same env vars and secret refs as before the deploy, and the new image.
- [ ] After a deploy, the migrate and purge jobs have exactly the service's plain env vars and secret refs: same names, values and versions, nothing extra.
- [ ] A setting changed on the service (console or `gcloud run services update`) survives the next deploy and reaches both jobs.
- [ ] `NGOME_EMAIL_CODE_BODY`, a multi-line value, arrives on the jobs byte-for-byte.
- [ ] `tool/deploy_cloud_run.sh` stops before Cloud Build, with a message naming the service and pointing at the README, when the service doesn't exist.
- [ ] Neither deploy path passes `--env-vars-file` or `--set-secrets` to `gcloud run deploy`.
- [ ] `deploy.env` no longer needs `CLOUD_RUN_SECRETS` or `CLOUD_RUN_ENV_YAML_FILE`.
- [ ] `bash -n` and `shellcheck` are clean on all three scripts, and `actionlint` is clean on the workflow.
- [ ] First real deploy: migrations pass, `/health/ready` answers 200, the purge job runs and exits 0.

## Edge cases

- **Service missing:** the helper and the script fail with "Cloud Run service X not found in region Y; create it once (README, Settings on Cloud Run)". Nothing is built or changed.
- **Service with no secret refs:** the helper fails. Jobs are never deployed without `NGOME_JWT_SECRET` and `NGOME_CONTACT_PEPPER`.
- **Empty env value** (listed with no `value` key): mirrored as `""`.
- **Values with newlines, commas, `=`, quotes:** carried through the JSON env file. Secret names can't contain commas, so the `--set-secrets` string is safe.
- **Settings edited mid-deploy:** the jobs get the settings as read at the start, while the service keeps the newer ones (deploys don't touch them). The next deploy brings the jobs in line.
- **Settings edited between deploys:** the purge job runs the old settings until the next deploy. If that breaks it (for example a rotated database URL behind a pinned version), it exits non-zero and logs, so the failure is visible. The migrate job is re-mirrored right before every run, so it can't use stale settings. See Open questions.
- **Service traffic rolled back to an old revision:** the old revision keeps its own settings, but the jobs mirror the service's *latest template*, not the serving revision. Acceptable at our scale. Roll forward instead.
- **Volume-mounted secrets or a second container:** ignored (non-goal). Only `containers[0].env` is read.
- **Placeholder still serving:** until the first real deploy, the service runs `hello` privately. Nothing calls it.

## Test plan

No automated tests: the repo has no shell-script tests, and the logic is gcloud plumbing.

- **Static:** `bash -n`, `shellcheck` on the scripts, `actionlint` on the workflow (installed with Homebrew for this check).
- **Helper, offline:** run the helper's jq filters against a fixture `describe` JSON in the scratchpad. The fixture has plain vars, an empty var, a multi-line var, `latest` and pinned secrets, and a service with no secrets. Compare against the expected env file and secrets string.
- **Live (this rollout):** first-time setup, then `tool/deploy_cloud_run.sh`. Diff the service's env against each job's (`gcloud run jobs describe --format json` on the same jq path). Change one harmless setting on the service (`NGOME_LOG_LEVEL=DEBUG`), redeploy, and check it survived on the service and reached both jobs. Then set it back.

## Rollout & rollback

Rollout (done from this machine with your gcloud login, in the Google Cloud project named `pesa-clarity`; its project ID is looked up after sign-in)

1. Reuse what already exists in the project (Artifact Registry repo, runtime service account, enabled APIs), and create what's missing following README step 4, plus `cloudbuild.googleapis.com`.
2. Create the Secret Manager secrets. The JWT secret and contact pepper are generated locally and piped straight into Secret Manager, never printed. The other values (Neon URL, Brevo SMTP key, R2 keys) you write into a git-ignored file outside the repo. A script reads each value from that file into its secret, and the file is then deleted. I don't read or print the values.
3. First-time setup of the service with the settings (above).
4. Run the new `tool/deploy_cloud_run.sh`.
5. Set up the daily purge schedule (README step 6).

Rollback

- Code: revert the commit. The old script needs `CLOUD_RUN_SECRETS` and `CLOUD_RUN_ENV_YAML_FILE` back in `deploy.env`, plus a `cloud-run.env.yaml`. Regenerate it from the service with the helper.
- Deploy: `gcloud run services update-traffic "$SERVICE" --to-revisions <previous>=100`.
- Settings: each edit on the service is a new revision with its own settings, so a bad settings change rolls back the same way.

## Open questions

1. **Jobs-only sync.** Should there be a quick way to copy the service's settings onto the jobs without a rebuild (e.g. `tool/deploy_cloud_run.sh --settings-only`)? Not planned. Today a settings change reaches the jobs at the next deploy.
2. **GitHub Actions deploy.** It stays dormant (no repository variables). Do you want deploy-on-merge-to-`main` turned on, with workload identity federation and repository variables? PR #29 suggested you'd rather deploy from the script.
3. **Unattested uploads.** Plan is `allow`, because F-Droid builds can't attest and `reject` would block their backups. Say if you want `reject`.
