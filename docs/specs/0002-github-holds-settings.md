# 0002 — GitHub's production environment holds the settings

**Status:** Implemented
**Date:** 2026-11-02

Builds on [0001](0001-settings-live-on-cloud-run.md). The Cloud Run service still holds the running settings, and deploys (Cloud Run's auto-deploy trigger on `main`) still only swap the image. What changes is where the values are managed: in GitHub, pushed to Cloud Run by a workflow.

## Problem

Settings are edited by hand: env vars on the Cloud Run service, secrets in Secret Manager, and a copy onto each job. We want one place to manage them, in GitHub's `production` environment, with the secrets loaded into Cloud Run without ever being printed.

## Goals / Non-goals

Goals

- GitHub's `production` environment holds every setting. Secrets (`NGOME_DATABASE_URL`, `NGOME_JWT_SECRET`, `NGOME_CONTACT_PEPPER`, `NGOME_SMTP_PASSWORD`) are environment secrets, and the other 19 are environment variables. *Done: copied from Cloud Run.*
- Only workflows running on `main` can read them. *Done: an environment branch policy.*
- A **Sync settings** workflow checks the values and applies them to Secret Manager, the service and both jobs.

Non-goals

- Syncing on every push. A sync runs when you start it.
- Reading values back from GitHub. GitHub secrets are write-only, so Secret Manager remains the place to recover a value.
- Changes to the Cloud Build trigger, Neon or Brevo.

## Approach

**Workflow** `.github/workflows/sync-settings.yml`, started from the Actions tab (`workflow_dispatch` only):

1. Runs in the `production` environment, signing in to Google Cloud without a stored key (workload identity federation) as a deploy account. That account trusts only this repository's `production` environment.
2. **Checks first.** The server's own `Settings()` validation runs on the GitHub values (`uv sync`, then a short Python check). A bad value, such as `NGOME_SMTP_PORT=abc` or a missing secret, fails the run before anything changes.
3. Runs `tool/sync_settings.sh`, which reads the values from two files. One comes from `toJSON(vars)`. The other comes from the six secret settings the server has, each named in the workflow, with unset ones left out. (`toJSON(secrets)` was tried first: GitHub held those runs for approval as potentially malicious, since a run that collects every secret looks like theft.) Both files are written to `RUNNER_TEMP` with mode 0600, and values are never echoed (GitHub also masks secrets in logs). The script then:
   - **Plain settings:** variables named `NGOME_*`, plus `FORWARDED_ALLOW_IPS`, become the env file.
   - **Secrets:** each `NGOME_*` secret maps to the Secret Manager secret `pesaclarity-` plus the name without `NGOME_`, lowercased, with `_` turned into `-`. That matches the four that exist. A missing secret is created. An existing one gets a new version only when the value differs.
   - **Contact pepper:** if `NGOME_CONTACT_PEPPER` differs from Secret Manager, the run fails and nothing is applied. Changing it would orphan every account.
   - **Service:** `gcloud run services update --env-vars-file … --set-secrets …` replaces both sets. The pepper reference stays pinned to version `1`, and the rest use `latest`. If the new revision fails to start, Cloud Run keeps serving the old one and the run fails.
   - **Jobs:** both get the service's settings, via `tool/cloud_run_settings.sh` and `gcloud run jobs update`.

**Access** for the deploy account `pesaclarity-deploy`, set up once by you (my permissions can't grant roles):

- `roles/run.developer` on the project: update the service and jobs.
- `roles/secretmanager.admin` on the project: create secrets for new settings, and read current values to compare.
- `roles/artifactregistry.reader` on the project: Cloud Run refuses a service update from an account that can't read the service's image.
- `roles/iam.serviceAccountUser` on the runtime account only.
- `roles/iam.workloadIdentityUser` for this repository, with a provider condition requiring `repository == pesaclarity/pesaclarity-backend` and `environment == production`.

## Alternatives considered

- **Keep Cloud Run and Secret Manager as the source (0001).** GitHub would need no access to Google Cloud. Not what's wanted.
- **One multi-line `CLOUD_RUN_ENV_YAML` variable.** One thing to edit. One variable per setting is easier to change in GitHub's UI, and each change shows up on its own.
- **Secrets as plain Cloud Run env vars (no Secret Manager).** Simpler, but anyone who can view the service could read them.
- **Sync on every push to `main`.** That would race the auto-deploy, which writes to the same service. A run you start keeps changes deliberate.

## Changes

- `.github/workflows/sync-settings.yml` (new).
- `tool/sync_settings.sh` (new).
- `docs/deploying.md` (new): the CLI runbook, including how settings are managed.
- `README.md`: the "Deploying to Cloud Run" section shrinks to a summary pointing at `docs/deploying.md`, and the Retention section notes the Cloud Scheduler job.
- GitHub `production` environment: the variables `GCP_PROJECT_ID`, `GCP_REGION`, `CLOUD_RUN_SERVICE`, `CLOUD_RUN_MIGRATE_JOB`, `CLOUD_RUN_PURGE_JOB`, `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_DEPLOY_SERVICE_ACCOUNT`. These are environment-level, so the dormant `deploy-cloud-run.yml` (which checks a repository-level `GCP_PROJECT_ID`) stays off.

## Acceptance criteria

- [ ] A variable changed in GitHub, followed by a Sync run, shows the new value on the service and both jobs. The image is unchanged.
- [ ] A secret changed in GitHub becomes a new Secret Manager version that the new revision uses, and no value appears in the run's logs.
- [ ] Unchanged secrets get no new version.
- [ ] A changed `NGOME_CONTACT_PEPPER` fails the run, and nothing is applied.
- [ ] An invalid setting fails at the check step, and nothing is applied.
- [ ] A variable or secret deleted in GitHub disappears from the service and jobs on the next sync.
- [ ] The workflow can't use `production` from any branch but `main`.

## Edge cases

- **New secret** (the R2 keys, later): its Secret Manager secret is created.
- **Removed secret:** its reference leaves the service, and the Secret Manager secret is kept.
- **Multi-line and empty values** go through the JSON env file.
- **Auto-deploy at the same moment:** gcloud's update conflicts and one side fails. Re-run it.
- **Edits made directly on Cloud Run** are overwritten by the next sync. GitHub wins.

## Test plan

- **Offline:** `tool/sync_settings.sh` against a fake `gcloud`. Cover a changed variable, a changed and an unchanged secret, a new secret, a changed pepper (must fail) and a removed secret.
- **Live demo:** set `NGOME_LOG_LEVEL=DEBUG` in GitHub, run Sync, check the service and jobs, then remove it and sync again.

## Rollout & rollback

Rollout: you run the access commands once. I add the workflow and script, which have to be on `main` for the Actions tab to offer them, set the `GCP_*` environment variables, and run the demo.

Rollback: disable the workflow (`gh workflow disable "Sync settings"`). Cloud Run keeps the last settings applied. To remove GitHub's access, delete the workload identity pool.

## Open questions

1. Getting it onto `main`: push straight to `main` like your last commit, or a PR to `dev` and then a release?
