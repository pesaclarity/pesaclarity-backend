#!/usr/bin/env bash
# Deploys the server to Cloud Run from your own machine or Cloud Shell, without
# GitHub Actions: the same steps as .github/workflows/deploy-cloud-run.yml, but
# the image is built by Cloud Build, so no local Docker is needed.
#
# Names come from an env file with the same names as the workflow's
# repository variables (copy deploy.env.example to deploy.env; it is
# git-ignored). The server's settings live on the Cloud Run service (README,
# "Settings on Cloud Run"): deploys keep them, and copy them onto the migrate
# and purge jobs.
#
# Usage: tool/deploy_cloud_run.sh [env file]   (default: deploy.env)
# Needs: gcloud, signed in with an account that may deploy (gcloud auth login), and jq.
set -euo pipefail

cd "$(dirname "$0")/.."
env_file="${1:-deploy.env}"
[ -f "$env_file" ] || { echo "No $env_file; copy deploy.env.example and fill it in." >&2; exit 1; }
set -a
# shellcheck source=/dev/null
. "./$env_file"
set +a

missing=""
for name in GCP_PROJECT_ID GCP_REGION GCP_IMAGE GCP_RUNTIME_SERVICE_ACCOUNT CLOUD_RUN_SERVICE \
  CLOUD_RUN_MIGRATE_JOB CLOUD_RUN_PURGE_JOB CLOUD_RUN_SERVICE_FLAGS CLOUD_RUN_JOB_FLAGS; do
  [ -n "${!name:-}" ] || missing="$missing $name"
done
[ -z "$missing" ] || { echo "Missing in $env_file:$missing" >&2; exit 1; }

project=(--project "$GCP_PROJECT_ID")
where=("${project[@]}" --region "$GCP_REGION")

# Read before building, so a missing service fails in seconds rather than after a build.
settings_file="$(mktemp)"
trap 'rm -f "$settings_file"' EXIT
secrets="$(tool/cloud_run_settings.sh "$GCP_PROJECT_ID" "$GCP_REGION" "$CLOUD_RUN_SERVICE" "$settings_file")"

tag="$(git rev-parse --short=12 HEAD)$(git diff --quiet && echo '' || echo '-dirty')"
image="$GCP_IMAGE:$tag"

echo "Building $image with Cloud Build..."
gcloud builds submit "${project[@]}" --config tool/cloudbuild.yaml \
  --substitutions "_IMAGE=$image" .

echo "Migrating the database..."
# shellcheck disable=SC2086 # the flags variables hold several flags
gcloud run jobs deploy "$CLOUD_RUN_MIGRATE_JOB" "${where[@]}" --image "$image" \
  --command alembic --args upgrade,head --service-account "$GCP_RUNTIME_SERVICE_ACCOUNT" \
  --env-vars-file "$settings_file" --set-secrets "$secrets" $CLOUD_RUN_JOB_FLAGS --quiet
gcloud run jobs execute "$CLOUD_RUN_MIGRATE_JOB" "${where[@]}" --wait

echo "Releasing the API..."
# No env or secret flags: those would replace the settings on the service.
# shellcheck disable=SC2086
gcloud run deploy "$CLOUD_RUN_SERVICE" "${where[@]}" --image "$image" \
  --service-account "$GCP_RUNTIME_SERVICE_ACCOUNT" $CLOUD_RUN_SERVICE_FLAGS --quiet

echo "Updating the purge job..."
# shellcheck disable=SC2086
gcloud run jobs deploy "$CLOUD_RUN_PURGE_JOB" "${where[@]}" --image "$image" \
  --command ngome-purge --service-account "$GCP_RUNTIME_SERVICE_ACCOUNT" \
  --env-vars-file "$settings_file" --set-secrets "$secrets" $CLOUD_RUN_JOB_FLAGS --quiet

url="$(gcloud run services describe "$CLOUD_RUN_SERVICE" "${where[@]}" --format 'value(status.url)')"
curl -fsS --retry 10 --retry-delay 6 --retry-all-errors "$url/health/ready" > /dev/null
echo "Live at $url"

# Optional: keep the address in Secret Manager for the app build to read.
if [ -n "${APP_API_URL_SECRET:-}" ]; then
  if gcloud secrets describe "$APP_API_URL_SECRET" "${project[@]}" > /dev/null 2>&1; then
    printf '%s' "$url" | gcloud secrets versions add "$APP_API_URL_SECRET" "${project[@]}" --data-file -
  else
    printf '%s' "$url" | gcloud secrets create "$APP_API_URL_SECRET" "${project[@]}" --data-file -
  fi
  echo "Stored the address in secret $APP_API_URL_SECRET"
fi
