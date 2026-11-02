#!/usr/bin/env bash
# Reads the settings of the Cloud Run service so deploys can copy them onto the
# migrate and purge jobs. The service is the one place settings live (README,
# "Settings on Cloud Run"; docs/specs/0001).
#
# Writes the plain env vars to <env file> as JSON (which --env-vars-file accepts
# as YAML) and prints the Secret Manager references as ENV=secret:version pairs
# for --set-secrets.
#
# Usage: tool/cloud_run_settings.sh <project> <region> <service> <env file to write>
# Needs: gcloud and jq.
set -euo pipefail

[ $# -eq 4 ] || { echo "Usage: $0 <project> <region> <service> <env file to write>" >&2; exit 2; }
project="$1" region="$2" service="$3" env_file="$4"

spec="$(gcloud run services describe "$service" --project "$project" --region "$region" --format json)" || {
  echo "Could not read Cloud Run service $service in $region. If it doesn't exist yet, create it once (README, \"Settings on Cloud Run\")." >&2
  exit 1
}

env='.spec.template.spec.containers[0].env // [] | .[]'
# An env var set to "" comes back with no value at all.
jq "[$env | select(.valueFrom == null) | {(.name): (.value // \"\")}] | add // {}" <<<"$spec" > "$env_file"
secrets="$(jq -r "[$env | select(.valueFrom.secretKeyRef) |
  \"\(.name)=\(.valueFrom.secretKeyRef.name):\(.valueFrom.secretKeyRef.key)\"] | join(\",\")" <<<"$spec")"

# Without this the jobs would quietly run with no JWT secret or contact pepper.
[ -n "$secrets" ] || {
  echo "Service $service has no Secret Manager references; set its secrets first (README, \"Settings on Cloud Run\")." >&2
  exit 1
}
printf '%s\n' "$secrets"
