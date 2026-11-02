#!/usr/bin/env bash
# Applies the settings kept in GitHub's production environment to Cloud Run
# (docs/specs/0002, docs/deploying.md). NGOME_* secrets go to Secret Manager;
# the service and both jobs get every setting and the secret references.
# Run by .github/workflows/sync-settings.yml.
#
# Usage: tool/sync_settings.sh <variables json> <secrets json>
#   Each file maps names to values, as toJSON(vars) and toJSON(secrets) give them.
#   Names come from GCP_PROJECT_ID, GCP_REGION, CLOUD_RUN_SERVICE,
#   CLOUD_RUN_MIGRATE_JOB and CLOUD_RUN_PURGE_JOB.
# Needs: gcloud and jq. Never prints a secret value.
set -euo pipefail

[ $# -eq 2 ] || { echo "Usage: $0 <variables json> <secrets json>" >&2; exit 2; }
vars_json="$1" secrets_json="$2"
for name in GCP_PROJECT_ID GCP_REGION CLOUD_RUN_SERVICE CLOUD_RUN_MIGRATE_JOB CLOUD_RUN_PURGE_JOB; do
  [ -n "${!name:-}" ] || { echo "$name is not set" >&2; exit 1; }
done
project=(--project "$GCP_PROJECT_ID")
where=("${project[@]}" --region "$GCP_REGION")
# Keys every account's contact hash: a new value would orphan them all, so it is
# only ever compared with its first version, never replaced.
pepper=NGOME_CONTACT_PEPPER

work="$(mktemp -d)"
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

jq 'with_entries(select((.key | startswith("NGOME_")) or .key == "FORWARDED_ALLOW_IPS"))' \
  "$vars_json" > "$work/env.json"

# NGOME_SMTP_PASSWORD -> pesaclarity-smtp-password
secret_for() { printf 'pesaclarity-%s' "$(printf '%s' "${1#NGOME_}" | tr 'A-Z_' 'a-z-')"; }

# First decide what each secret needs, so a refused pepper change leaves everything untouched.
names=()
actions=()
while IFS= read -r name; do
  secret="$(secret_for "$name")"
  jq -j --arg k "$name" '.[$k]' "$secrets_json" > "$work/$name"
  version=latest
  [ "$name" = "$pepper" ] && version=1
  if ! gcloud secrets describe "$secret" "${project[@]}" > /dev/null 2>&1; then
    action=create
  elif gcloud secrets versions access "$version" --secret "$secret" "${project[@]}" 2> /dev/null \
    | cmp -s - "$work/$name"; then
    action=keep
  elif [ "$name" = "$pepper" ]; then
    echo "$name in GitHub differs from $secret in Secret Manager. It must never change:" \
      "a new value orphans every account. Put the original value back in GitHub." >&2
    exit 1
  else
    action=update
  fi
  names+=("$name")
  actions+=("$action")
done < <(jq -r 'keys[] | select(startswith("NGOME_"))' "$secrets_json")

[ ${#names[@]} -gt 0 ] || { echo "No NGOME_* secrets in GitHub; refusing to remove them all." >&2; exit 1; }

refs=()
for i in "${!names[@]}"; do
  name="${names[$i]}"
  secret="$(secret_for "$name")"
  case "${actions[$i]}" in
    create)
      gcloud secrets create "$secret" "${project[@]}" --data-file "$work/$name" --quiet > /dev/null
      echo "$name: created $secret" ;;
    update)
      gcloud secrets versions add "$secret" "${project[@]}" --data-file "$work/$name" --quiet > /dev/null
      echo "$name: new version of $secret" ;;
    keep)
      echo "$name: unchanged" ;;
  esac
  rm -f "$work/$name"
  if [ "$name" = "$pepper" ]; then refs+=("$name=$secret:1"); else refs+=("$name=$secret:latest"); fi
done
secret_refs="$(IFS=,; printf '%s' "${refs[*]}")"

# Both flags replace what is there, so settings removed in GitHub leave Cloud Run too.
echo "Updating $CLOUD_RUN_SERVICE with $(jq length "$work/env.json") settings and ${#refs[@]} secrets..."
gcloud run services update "$CLOUD_RUN_SERVICE" "${where[@]}" \
  --env-vars-file "$work/env.json" --set-secrets "$secret_refs" --quiet
for job in "$CLOUD_RUN_MIGRATE_JOB" "$CLOUD_RUN_PURGE_JOB"; do
  # On a new setup the jobs come after the first deploy (docs/deploying.md).
  if ! gcloud run jobs describe "$job" "${where[@]}" > /dev/null 2>&1; then
    echo "Job $job doesn't exist yet; skipped."
    continue
  fi
  echo "Updating job $job..."
  gcloud run jobs update "$job" "${where[@]}" \
    --env-vars-file "$work/env.json" --set-secrets "$secret_refs" --quiet
done
echo "Settings applied."
