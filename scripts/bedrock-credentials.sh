#!/usr/bin/env bash
# Short-lived AWS credentials for the local API's Bedrock calls (Phase 9, ADR-0024; C-AI-07).
#
#   make bedrock-credentials [AWS_PROFILE=sentineledge] [HOURS=8]
#
# Writes .env.bedrock (mode 600, git-ignored). Whatever the profile, the container only ever gets
# credentials that can invoke one model:
#
# - A signed-in session (`aws login`, SSO) carries every permission of the person signed in, so it
#   is never written out. The script assumes the account stack's one-permission role
#   (sentineledge-local-bedrock) with it and writes that role's session instead. Assuming a role
#   from a session is capped by AWS at one hour, whatever HOURS says: run this again when it ends.
# - Long-lived IAM user keys (the Phase 9 setup) are exchanged for a session of HOURS (1-12).
#
# Run `docker compose up -d api` afterwards to load them, and `make bedrock-credentials-clear` to
# remove them.
set -euo pipefail

profile="${AWS_PROFILE:-sentineledge}"
role="${BEDROCK_ROLE:-sentineledge-local-bedrock}"
hours="${HOURS:-8}"
out=".env.bedrock"

if ! [[ "$hours" =~ ^([1-9]|1[0-2])$ ]]; then
  echo "HOURS must be a whole number from 1 to 12." >&2
  exit 2
fi
command -v aws >/dev/null || { echo "The AWS CLI v2 is required (Garuda: sudo pacman -S aws-cli-v2)." >&2; exit 2; }

creds="$(aws configure export-credentials --profile "$profile" --format process)" || {
  echo "Could not read credentials for profile '$profile': run aws login --profile $profile." >&2
  exit 2
}
if printf '%s' "$creds" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("SessionToken") else 1)'; then
  # A signed-in session can do everything that person can: never hand it to the container.
  account="$(aws sts get-caller-identity --profile "$profile" --query Account --output text)"
  creds="$(aws sts assume-role --profile "$profile" \
    --role-arn "arn:aws:iam::${account}:role/${role}" \
    --role-session-name sentineledge-local-api --duration-seconds 3600 \
    --query 'Credentials' --output json)" || {
    echo "Could not assume ${role}: apply the account stack first (make tf-plan STACK=account)." >&2
    exit 2
  }
  [[ "$hours" == 1 ]] || echo "Note: a role session from a signed-in session lasts at most 1 hour (HOURS ignored)."
else
  # Long-lived IAM user keys: exchange them for a session; only the session is written.
  creds="$(aws sts get-session-token --profile "$profile" --duration-seconds $((hours * 3600)) \
    --query 'Credentials' --output json)"
fi

umask 077
read -r -d '' to_env <<'PY' || true
import json, os, sys
c = json.loads(os.environ["CREDS"])
names = {"AccessKeyId": "AWS_ACCESS_KEY_ID", "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
         "SessionToken": "AWS_SESSION_TOKEN"}
for key, name in names.items():
    value = c.get(key) or ""
    if not value or any(ch in value for ch in "\n\r\"' #"):
        sys.exit(f"unexpected {key} from the AWS CLI")
    print(f"{name}={value}")
print("# expires " + str(c.get("Expiration", "(see AWS)")))
PY
CREDS="$creds" python3 -c "$to_env" > "$out.tmp"
mv "$out.tmp" "$out"
chmod 600 "$out"
echo "Wrote $out ($(grep '^# expires' "$out" | cut -c3-)). Load it: docker compose up -d api"
