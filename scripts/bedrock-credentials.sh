#!/usr/bin/env bash
# Short-lived AWS credentials for the local API's Bedrock calls (Phase 9, ADR-0024).
#
#   make bedrock-credentials [AWS_PROFILE=sentineledge-bedrock] [HOURS=8]
#
# Writes .env.bedrock (mode 600, git-ignored) with a session that expires after HOURS (1-12).
# Long-lived keys from your AWS profile never enter the container: an IAM user's keys are
# exchanged for a session with `aws sts get-session-token`; SSO and role profiles already
# produce session credentials. Run `docker compose up -d api` afterwards to load them, and
# `make bedrock-credentials-clear` to remove them.
set -euo pipefail

profile="${AWS_PROFILE:-sentineledge-bedrock}"
hours="${HOURS:-8}"
out=".env.bedrock"

if ! [[ "$hours" =~ ^([1-9]|1[0-2])$ ]]; then
  echo "HOURS must be a whole number from 1 to 12." >&2
  exit 2
fi
command -v aws >/dev/null || { echo "The AWS CLI v2 is required (Garuda: sudo pacman -S aws-cli-v2)." >&2; exit 2; }

creds="$(aws configure export-credentials --profile "$profile" --format process)" || {
  echo "Could not read credentials for profile '$profile' (aws configure --profile $profile, or aws sso login)." >&2
  exit 2
}
if ! printf '%s' "$creds" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("SessionToken") else 1)'; then
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
