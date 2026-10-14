#!/usr/bin/env bash
# Run Terraform for one SentinelEdge stack, with the guards ADR-0014 asks for.
#
#   scripts/tf.sh <stack> <init|plan|apply|destroy-plan|output|output-json|lock>
#
#   stack: bootstrap | account | dev
#
# - The AWS identity in use must belong to the account named in the stack's terraform.tfvars;
#   anything else is refused before Terraform runs (the provider's allowed_account_ids is the
#   second guard).
# - `plan` and `destroy-plan` save the plan to <stack>/tfplan; `apply` applies only that saved
#   plan, so what changes is exactly what was reviewed. There is no auto-approve.
# - Stacks other than bootstrap keep remote state: `init` writes their backend.hcl (git-ignored)
#   from the state bucket and key that bootstrap created.
#
# Credentials come from the AWS CLI profile in AWS_PROFILE (signed in with `aws login`). Nothing
# here stores or prints them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACKS=(bootstrap account dev)
PLATFORMS=(-platform=linux_amd64 -platform=darwin_arm64)

die() { printf 'tf: %s\n' "$*" >&2; exit 2; }
usage() { die "usage: scripts/tf.sh <bootstrap|account|dev> <init|plan|apply|destroy-plan|output|output-json|lock>"; }

[[ $# -eq 2 ]] || usage
STACK="$1"
CMD="$2"
case " ${STACKS[*]} " in *" $STACK "*) ;; *) usage ;; esac

case "$STACK" in
  bootstrap | account) DIR="$ROOT/terraform/$STACK" ;;
  *) DIR="$ROOT/terraform/environments/$STACK" ;;
esac
[[ -d "$DIR" ]] || die "no stack at ${DIR#"$ROOT"/}"

command -v terraform >/dev/null || die "terraform is not installed (see docs/aws-setup.md)"
TF_VERSION="$(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')"
python3 - "$TF_VERSION" <<'PY' || die "Terraform $TF_VERSION is too old: 1.11 or later is needed (S3 state locking, write-only secrets)"
import sys
major, minor = (int(p) for p in sys.argv[1].split(".")[:2])
sys.exit(0 if (major, minor) >= (1, 11) else 1)
PY

tf() { terraform -chdir="$DIR" "$@"; }

# The account the stack is allowed to change, from its terraform.tfvars.
tfvars_account() {
  local file="$DIR/terraform.tfvars"
  [[ -f "$file" ]] || die "${file#"$ROOT"/} is missing: copy terraform.tfvars.example and fill it in"
  local id
  id="$(sed -nE 's/^[[:space:]]*account_id[[:space:]]*=[[:space:]]*"([0-9]{12})".*/\1/p' "$file" | head -n1)"
  [[ -n "$id" ]] || die "${file#"$ROOT"/} has no account_id"
  printf '%s' "$id"
}

check_identity() {
  command -v aws >/dev/null || die "the AWS CLI is not installed (see docs/aws-setup.md)"
  local want have arn
  want="$(tfvars_account)"
  have="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
    || die "no usable AWS credentials: sign in first (docs/aws-setup.md)"
  arn="$(aws sts get-caller-identity --query Arn --output text)"
  [[ "$have" == "$want" ]] || die "signed in to account $have, but $STACK may only change $want"
  [[ "$arn" != *":root" ]] || die "refusing to run as the root user: sign in with aws login (docs/aws-setup.md)"
  printf 'tf: %s in account %s as %s\n' "$STACK" "$have" "${arn##*/}" >&2
  export_credentials
}

# `aws login` keeps its session in the CLI's own cache, which not every SDK reads, and the
# credentials it hands out last only about 15 minutes (the CLI renews them itself). Exporting them
# once let a long apply outlive them ("ExpiredToken" while waiting for CloudFront, second deploy
# window). Instead Terraform gets a temporary AWS config whose one profile asks the CLI for fresh
# credentials whenever the old ones expire (credential_process). Nothing is printed or stored: the
# file holds only the command, and it is deleted when this script exits.
export_credentials() {
  if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
    return # credentials already in the environment (not from aws login): use them as they are
  fi
  aws configure export-credentials --format process >/dev/null \
    || die "could not read the AWS session: run aws login again (docs/aws-setup.md)"
  local real_config="${AWS_CONFIG_FILE:-$HOME/.aws/config}" profile="${AWS_PROFILE:-default}"
  TF_AWS_CONFIG="$(mktemp)"
  trap 'rm -f "$TF_AWS_CONFIG"' EXIT
  printf '[profile sentineledge-terraform]\ncredential_process = %s\n' \
    "$(printf '%q ' env "AWS_CONFIG_FILE=$real_config" aws configure export-credentials \
      --profile "$profile" --format process)" >"$TF_AWS_CONFIG"
  export AWS_CONFIG_FILE="$TF_AWS_CONFIG" AWS_PROFILE=sentineledge-terraform
  unset AWS_CREDENTIAL_EXPIRATION
}

write_backend_config() {
  local account region bucket key_arn
  account="$(tfvars_account)"
  region="$(sed -nE 's/^[[:space:]]*region[[:space:]]*=[[:space:]]*"([a-z0-9-]+)".*/\1/p' "$DIR/terraform.tfvars" | head -n1)"
  region="${region:-us-east-2}"
  bucket="sentineledge-tfstate-$account"
  aws s3api head-bucket --bucket "$bucket" --region "$region" >/dev/null 2>&1 \
    || die "state bucket $bucket not found: apply the bootstrap stack first"
  # The bucket policy accepts only this key's ARN, so look it up rather than use the alias.
  key_arn="$(aws kms describe-key --key-id alias/sentineledge-tfstate --region "$region" \
    --query KeyMetadata.Arn --output text)"
  umask 077
  cat > "$DIR/backend.hcl" <<EOF
# Written by scripts/tf.sh from the bootstrap stack's resources. Git-ignored.
bucket     = "$bucket"
region     = "$region"
kms_key_id = "$key_arn"
EOF
}

init() {
  if [[ "$STACK" == bootstrap ]]; then
    tf init -input=false
  else
    write_backend_config
    tf init -input=false -backend-config=backend.hcl
  fi
}

case "$CMD" in
  init)
    check_identity
    init
    ;;
  plan | destroy-plan)
    check_identity
    [[ -d "$DIR/.terraform" ]] || init
    flags=(-input=false -out=tfplan -detailed-exitcode)
    [[ "$CMD" == destroy-plan ]] && flags+=(-destroy)
    # -detailed-exitcode: 0 no changes, 1 error, 2 changes to review.
    rc=0
    tf plan "${flags[@]}" || rc=$?
    case "$rc" in
      0)
        rm -f "$DIR/tfplan"
        printf '\ntf: no changes: nothing to apply\n'
        ;;
      2)
        printf '\ntf: plan saved to %s. Review it, then: scripts/tf.sh %s apply\n' \
          "${DIR#"$ROOT"/}/tfplan" "$STACK"
        ;;
      *)
        rm -f "$DIR/tfplan"
        exit "$rc"
        ;;
    esac
    ;;
  apply)
    check_identity
    [[ -f "$DIR/tfplan" ]] || die "no saved plan: run scripts/tf.sh $STACK plan first"
    # A saved plan is used once: after a failed apply the state has moved on and the plan is
    # stale, so it is discarded either way and the next step is always a fresh plan.
    if ! tf apply -input=false tfplan; then
      rm -f "$DIR/tfplan"
      die "apply failed and the saved plan was discarded: fix the cause, then plan again"
    fi
    rm -f "$DIR/tfplan"
    ;;
  output)
    [[ "$STACK" == bootstrap ]] || check_identity
    tf output
    ;;
  output-json)
    # For scripts (images-push.sh, ecs-task.sh): the same guard, machine-readable output.
    [[ "$STACK" == bootstrap ]] || check_identity
    tf output -json
    ;;
  lock)
    # `init` already records HashiCorp's signed checksums (zh:) for every platform. This adds the
    # package hashes (h1:) for Linux (the owner's machine and CI) and Apple silicon.
    tf providers lock "${PLATFORMS[@]}"
    ;;
  *) usage ;;
esac
