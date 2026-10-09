#!/usr/bin/env bash
# Run Terraform for one SentinelEdge stack, with the guards ADR-0014 asks for.
#
#   scripts/tf.sh <stack> <init|plan|apply|destroy-plan|output|lock>
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
PLATFORMS=(-platform=linux_amd64 -platform=linux_arm64 -platform=darwin_arm64 -platform=darwin_amd64)

die() { printf 'tf: %s\n' "$*" >&2; exit 2; }
usage() { die "usage: scripts/tf.sh <bootstrap|account|dev> <init|plan|apply|destroy-plan|output|lock>"; }

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
python3 - "$TF_VERSION" <<'PY' || die "Terraform $TF_VERSION is too old: 1.10 or later is needed for S3 state locking"
import sys
major, minor = (int(p) for p in sys.argv[1].split(".")[:2])
sys.exit(0 if (major, minor) >= (1, 10) else 1)
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
  printf 'tf: %s in account %s as %s\n' "$STACK" "$have" "${arn##*/}"
  export_credentials
}

# `aws login` keeps its session in the CLI's own cache, which not every SDK reads. Hand Terraform
# the same short-lived credentials through this process's environment only: they are never
# printed or written to disk, and they end with the session.
export_credentials() {
  local creds
  creds="$(aws configure export-credentials --format env)" \
    || die "could not read the AWS session: run aws login again (docs/aws-setup.md)"
  eval "$creds"
}

write_backend_config() {
  local account region bucket key_arn
  account="$(tfvars_account)"
  region="$(sed -nE 's/^[[:space:]]*region[[:space:]]*=[[:space:]]*"([a-z0-9-]+)".*/\1/p' "$DIR/terraform.tfvars" | head -n1)"
  region="${region:-us-east-2}"
  bucket="sentineledge-tfstate-$account"
  aws s3api head-bucket --bucket "$bucket" --region "$region" 2>/dev/null \
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
    flags=(-input=false -out=tfplan)
    [[ "$CMD" == destroy-plan ]] && flags+=(-destroy)
    tf plan "${flags[@]}"
    printf '\ntf: plan saved to %s. Review it, then: scripts/tf.sh %s apply\n' \
      "${DIR#"$ROOT"/}/tfplan" "$STACK"
    ;;
  apply)
    check_identity
    [[ -f "$DIR/tfplan" ]] || die "no saved plan: run scripts/tf.sh $STACK plan first"
    tf apply -input=false tfplan
    rm -f "$DIR/tfplan"
    ;;
  output)
    [[ "$STACK" == bootstrap ]] || check_identity
    tf output
    ;;
  lock)
    # Record provider checksums for every platform the stack may run on (the owner's Linux
    # machine, CI, and macOS), so `init` on any of them verifies the same binaries.
    tf providers lock "${PLATFORMS[@]}"
    ;;
  *) usage ;;
esac
