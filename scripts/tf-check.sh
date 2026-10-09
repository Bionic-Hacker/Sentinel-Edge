#!/usr/bin/env bash
# Static Terraform checks for every stack, with no AWS credentials and no state:
# fmt, validate (init -backend=false), and TFLint. Checkov runs with the other scanners
# (`make scan`, and CI's security-scans job). Used by `make tf-check` and by CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF="$ROOT/terraform"
STACKS=(bootstrap account environments/dev)

command -v terraform >/dev/null || { echo "tf-check: terraform is not installed (see docs/aws-setup.md)" >&2; exit 2; }

echo "==> terraform fmt"
terraform fmt -check -recursive -diff "$TF"

for stack in "${STACKS[@]}"; do
  [[ -d "$TF/$stack" ]] || continue
  echo "==> terraform validate: $stack"
  # A throwaway data directory: never touches a stack's real .terraform or backend.
  data_dir="$(mktemp -d)"
  TF_DATA_DIR="$data_dir" terraform -chdir="$TF/$stack" init -backend=false -input=false -no-color >"$data_dir/init.log" \
    || { cat "$data_dir/init.log"; rm -rf "$data_dir"; exit 1; }
  TF_DATA_DIR="$data_dir" terraform -chdir="$TF/$stack" validate -no-color
  rm -rf "$data_dir"
done

if command -v tflint >/dev/null; then
  echo "==> tflint"
  (cd "$TF" && tflint --init --config "$TF/.tflint.hcl" >/dev/null && tflint --recursive --config "$TF/.tflint.hcl")
else
  echo "==> tflint not installed: skipped here (CI runs it)"
fi

echo "tf-check: all stacks pass"
