#!/usr/bin/env bash
# Terraform checks for every stack and module, with no AWS credentials and no state:
# fmt, validate (init -backend=false), the module tests (terraform test, with a mocked AWS
# provider), and TFLint. Checkov runs with the other scanners (`make scan`, and CI's
# security-scans job). Used by `make tf-check` and by CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF="$ROOT/terraform"
STACKS=(bootstrap account environments/dev)

command -v terraform >/dev/null || { echo "tf-check: terraform is not installed (see docs/aws-setup.md)" >&2; exit 2; }

# Download each provider once, not once per stack and module.
export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"
mkdir -p "$TF_PLUGIN_CACHE_DIR"

echo "==> terraform fmt"
terraform fmt -check -recursive -diff "$TF"

# init with a throwaway data directory: never touches a stack's real .terraform or backend.
init_throwaway() {
  local dir="$1" data_dir="$2"
  TF_DATA_DIR="$data_dir" terraform -chdir="$dir" init -backend=false -input=false -no-color >"$data_dir/init.log" \
    || { cat "$data_dir/init.log"; rm -rf "$data_dir"; exit 1; }
}

for stack in "${STACKS[@]}"; do
  [[ -d "$TF/$stack" ]] || continue
  echo "==> terraform validate: $stack"
  data_dir="$(mktemp -d)"
  init_throwaway "$TF/$stack" "$data_dir"
  TF_DATA_DIR="$data_dir" terraform -chdir="$TF/$stack" validate -no-color
  rm -rf "$data_dir"
done

for module in "$TF"/modules/*/; do
  module="${module%/}"
  name="${module#"$TF"/}"
  data_dir="$(mktemp -d)"
  init_throwaway "$module" "$data_dir"
  echo "==> terraform validate: $name"
  TF_DATA_DIR="$data_dir" terraform -chdir="$module" validate -no-color
  if [[ -d "$module/tests" ]]; then
    echo "==> terraform test: $name"
    TF_DATA_DIR="$data_dir" terraform -chdir="$module" test -no-color
  fi
  rm -rf "$data_dir"
done

if command -v tflint >/dev/null; then
  echo "==> tflint"
  (cd "$TF" && tflint --init --config "$TF/.tflint.hcl" >/dev/null && tflint --recursive --config "$TF/.tflint.hcl")
else
  echo "==> tflint not installed: skipped here (CI runs it)"
fi

echo "tf-check: all stacks and modules pass"
