#!/usr/bin/env bash
# The deployment end of the pipeline (Phase 11, ADR-0030). CI never holds AWS credentials: it
# builds, tests, scans and gates every commit; this script deploys a commit only after GitHub
# reports every one of CI's checks green for it, from the owner's signed-in machine.
#
#   scripts/deploy.sh preflight   the commit may be deployed (checks only, changes nothing)
#   scripts/deploy.sh plan        preflight, push its images, save the dev plan for review
#   scripts/deploy.sh finish      apply the reviewed plan, migrate, publish the SPA, then verify
#   scripts/deploy.sh verify      post-deployment checks only: the edge and the audit anchor
#
# A commit may be deployed only if it is the tip of main on GitHub, the tree is clean, and every
# check run GitHub recorded for it succeeded (none pending, none failed). The plan is still read
# by a person before `finish`: the pipeline gates; it does not replace the review.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
die() { printf 'deploy: %s\n' "$*" >&2; exit 2; }
step() { printf '\n==> %s\n' "$*"; }

repo_slug() {
  git remote get-url origin | sed -E 's#^(https://github.com/|git@github.com:)##; s#\.git$##'
}

# Every check run GitHub has for the commit must have completed successfully. Public repository:
# the read needs no token. A commit with no check runs at all is refused, never assumed green.
ci_green() {
  python3 - "$(repo_slug)" "$1" <<'PY'
import json, sys, urllib.request
slug, sha = sys.argv[1], sys.argv[2]
url = f"https://api.github.com/repos/{slug}/commits/{sha}/check-runs?per_page=100"
request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
try:
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - fixed https URL
        runs = json.load(response)["check_runs"]
except (OSError, ValueError, KeyError) as exc:
    sys.exit(f"deploy: cannot read CI results from GitHub ({type(exc).__name__}); not deploying")
if not runs:
    sys.exit(f"deploy: GitHub has no CI results for {sha[:7]}; push it and let CI finish")
bad = [r for r in runs if r["status"] != "completed" or r["conclusion"] not in ("success", "skipped")]
for r in runs:
    state = r["conclusion"] or r["status"]
    print(f"  {'ok  ' if r not in bad else 'FAIL'} {r['name']} ({state})")
if bad:
    sys.exit(f"deploy: {len(bad)} CI check(s) not green for {sha[:7]}; not deploying")
print(f"  all {len(runs)} CI checks green for {sha[:7]}")
PY
}

preflight() {
  step "Preflight: the commit may be deployed"
  [[ -z "$(git status --porcelain)" ]] || die "the working tree has uncommitted changes"
  [[ "$(git branch --show-current)" == main ]] || die "deploy from main (on $(git branch --show-current))"
  git fetch --quiet origin main
  local head remote
  head="$(git rev-parse HEAD)"
  remote="$(git rev-parse origin/main)"
  [[ "$head" == "$remote" ]] || die "HEAD ${head:0:7} is not origin/main ${remote:0:7}: pull or push first"
  printf '  main at %s (%s)\n' "${head:0:7}" "$(git describe --tags --always)"
  ci_green "$head"
}

verify() {
  step "Post-deployment checks: the edge from the internet"
  ./scripts/edge-check.sh
  step "Post-deployment checks: the audit chain against its anchor"
  ./scripts/ecs-task.sh anchor
  ./scripts/ecs-task.sh anchor-check
}

case "${1:-}" in
  preflight) preflight ;;
  plan)
    preflight
    step "Images from this commit, by digest"
    ./scripts/images-push.sh
    step "The dev plan, saved for review"
    ./scripts/tf.sh dev plan
    printf '\ndeploy: read the plan above. If it is what you expect: make deploy-finish\n'
    ;;
  finish)
    preflight
    step "Apply the reviewed plan"
    ./scripts/tf.sh dev apply
    step "Migrations, as the migrator"
    ./scripts/ecs-task.sh migrate
    step "The web app"
    ./scripts/spa-push.sh
    verify
    printf '\ndeploy: deployed and verified.\n'
    ;;
  verify) verify ;;
  *) die "usage: scripts/deploy.sh <preflight|plan|finish|verify>" ;;
esac
