#!/usr/bin/env bash
# Run one of the one-off ECS tasks and wait for it
# (make ecs-task TASK=dbadmin|migrate|anchor|anchor-check|create-admin; Phases 4 and 5).
#
#   dbadmin       create the application's database roles and schema (once per deploy window)
#   migrate       apply database migrations (after each new API image)
#   anchor        anchor the audit chain's head now (it also runs every hour on a schedule)
#   anchor-check  check the database against the newest anchor (ADR-0005)
#   create-admin  create an administrator (EMAIL=…); the one-time password goes to Secrets
#                 Manager, never to this terminal or the task's log
#
# The task runs in the app subnets with the app security group, like the API. This prints its
# exit code and its log, and fails if the container did not exit 0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TASK="${1:-}"
die() { printf 'ecs-task: %s\n' "$*" >&2; exit 1; }
case "$TASK" in
  dbadmin | migrate | anchor | anchor-check | create-admin) ;;
  *) die "usage: scripts/ecs-task.sh dbadmin|migrate|anchor|anchor-check|create-admin" ;;
esac
# anchor-check and create-admin are task definitions with their command replaced.
FAMILY_KEY="${TASK%-check}"
OVERRIDES='{}'
if [[ "$TASK" == anchor-check ]]; then
  OVERRIDES='{"containerOverrides":[{"name":"anchor","command":["python","-m","app.cli","audit-anchor","check"]}]}'
elif [[ "$TASK" == create-admin ]]; then
  FAMILY_KEY=admin
  EMAIL="${EMAIL:-}"
  # The address goes into a JSON override and a command line: only plain addresses are accepted.
  [[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$ ]] \
    || die "set EMAIL to the administrator's e-mail address (make ecs-task TASK=create-admin EMAIL=you@example.com)"
  OVERRIDES="{\"containerOverrides\":[{\"name\":\"admin\",\"command\":[\"python\",\"-m\",\"app.cli\",\"create-admin\",\"--email\",\"$EMAIL\"]}]}"
fi

outputs="$("$ROOT/scripts/tf.sh" dev output-json)"
read -r cluster family subnets sg log_group region < <(printf '%s' "$outputs" | python3 -c '
import json, sys
o = json.load(sys.stdin)
w = (o.get("workload") or {}).get("value")
if not w:
    sys.exit("ecs-task: the workload is off: set workload = true and apply the dev stack first")
task = sys.argv[1]
print(w["cluster"], w["task_definitions"][task], ",".join(w["subnets"]), w["security_group"], w["log_groups"][task], w["region"])
' "$FAMILY_KEY")

[[ -n "${cluster:-}" ]] || die "could not read the dev stack's workload outputs"
printf 'ecs-task: starting %s in %s\n' "$family" "$cluster"
task_arn="$(aws ecs run-task --region "$region" --cluster "$cluster" --task-definition "$family" \
  --launch-type FARGATE --count 1 --started-by "make-ecs-task" --overrides "$OVERRIDES" \
  --network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$sg],assignPublicIp=DISABLED}" \
  --query 'tasks[0].taskArn' --output text)"
[[ "$task_arn" == arn:aws:ecs:* ]] || die "the task did not start"
printf 'ecs-task: %s\n' "${task_arn##*/}"

aws ecs wait tasks-stopped --region "$region" --cluster "$cluster" --tasks "$task_arn"
read -r code reason < <(aws ecs describe-tasks --region "$region" --cluster "$cluster" --tasks "$task_arn" \
  --query 'tasks[0].[containers[0].exitCode, stoppedReason]' --output text)

printf 'ecs-task: log (%s):\n' "$log_group"
aws logs get-log-events --region "$region" --log-group-name "$log_group" \
  --log-stream-name "$FAMILY_KEY/$FAMILY_KEY/${task_arn##*/}" --start-from-head --limit 60 \
  --query 'events[].message' --output text 2>/dev/null | tr '\t' '\n' | sed 's/^/  /' || true

[[ "$code" == "0" ]] || die "$TASK exited with ${code} (${reason})"
printf 'ecs-task: %s finished (exit 0)\n' "$TASK"
if [[ "$TASK" == create-admin ]]; then
  secret="$(printf '%s' "$outputs" | python3 -c 'import json,sys; print(json.load(sys.stdin)["workload"]["value"]["admin_otp_secret"])')"
  printf '\necs-task: read the one-time password once, then sign in and replace it:\n'
  printf '  aws secretsmanager get-secret-value --region %s --secret-id %s --query SecretString --output text\n' "$region" "$secret"
fi
