# Reproducing the Build

<p class="lead">These are the commands, in order, that bring SentinelEdge up from an empty machine and prove its controls. Each step says why it comes where it does. They were run on Garuda Linux with the fish shell. Every project command is a <code>make</code> target and behaves the same in bash or zsh. The few fish-specific lines are marked.</p>

## Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Docker + Compose v2 (v5 tested) + buildx | current | The local stack |
| Python (via `uv`) | 3.12 | Backend tooling and tests, matching CI |
| Node.js + npm | 22 LTS or newer | Frontend tooling and tests |
| GNU Make, OpenSSL, git, unzip | any | Entry points, secret generation |
| pre-commit | current | Local security gates |
| GitHub CLI (`gh`) | current | Pull requests and releases |
| Terraform ≥ 1.10, AWS CLI v2 | — | Not needed until Phase 3 |

## Step 1 — Prepare the machine

Install the toolchain and let your user run Docker without `sudo`. This keeps every `make` target sudo-free, and files the tools create stay owned by you. Group membership only applies to a new login session.

```
sudo pacman -S --needed git unzip make openssl docker docker-compose docker-buildx \
    nodejs npm uv pre-commit github-cli          # Arch/Garuda; use your distro's equivalents
sudo systemctl enable --now docker.service
sudo usermod -aG docker $USER
# log out completely and back in, then:
docker run --rm hello-world
```

## Step 2 — Get the source

```
mkdir -p ~/Sentinel-Edge && cd ~/Sentinel-Edge
git clone https://github.com/Bionic-Hacker/Sentinel-Edge.git sentineledge
cd sentineledge
git log --oneline -3          # main ends at the latest release merge
```

## Step 3 — Create the Python environment and install dependencies

CI runs linters, type checkers and scanners against the source, so local results only match CI if the versions match. `make install` installs hash-pinned Python packages (`--require-hashes`) and the exact npm lockfile, without running install scripts.

```
uv venv --python 3.12 --seed .venv
source .venv/bin/activate.fish        # fish; in bash/zsh: source .venv/bin/activate
make install
make precommit                        # git hooks: Gitleaks, Ruff, Bandit, ESLint
```

## Step 4 — Generate local secrets

There are no default credentials anywhere in the project. `make env` copies `.env.example`, replaces every placeholder with a distinct random value, and sets mode 600. It never overwrites an existing `.env`. Compose refuses to start without it, so it must come before the stack.

```
make env
ls -l .env                            # -rw-------
```

## Step 5 — Start the stack

`make dev` builds the images and starts them in dependency order. `db` initializes and runs the role bootstrap, `migrate` applies all migrations as `sentinel_migrator` and exits, then `api` (as `sentinel_app`) and `web` start. If startup fails, `make dev` prints a diagnosis with the fix, for example a stale database volume from an older phase.

```
make dev
docker compose ps -a                  # migrate Exited (0); db, api, web running
curl -s http://localhost:8000/api/v1/ready
xdg-open http://localhost:8080
```

## Step 6 — Create the first administrator

`create-admin` prints a one-time password, shown once. Signing in with it forces a new password and, for the admin role, authenticator-app enrollment. Save the recovery codes it shows.

```
make create-admin EMAIL=you@example.com
```

Then, in the browser, open **Settings → Users** and invite a second user, for example an ANALYST. Invitations land in the local outbox rather than a real mailbox:

```
make outbox                           # shows the one-time invitation link
```

## Step 7 — Prove the controls

Each check below demonstrates a control from the threat model on your own machine. These are the checks an interviewer may ask you to show.

```
make check              # every CI gate: lint, types, tests, SAST, SCA, secret scan
make smoke              # 56 end-to-end checks against the running stack
make verify-hardening   # 18 container and network checks
make verify-audit       # walk the audit hash chain; prints the head hash
```

Watch per-IP rate limiting, and spoofing being ignored, through the edge (fish syntax):

```
for i in (seq 22)
    curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:8080/api/v1/auth/login \
        -H 'Content-Type: application/json' -H 'Origin: http://localhost:8080' \
        -H 'X-SentinelEdge-CSRF: 1' -H 'X-Forwarded-For: 6.6.6.6' \
        -d '{"email":"nobody@example.com","password":"wrong"}'
end; echo
```

Expected: up to twenty `401` responses, then `429`. Under **Audit Logs**, filter by `ratelimit.exceeded`. There is one record for the whole burst, naming your real address (172.30.86.x), not 6.6.6.6. Then open **/apis**: the login row shows *Elevated* with the throttled count. Signed in as the analyst, the same page explains that the inventory is restricted, and no request for it is made.

Watch detection and the incident workflow (Phase 7). Send one SQL injection probe to a public
endpoint through the edge:

```
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/api/v1/health?q=1'%20OR%20'1'='1'%20--"
```

Expected: `200`, because detection never blocks. On the **Threats** page (live view) a new
*SQL injection* event appears from your own address, raised to *Critical* because the request was
served; select it to see the HTTP analysis and what matched. Then, as an admin:

1. **Automation** → *SQL injection* → **Run simulation**. The result shows the requests blocked at
   the edge and no incident (COR-003 is lowered when nothing got through).
2. **WAF** → set the SQL injection rules to *Count only*, then run the scenario again. Now the
   payloads reach the application and COR-003 fires at HIGH, opening an incident (or adding
   evidence to the open simulated one, since a detection is raised once per source in ten
   minutes).
3. **Dashboard** → *Simulated*: the amber banner, the simulated incident and traffic. *Live* shows
   none of it.
4. Open the incident, **Move to Triaged**, add a note, and check **Evidence integrity** reads
   *Verified*. Set the WAF rules back to *Block*.

Scan the build and track what it finds (Phase 8). The scanners run in digest-pinned images, so the
first run pulls them; later runs take a few minutes. `make dast` needs the stack from Step 5.

```
make scan               # SAST, dependencies, secrets, IaC, images, SBOMs, then the gate
make dast               # ZAP baseline + authenticated API scan, then the gate over everything
make scan-import        # record the scan in vulnerability management
make image-digests      # any pinned image whose tag has moved
```

Expected: each scan ends with `PASS` (or `FAIL` naming the blocking findings), and the import
prints a line such as `Imported SCAN-0003 for sentineledge: 178 findings (8 new, …); … gate passed.` Then, in the browser:

1. **Vulnerabilities**: open findings by severity, past SLA, awaiting a fix, and the last scan with
   its gate result. Filter by tool *ZAP* to see the DAST alerts.
2. Open a finding: where it was found, the fix, the deadline, and only the moves your role allows.
   As a lead, mark an expected DAST alert *False positive* with a note; it stays one on later scans.
3. **SBOM**: search for a component and download the CycloneDX document.
4. **Dashboard**: the Vulnerabilities control now shows measured values; **API Security** shows each
   endpoint's last authenticated scan.

Model threats and govern risk (Phase 10). Approving anything needs a second lead, because
whoever asks cannot approve: invite a second ADMIN or SECURITY_ENGINEER from **Users** and
complete its first sign-in in a private window.

1. **Threat Modeling**: SentinelEdge's own model is marked *Maintained as code*. Its threats link
   to their controls, and it has no edit or delete buttons.
2. As a lead, create a model for an application in the inventory (add one under **Applications**
   if needed). Add an asset and a threat that cites a control, such as `C-API-01`.
3. **Compliance** → **Posture**: each category's score, the deductions with the records behind
   them, and the method. As a lead, take a snapshot.
4. **Compliance** → **Exceptions**: request one as the first lead. There is no *Approve* button,
   and the page says why. Sign in as the second lead and approve it.
5. On your model, select **Delete**: the dialog offers *Archive* and *Delete permanently*.
   Archive it, then tick *Show archived models* on the list.

After deciding a scan-finding exception, regenerate the gate's register; after editing the
threat model or controls documents, regenerate the catalogue:

```
make accepted-risks         # scanning/accepted-findings.toml from the approved exceptions
make governance-catalogue   # backend/app/governance/catalogue.json from the two documents
```

Analyse with AI (Phase 9). The engine is off until you choose a provider. In `.env`, set
`SENTINEL_AI_PROVIDER=offline` (free, deterministic, local), then:

```
docker compose up -d api
make ai-check               # one synthetic event, with an injection attempt, through the contract
```

Expected: `Prompt risk 65 (instruction_override, output_steering)`, then
`COMPLETED: classification sql_injection, ...`. Then, in the browser:

1. **Threats**: select an injection event, then **Analyze with AI**. The analysis page shows the
   input's injection signals, the observed evidence (verbatim quotes, attacker text as text) beside
   the inference, and any proposals.
2. As a lead, approve or reject a proposal. Rejecting needs a reason. An approved "open an
   incident" creates the incident as you, with the event as evidence.
3. **AI Security**: usage against the daily limits, proposals awaiting a decision, recent analyses.

To use a real model, follow `docs/bedrock-setup.md`: one IAM user that can call only Nova Micro,
a $1 budget alert, then `make bedrock-credentials` and `SENTINEL_AI_PROVIDER=bedrock`.
`make ai-check` costs about a thousand tokens.

Container hardening by hand:

```
docker compose exec api id -u            # non-zero
docker compose exec api touch /probe     # Read-only file system
nc -zv 127.0.0.1 5432                    # Connection refused
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' http://localhost:8000/api/v1/health   # 400
```

## Step 8 — Ship a phase the way this project does

This is the release workflow from Chapter 2, with the exact commands used for v0.7.0 (Phase 9); every earlier release followed the same steps. The GitHub token is a fine-grained token scoped to this one repository (Contents, Workflows and Pull requests read/write; Actions read-only). It is pasted at the prompt and never written to disk.

```
git switch -c phase/9-ai-security                          # one branch per phase
# … milestone commits; make check && make smoke && make verify-hardening …
git push -u origin phase/9-ai-security                     # password prompt: paste the token

read -s -g -x -P "GitHub token: " GH_TOKEN              # fish: hidden prompt, exported for gh
gh pr create --repo Bionic-Hacker/Sentinel-Edge --base main --head phase/9-ai-security \
    --title "Phase 9: AI security engine" --body-file docs/releases/v0.7.0.md
gh pr checks phase/9-ai-security --repo Bionic-Hacker/Sentinel-Edge --watch
gh pr merge  phase/9-ai-security --repo Bionic-Hacker/Sentinel-Edge --merge

git switch main && git pull --ff-only
git tag -a v0.7.0 -m "Phase 9: AI security engine"                # SSH-signed (tag.gpgsign true)
git push origin v0.7.0
gh release create v0.7.0 --repo Bionic-Hacker/Sentinel-Edge \
    --title "v0.7.0 - Phase 9: AI security engine" --notes-file docs/releases/v0.7.0.md
set -e GH_TOKEN                                         # fish: forget the token
```

Signed tags use an SSH signing key. Set it up once, and register the public key on GitHub as a **Signing Key** so tags show as Verified:

```
ssh-keygen -t ed25519 -C "signing" -f ~/.ssh/id_ed25519_signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

## Day-to-day reference

| Task | Command |
|---|---|
| All CI checks locally | `make check` |
| Backend tests against a throwaway PostgreSQL | `make test-backend` |
| Frontend tests | `make test-frontend` |
| Apply new migrations to the running stack | `docker compose run --rm migrate` |
| Hot-reload frontend against the API container | `cd frontend && npm run dev` |
| Follow logs | `make logs` |
| Delete idle rate-limit buckets | `make prune-rate-limits` |
| Stop, keeping data | `docker compose down` |
| Re-apply the gate after regenerating accepted risks | `make scan-gate` |
| Regenerate the gate's accepted risks from approved exceptions | `make accepted-risks` |
| Regenerate the governance catalogue after editing the threat model or controls | `make governance-catalogue` |
| Check the AI provider against the output contract | `make ai-check` |
| Bedrock session credentials / remove them | `make bedrock-credentials` / `make bedrock-credentials-clear` |
| Import a CI scan artifact | `make scan-import FROM=<dir> SOURCE=ci` |
| Test the SentinelEdge Semgrep rules | `make scan-test` |
| Reset everything, including the database | `make clean` |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `password authentication failed for user sentinel_migrator` | Database volume created by an older phase with different secrets | `docker compose down -v`, then `make dev` (local data is synthetic) |
| `Your .env is missing …` | `.env` predates the current phase | Back up `.env`, run `make env`, recreate the database |
| Sign-in loops back to the login page | `__Host-` cookie refused on an IP address | Use `http://localhost:8080`, not `127.0.0.1` |
| API returns 400 for everything | Host not in `SENTINEL_TRUSTED_HOSTS` | Add it in `.env` and restart |
| `make smoke` reports 429s early | Your browser shares this machine's sign-in allowance | Wait two minutes and rerun |
| Error shows a reference ID | Expected: errors are generic | Search API logs for that `correlation_id` |
| `docker pull` of a scanner fails with *Temporary failure in name resolution* | A DNS hiccup during the first pull | `docker pull` that image by hand, then rerun |
| `scan-gate: missing reports: …` | A scanner failed; its error is above the verdict | Fix the scanner's error and rerun; the gate never passes without every report |
| `make scan-import`: *No reports* | No scan has run in this checkout | `make scan` (and `make dast`) first |
