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
make smoke              # 34 end-to-end checks against the running stack
make verify-hardening   # 17 container and network checks
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

Container hardening by hand:

```
docker compose exec api id -u            # non-zero
docker compose exec api touch /probe     # Read-only file system
nc -zv 127.0.0.1 5432                    # Connection refused
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' http://localhost:8000/api/v1/health   # 400
```

## Step 8 — Ship a phase the way this project does

This is the release workflow from Chapter 2. The commands are the ones used for v0.1.0 through v0.3.0, shown here for the next release (Phase 7, v0.4.0). The GitHub token is a fine-grained token scoped to this one repository (Contents, Workflows and Pull requests read/write; Actions read-only). It is pasted at the prompt and never written to disk.

```
git switch -c phase/7-security-ops                      # one branch per phase
# … milestone commits; make check && make smoke && make verify-hardening …
git push -u origin phase/7-security-ops                 # password prompt: paste the token

read -s -g -x -P "GitHub token: " GH_TOKEN              # fish: hidden prompt, exported for gh
gh pr create --repo Bionic-Hacker/Sentinel-Edge --base main --head phase/7-security-ops \
    --title "Phase 7: security operations" --body-file docs/releases/v0.4.0.md
gh pr checks phase/7-security-ops --repo Bionic-Hacker/Sentinel-Edge --watch
gh pr merge  phase/7-security-ops --repo Bionic-Hacker/Sentinel-Edge --merge

git switch main && git pull --ff-only
git tag -a v0.4.0 -m "Phase 7: security operations"     # SSH-signed (tag.gpgsign true)
git push origin v0.4.0
gh release create v0.4.0 --repo Bionic-Hacker/Sentinel-Edge \
    --title "v0.4.0 - Phase 7: security operations" --notes-file docs/releases/v0.4.0.md
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
