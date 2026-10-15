# Lessons learned

The curated version of the running record kept through the build (the book's last chapter has
every lesson with its story). Each line is something that changed how the project works.

## Engineering
- **Tests find what review misses.** Unicode digits crashing a constant-time compare and a role
  compared with `is` were both caught by tests; the authorization sweep earned its place on day
  one.
- **Compute a fact once.** Route templates, client IPs and capabilities each have one source;
  several features reading one fact never disagree.
- **Fail closed, but say why.** A limiter without its database refuses with 503 and Retry-After,
  not a bare 500.
- **Mocked tests cannot know a provider's rules.** EC2 rejected an apostrophe; the Free plan
  rejected an instance type and a bucket Region; Terraform validated what OpenTofu did not. Encode
  documented rules as tests, and expect the first real apply to teach the rest.
- **A plan that never settles hides the change that matters.** Write resources exactly as the
  provider returns them, so `No changes` means something.
- **An exemption should be as narrow as the client that needs it.** One method on one path for
  health checks, nothing more.

## Security design
- **Record a constraint instead of working around it.** No OIDC became "CI never touches AWS",
  not a stored key.
- **A feature that cannot work in production is a design question.** Undeliverable reset links
  became "an administrator issues temporary passwords", which also closed a takeover path.
- **Label what is real.** Real AWS, local, simulated and demo data never mix, and tests enforce
  it; the internet's 198 blocked scanners in a day were real evidence because of it.
- **Credentials should outlive the job, or renew.** Exporting 15-minute credentials once broke a
  long apply; a refreshing profile fixed it.

## Process
- **The plan is the review.** Read the resource lines, not just the summary, and strip colour
  before you grep.
- **Look at CI, not just at the local checks.** Three failures sat unnoticed on branch pushes
  until the pull requests; scan every framework and every branch before delivering.
- **Make every step recoverable.** Bundles with checksums, a push per part, signed tags, saved
  state: a half-applied window was recovered in minutes.
- **Order the work by cost.** Building everything locally first kept AWS spend to a few dollars
  for the whole project.
