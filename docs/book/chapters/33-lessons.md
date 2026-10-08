# Lessons Learned So Far

<p class="lead">A running record of what the build taught, in the order it was learned. The final, curated version becomes <code>LESSONS_LEARNED.md</code> in Phase 12.</p>

## Engineering

:::lesson Tests find the bugs code review misses
Two of Phase 2's defects were found by tests, not by reading code. Unicode digits slipped past a `\d` check and crashed a constant-time comparison. A role comparison used `is` against a string and could never match. Both were subtle, both were security-relevant, and both now have regression tests. The authorization sweep earned its place on its first run.
:::

:::lesson Framework internals change what "the path" means
Under nested routers, the matched route knows only its router-relative path. Rate-limit keys, metrics and audit records briefly recorded `PATCH /{user_id}` instead of the full endpoint. A startup-built map from route object to full template fixed all three consumers at once. Wherever several features need the same fact, it should be computed once.
:::

:::lesson Proxy headers are a trust decision, so make exactly one
Behind nginx, every client looked like the proxy, so per-IP limits would have throttled everyone together. Trusting `X-Forwarded-For` blindly would have let clients pick their own address. The answer was one middleware, outermost, trusting only a pinned network and walking right to left, with Uvicorn's own proxy handling turned off so nothing else could disagree.
:::

:::lesson Fail closed, but fail clearly
The first version of the limiter answered a database outage with a generic `500`. The secure outcome (refusing the request) was right, but the signal was wrong. A `503` with `Retry-After` tells clients and operators what is happening without loosening anything.
:::

:::lesson One lock, always taken first
Correlation needed to be exactly once, and audit writes already serialized on an advisory lock. A second lock for correlation would have been taken in different orders by different code paths, which is how deadlocks are made. Taking the audit lock first, everywhere, gave one lock order, exactly-once detections, and nothing new to operate. A thirty-thread test keeps it honest.
:::

:::lesson Let the server own the rules, and send them
The incident workflow has role rules, object rules and status rules. Re-implementing them in the browser to decide which buttons to show would create a second copy that drifts. Instead every incident response carries the moves and permissions computed for the person asking, and the UI renders exactly those.
:::

:::lesson Defenders type attack strings too
The first incident note quoting a payload would have raised a new SQL injection detection about the analyst. Free-text incident fields are excluded from inspection, like a WAF rule exclusion, and a test checks that every exclusion still names a real route and field.
:::

## Testing and tooling

:::lesson Timing-based tests are machine-dependent
A fixed 125-request burst tripped the probe limit in the sandbox but not on a slower workstation, because the bucket refilled during the burst. The smoke test now sends until the first `429`, and so asserts the behavior rather than an assumed speed. Similarly, React `act()` warnings that appeared only on some Node versions were fixed by waiting for the actual session-change event instead of a fixed number of ticks.
:::

:::lesson Tooling upgrades can quietly break a check
Docker Compose v5 changed `docker compose port` to report success for an unpublished port, which silently inverted a hardening check. The check now inspects the container's port bindings directly. A security check that can pass for the wrong reason needs its own test.
:::

:::lesson A workaround can hide a slower bug
The Phase 6 fix for `act()` warnings made them go away on most machines, but every frontend test still sat on a two-second safety timeout. The real cause was waiting for sign-in inside the same `act()` as the render, when React only runs effects as an `act()` scope exits. Splitting the wait into a second `act()` removed the warnings everywhere and cut the suite from about 60 seconds to 12.
:::

:::lesson Look at the screen, at the size people use
Every unit test passed while several pages scrolled sideways on a phone. Screenshots at 390 px found it: screen-reader-only labels inside scroll boxes were positioned against the page, not the box. The fix was one CSS rule, and it also repaired two pages from earlier phases. The same review found chart labels shrinking to unreadable sizes on small screens.
:::

## Process

:::lesson Order the plan by cost, not by number
Building every local phase before any AWS phase keeps cloud spend at zero until the infrastructure has something to run. The phase numbers stayed the same, so nothing in the specification's acceptance criteria had to be reinterpreted.
:::

:::lesson Make every step recoverable
One branch per phase, milestone commits, checksummed bundles, a push after every milestone, and a signed tag per release. At any point the worst case is returning to the last tag. The owner set this as a rule before any code was written.
:::

:::lesson Hand work over as if the session could end at any moment
Phase 7's frontend milestone was interrupted mid-way. Because work in progress was committed to a WIP branch, bundled with a checksum, and described in a handoff document listing exactly what was done, what remained and how to verify the starting point, a fresh session resumed at the same test counts and finished the milestone without redoing anything.
:::

:::lesson Operational friction is a requirement
A stale database volume after an upgrade produced a confusing authentication error. Instead of documenting it, the platform now diagnoses it: `make dev` detects the cause and prints the fix. Every confusing failure is a missing diagnostic.
:::
