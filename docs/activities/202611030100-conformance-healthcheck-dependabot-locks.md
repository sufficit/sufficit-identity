# Nightly conformance and Dependabot lock files

**Date:** 2026-11-03

## Nightly OpenID conformance never reached the suite

The two most recent runs with logs still available stopped before any test: the identity host exited with
`Unable to connect to any of the specified MySQL hosts`, while compose reported the database healthy. All
25 runs still listed by GitHub, back to 2026-09-18, failed; logs older than the 5-day retention are gone,
so their cause is not confirmed.

While initializing, the MariaDB image runs a temporary server with networking off. `mysqladmin ping`
without a host uses the socket, so it reports healthy in that window. Measured on `mariadb:10.4.34`:
for about 2 seconds the socket answered and TCP did not, then the temporary server stopped, and only
afterwards did both answer.

The healthcheck now pings over TCP in `conformance/docker-compose.yml`, `docker-compose.yml` and the CI
database service, which all had the same defect.

With the database fixed, the run reached the next defect that had been hidden behind it: `run.sh` changes
to `conformance/` while the workflow passes the template relative to the repository root, so `sed` failed
after the environment was built and seeded. The script now accepts both forms and checks the template
before doing any work.

The Basic plan then ran in full: 36 modules, 1842 successful conditions, no failures. It still failed on a
stale accepted result: `oidcc-ensure-request-with-acr-values-succeeds` expected a warning that went away
when `c2b754a` made the server honour `acr_values` on 2026-09-19. That entry was removed, which makes the
gate stricter.

The FAPI 2.0 plan ran next: 57 modules, 4100 successful conditions, no failures, and one module that never
finished. `par-attempt-to-use-expired-request_uri` accepts the server's own error page as an alternative to a
redirect, and then waits for a screenshot of it. The browser task was configured not to upload one, so the
module waited until the runner gave up. The task now uploads it, and the expected failure on
`EnsureInvalidRequestUriError`, which no longer happens, was removed.

Both plans then passed on `eee5df9`: Basic with 23 PASSED, 6 WARNING, 4 REVIEW and 2 SKIPPED; FAPI 2.0 with
42 PASSED, 1 WARNING, 10 REVIEW and 3 SKIPPED. REVIEW modules are finished by an uploaded screenshot that
nobody inspects, and the export does not include the image.

## Exit 139 is not a crash

Reproduced: the same unhandled startup exception exits 134 under `sh` or `docker run --init` and 139 as PID 1.
The kernel does not deliver a default-action SIGABRT to a namespace's PID 1, so glibc's `abort()` falls through
to an invalid instruction. There is no memory fault. The conformance `identity` service now uses `init: true`.

## What REVIEW results prove

Of the 14 modules finishing as REVIEW:

- 3 ask for a login page, and the browser types into the form, so a different page fails them.
- 5 (long `nonce`/`state`, inside/outside request object) took the successful path their summary allows, and
  the suite checks the returned values. The upload is a leftover of the login page.
- 6 expect an error page and were weak: `css body` with `.*` accepts any page. Both error renderers now carry
  `data-authorization-error`, and the tasks wait for it.

## Dependabot PRs failing with NU1004

Dependabot regenerates only the lock of the project that references a package directly. A package with
dependent projects leaves their locks stale and `--locked-mode` fails, as on #107 and #108.

`.github/workflows/dependabot-locks.yml` runs `scripts/propagate-lock-versions.py` on the Dependabot branch,
commits the result and dispatches CI and CodeQL on the new head. `dotnet restore --force-evaluate` is
deliberately not used: it also floats `Sufficit.Blazor.UI`, which uses a version range.

Fixing the locks only inside CI was rejected: the PR would go green and the stale locks would break main.

The script reproduces the validated lock files of #107 and #108 from their original Dependabot commits.

### Limits

- A bump that removes a transitive package leaves it in dependent locks, and that PR stays red. New transitive
  packages are added.
- After this commit, Dependabot no longer rebases the branch by itself; comment `@dependabot rebase`.
- `pull_request_target` from Dependabot can only run on a real Dependabot PR. `workflow_dispatch` runs the same
  steps for recovery.
