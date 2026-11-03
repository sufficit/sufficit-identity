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

The container reports exit 139 for an unhandled startup exception. Why it is not the usual 134 was not
investigated.

## Dependabot PRs failing with NU1004

Dependabot regenerates only the lock of the project that references a package directly. A package with
dependent projects leaves their locks stale and `--locked-mode` fails, as on #107 and #108.

`.github/workflows/dependabot-locks.yml` runs `scripts/propagate-lock-versions.py` on the Dependabot branch,
commits the result and dispatches CI and CodeQL on the new head. `dotnet restore --force-evaluate` is
deliberately not used: it also floats `Sufficit.Blazor.UI`, which uses a version range.

Fixing the locks only inside CI was rejected: the PR would go green and the stale locks would break main.

The script reproduces the validated lock files of #107 and #108 from their original Dependabot commits.

### Limits

- A bump that adds a new transitive package to a dependent project is not handled; that PR stays red.
- After this commit, Dependabot no longer rebases the branch by itself; comment `@dependabot rebase`.
- The workflow itself first runs on the next Dependabot NuGet PR, since `pull_request_target` cannot be
  exercised without one.
