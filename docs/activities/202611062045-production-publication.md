# Activity — Production publication of e1aeb174

Date: 2026-11-06, 20:45 America/Sao_Paulo. Delivery under the
[production plan](../plans/PLAN-PRODUCTION-GATES.md).

## Release and scope

Published `20261106-e1aeb174`, revision
`e1aeb17488af8b82af3fd270853a51c88cb94b15`, sequentially to eveo-apps,
castrum-apps and apoint-apps. The release includes feature-owned protocol posture,
the management audit executor and the optional Galera session preparation policy.
No schema changes or migrations were included.

The clean detached checkout `/mnt/sufficit/.identity-deploy-e1aeb174` used local
Sufficit.Blazor.UI revision `91f76e061b5561cf8adeafdf311815407061856a`.
The archive `/tmp/identity-release-e1aeb174/20261106-e1aeb174.tar.gz` has SHA-256
`b8bf13f2becbb4eaefd67fa53f565aef3aad421fb1a3c9161625e4c927b9e222`.
The package contains no production appsettings or certificates. Preparation
verified archive/helper hashes and inherited four configuration files per node.

## Execution and validation

- `dotnet restore` and `helpers/package-release.sh` succeeded in the isolated checkout.
- Before activation, `verify-production-cluster.sh` confirmed all three nodes
  healthy on `56d046306578c95be8cfa8b022dd78e3dd7ea2ce`.
- `prepare-cluster-release.sh` and `activate-cluster-release.sh` succeeded. The
  activation held the shared deployment lease and changed one node at a time.
- The post-activation gate confirmed the exact new revision on all nodes, service
  active, health Healthy and readiness Healthy.
- Independent service checks: active/running, NRestarts=0 on all three nodes.
- Public `/health`, `/health/ready`, `/.well-known/openid-configuration` and
  `/account/login`: HTTP 200, enforcing Content-Security-Policy header present.
- Certificate SHA-256 unchanged:
  `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`.
- JWKS SHA-256 unchanged:
  `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`.

The prior [compatibility activity](202611062028-galera-session-compatibility.md)
records the full suite (2,147 passed, 18 opt-in skipped), 11 targeted checks and
one owned Galera integration test. Product code did not change afterward; these
checks were not redundantly rerun for deployment. All eight Markdown coverage checks and `git diff --check` passed for this
delivery record.

## Rollback and limits

Each node retains `/opt/sufficit-identity.releases/20261106-56d0463` as the
previous release. The activation helper provides health-checked rollback to that
path. No rollback was needed. Transient HTTP 502 responses occurred during
restarts; this record does not claim zero downtime.

Production configuration was preserved. `RequireGaleraCausalReads` was not enabled
by this deployment; it defaults false. Gradual activation and observation remain
an operational task under the runtime plan. No authenticated user journey,
weighted failover, network partition or consumer signing-key rotation was tested.
No production data or GLOBAL SQL variable was changed. The six parallel lockfile
changes in the original checkout were preserved and excluded from this delivery.
