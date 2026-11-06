# Activity — Production session and DPoP publication

Date: 2026-11-06. User explicitly authorized deployment, evaluation and continuation.

## Release and procedure

- Release: `20261106-206fbb9`.
- Revision: `206fbb94d331c3ff37c50ddcb591593fdca8d954`.
- Previous release: `20261106-8ccf3cf`, retained for rollback.
- Local SUI revision: `91f76e061b5561cf8adeafdf311815407061856a`.
- Archive SHA-256: `82428632e88ae743538ba501f91e4f9274676be314d7b9f5445c0bb86f9d09f0`.

Includes the DPoP subject-token exchange correction and the session repository,
cancellation, conditional-renewal, absolute-cache-deadline and bulk-revocation
changes, plus their tests. Comparing the previous release found no core schema,
mapping or migration changes; no migration was executed.

Built with the local SUI as required by DEPLOY.md. Local-SUI restore changed
package locks; only those generated changes were restored before packaging the
clean commit. Cluster preparation verified the archive and inherited the current
per-node configuration. Activation used the cluster lease and sequential wrapper
with rollback protection. The wrapper also pruned old releases according to its
retention policy; the immediately previous release remains the rollback target.

## Evaluation

eveo-apps, castrum-apps and apoint-apps all report the exact revision, active
service, Healthy liveness and Healthy database readiness. All share certificate
SHA-256 `5e858b8d138993436730db83743ac67183495e44de8e2e041e72b2882410eefb`
and JWKS SHA-256 `85d43862afae2e2eea21c6668aa9ec34fa0c029ac906cd0eaee9122847aed769`.

Public HTTPS /health, /health/ready, OIDC discovery and /account/login returned
200. Discovery issuer matches https://identity.sufficit.com.br; login has enforcing
CSP. Direct-node probes observed transient 502 during restarts and recovered
within wrapper deadlines. These probes do not prove uninterrupted requests or
an authenticated end-user flow. No credentials or authorization settings changed.

Post-activation inspection also found ActiveState=active, SubState=running,
NRestarts=0 on all nodes and zero journal lines at priority err over the queried
last ten minutes. This does not assert absence of application-level warnings
or failures logged at other priorities.

Pre-deployment session verification: 54 tests plus 8 Markdown checks passed;
earlier DPoP regression results remain in their delivery activity. GitHub CI and
CodeQL for this checkpoint were still running at initial evaluation, not claimed
passed. [Rolling deployment procedure](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).
The [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) continues with combined
outage tests; later test/documentation commits are not additional deployments.
