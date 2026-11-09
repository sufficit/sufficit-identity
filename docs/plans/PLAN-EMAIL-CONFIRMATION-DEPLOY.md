# Email confirmation deployment

Authorized by the maintainer on 2026-11-09.

## Objective and acceptance

Publish the email confirmation recovery correction to all three production
Identity nodes using the cluster wrappers. Verify exact revision, active service,
liveness/readiness and certificate/JWKS uniformity, then inspect the public
invalid-link page without using the supplied personal confirmation token.

## Ordered checkpoints

1. **Completed** — Inspect source/dependency state and production baseline;
   package an exact clean revision and confirm schema compatibility.
2. **Completed** — Prepare the same archive on all nodes and activate sequentially
   under the cluster lease with rollback protection.
3. **Completed** — Verify public behavior and cluster health; record deployment
   evidence and commit/push the delivery record.

## Constraints and commands

Follow [cluster rolling deployment](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).
Use eveo-apps, apoint-apps and castrum-apps; preserve per-node configuration.
No account mutation or replay of the user's token. Package with
`helpers/package-release.sh`, prepare/activate with the corresponding cluster
wrappers and verify with `helpers/verify-production-cluster.sh`.
Source tests passed in the [correction record](../activities/202611091328-email-confirmation-recovery.md).
Exact reason for the original token rejection is still unknown and is not a
condition for deploying the localized recovery action.

## Package and baseline

- All three nodes: active/Healthy/ready at
  `e1aeb17488af8b82af3fd270853a51c88cb94b15` before rollout.
- Package revision: `d04ff98072e7ead121cb49dd7fb6859ea4cc175e`.
- Release: `20261109-d04ff980`.
- Archive SHA-256: `1068f3759bc5e43f59c738d69fa714cbd7f696577fa205f618612725f14eacd4`.
- Local SUI source: `91f76e061b5561cf8adeafdf311815407061856a`, clean.
- No changes in core migrations, mapping or entities versus production baseline.
  No database migration required or executed.
- Package helper succeeded and validated binaries, static assets, permissions
  and absence of bundled runtime configuration/certificates.

## Activation checkpoint

Archive and preservation-helper hashes passed on each node. All four per-node
configuration files were inherited. Activation completed under the cluster lease,
one node at a time; direct-node readiness probes briefly returned 502 during
restarts, then recovered within the helper deadline. No rollback was needed.
Post-activation uniformity gate: all nodes active, Healthy and ready on the exact
package revision, with unchanged certificate/JWKS digests.

## Public verification and delivery

Public health/readiness/discovery, confirmation and resend routes returned 200.
The pt-BR SSR response without account/token parameters contains the localized
invalid-link message and resend action. No personal token was replayed. All
checkpoints are complete; [deployment evidence](../activities/202611091333-email-confirmation-deployment.md)
accompanies this record in Git. Documentation commits after the package revision
do not imply a different deployed binary.
