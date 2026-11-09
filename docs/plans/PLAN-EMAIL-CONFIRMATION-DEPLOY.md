# Email confirmation deployment

Authorized by the maintainer on 2026-11-09.

## Objective and acceptance

Publish the email confirmation recovery correction to all three production
Identity nodes using the cluster wrappers. Verify exact revision, active service,
liveness/readiness and certificate/JWKS uniformity, then inspect the public
invalid-link page without using the supplied personal confirmation token.

## Ordered checkpoints

1. **In progress** — Inspect source/dependency state and production baseline;
   package an exact clean revision and confirm schema compatibility.
2. **Pending** — Prepare the same archive on all nodes and activate sequentially
   under the cluster lease with rollback protection.
3. **Pending** — Verify public behavior and cluster health; record deployment
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
