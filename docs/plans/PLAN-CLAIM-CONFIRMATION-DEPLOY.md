# Claim confirmation preservation deployment

Maintainer authorized production deployment on 2026-11-09.

## Objective and acceptance

Publish the correction in 408c8cb2 to all production Identity nodes. Verify exact
revision, active services, liveness/readiness and unchanged certificate/JWKS
uniformity. Preserve configuration; no account changes or confirmation-token replay.

## Checkpoints

1. **Completed** — Verify source/dependency cleanliness and production baseline,
   confirm schema compatibility and package an exact clean revision.
2. **Completed** — Prepare on all nodes and activate sequentially under the cluster
   lease with rollback protection.
3. **Completed** — Verify public endpoints and cluster health, record evidence and
   commit/push deployment documentation.

## Procedure

Follow [cluster deployment](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md) using
helpers/package-release.sh, prepare-cluster-release.sh,
activate-cluster-release.sh and verify-production-cluster.sh. Target eveo-apps,
apoint-apps and castrum-apps. No schema changes are expected; compare against
active production revision before activation. Source correction passed 72 tests;
see [correction evidence](../activities/202611091910-claim-confirmation-preservation.md).

## Package and baseline

All nodes verified active/Healthy/ready on d04ff98072e7ead121cb49dd7fb6859ea4cc175e.
Package release: 20261109-8cbf3c66, revision 8cbf3c662ce7981675b9c8d678577262812c79c3,
including correction 408c8cb2. SHA-256:
1ee78fcbb55f4ae59590521910e3d0016dca042dd3964ec393bcaa1e3eb5f61f.
SUI local source: 91f76e061b5561cf8adeafdf311815407061856a, clean.
Source comparison has no migration, entity or mapping changes; no migration is
required or run. Package built successfully and passed archive contents and
permissions checks. Preparation and sequential activation remain in progress.

## Activation checkpoint

Archive/helper hashes and all per-node configuration inheritance checks passed.
Cluster activation completed sequentially on all three nodes under the lease.
Direct readiness probes briefly returned 502 during restarts and then recovered;
no uninterrupted-request claim is made. Post-activation gate verified the exact
package revision and active/Healthy/ready services everywhere; certificate and
JWKS pins stayed unchanged. No rollback was required. Public endpoint verification
and documentation delivery remain in progress.

## Verification and delivery

Public health/readiness/discovery/confirmation/resend returned HTTP 200; issuer
and localized invalid-link recovery matched expectations. All checkpoints are
complete. No personal tokens were replayed and no accounts or mail were changed.
[Deployment evidence](../activities/202611091921-claim-confirmation-deployment.md) records the observed release,
health and unchanged cryptographic pins. Documentation delivery accompanies this
completed plan; later documentation revisions are not deployed application code.
