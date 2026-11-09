# Claim confirmation preservation deployment

Maintainer authorized production deployment on 2026-11-09.

## Objective and acceptance

Publish the correction in 408c8cb2 to all production Identity nodes. Verify exact
revision, active services, liveness/readiness and unchanged certificate/JWKS
uniformity. Preserve configuration; no account changes or confirmation-token replay.

## Checkpoints

1. **In progress** — Verify source/dependency cleanliness and production baseline,
   confirm schema compatibility and package an exact clean revision.
2. **Pending** — Prepare on all nodes and activate sequentially under the cluster
   lease with rollback protection.
3. **Pending** — Verify public endpoints and cluster health, record evidence and
   commit/push deployment documentation.

## Procedure

Follow [cluster deployment](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md) using
helpers/package-release.sh, prepare-cluster-release.sh,
activate-cluster-release.sh and verify-production-cluster.sh. Target eveo-apps,
apoint-apps and castrum-apps. No schema changes are expected; compare against
active production revision before activation. Source correction passed 72 tests;
see [correction evidence](../activities/202611091910-claim-confirmation-preservation.md).
