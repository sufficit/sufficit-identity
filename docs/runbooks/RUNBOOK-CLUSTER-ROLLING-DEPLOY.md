# Cluster rolling deployment

The three production Identity nodes must be changed as one controlled
operation. A per-host lock in `activate-release.sh` protects a single restart,
but it cannot prevent two operators from publishing different releases to the
cluster at the same time. Use the cluster wrapper for every production
activation:

```bash
helpers/activate-cluster-release.sh <release-name> <commit-sha>
```

The release is expected to be prepared at the same path on each node:
`/opt/sufficit-identity.releases/<release-name>`. The release should contain a
`REVISION` file with the exact commit SHA. Until all packaging paths provide
that file, the wrapper accepts a legacy release name containing the expected
SHA, but that fallback is only an identity check on the directory name.

The wrapper:

1. takes a local lock and a shared `flock` lease on the coordinator (the first
   host by default), so a second invocation fails closed instead of racing;
2. verifies the candidate and records the currently active release on every
   node before changing anything;
3. calls the existing `activate-release.sh` one node at a time, preserving its
   health check and per-node rollback; and
4. verifies service state, `/health`, `/health/ready`, certificate SHA-256 and
   JWKS SHA-256 on all nodes. If a later node or the uniformity gate fails,
   nodes changed by this invocation are rolled back in reverse order.

Connection and host selection are controlled without putting credentials in
the repository:

```bash
export IDENTITY_PRODUCTION_HOSTS='eveo-apps.sufficit.com.br,apoint-apps.sufficit.com.br,castrum-apps.sufficit.com.br'
export IDENTITY_SSH_USER=root
export IDENTITY_SSH_PORT=26492
export IDENTITY_SSH_KEY=/protected/path/identity-deploy-key
export IDENTITY_COORDINATOR_HOST=eveo-apps.sufficit.com.br
```

To inspect an already running cluster without changing it:

```bash
helpers/verify-production-cluster.sh <commit-sha>
```

The verifier uses the first node's certificate and JWKS digests as the
baseline. Set `IDENTITY_EXPECTED_CERT_SHA256` and
`IDENTITY_EXPECTED_JWKS_SHA256` when an audited release requires explicit
pins. A host that cannot be reached, is not ready, has a different revision or
publishes a different signing/certificate digest makes the command fail.

Do not call `activate-release.sh` directly for a multi-node production
rollout; that bypasses the cluster lease and can recreate the race this
runbook is intended to remove. The existing helper remains available for a
single-node emergency rollback or a configuration-only restart.
