# Distributed cache and snapshot runbook

This runbook is intentionally generic. Replace the placeholders with values
from the target deployment's secret manager and network inventory; never put
real credentials in this file.

## Provisioning

1. Choose a private network and, when required by the availability target,
   deploy one Redis master per failure domain plus replicas.
2. Allow the Redis client port and cluster-bus port only between the service
   replicas and Redis peers.
3. Enable persistence appropriate to the cache recovery objective (AOF/RDB),
   memory limits and an eviction policy. A cache must have a finite budget.
4. Create a dedicated Redis credential and store it in the deployment secret
   manager.
5. Configure the service secret boundary:

   ```text
   <SERVICE_SECRET_DISTRIBUTED_CACHE_CONNECTION_STRING>=<private-endpoints>,password=<secret>,abortConnect=false
   ```

   The variable name is deliberately a placeholder. Use the host-secret
   boundary defined by the consuming service when embedding this component.
6. Keep the shared-cache requirement enabled for multi-replica deployments.
   A memory-only fallback is suitable for a single replica or a deliberate
   degraded mode only.

## Safe rollout

1. Validate the secret file owner and mode before restarting the service.
2. Check every Redis endpoint and authentication from each replica without
   echoing the credential.
3. Verify cluster state, slot coverage and peer links.
4. Restart one replica at a time using the deployment supervisor.
5. Confirm health, readiness and the invalidation subscription after every
   restart. Abort and roll back if a replica starts without the shared-cache
   boundary or if the cluster reports `fail`/`pfail`.

## Operational checks

Use the Redis CLI or provider equivalent with the credential supplied through
stdin/environment, not a shell history or command-line log. Check:

- `cluster_state:ok`;
- all expected slots assigned and no failed nodes;
- AOF/RDB persistence and free disk space;
- memory usage below the configured limit;
- Pub/Sub subscription active on every service replica;
- invalidation and cache-error rates in the monitoring system.

The application health endpoints must be checked independently from Redis
health. A healthy Redis cluster does not prove that the identity service is
ready, and a temporary Redis outage must not be mistaken for a database outage.

## Incident response

If one master is unavailable, first restore its process, network route and
cluster-bus reachability. Do not delete its node configuration or re-create
the cluster while data is still recoverable. If a cache-only slot is lost,
allow the service to repopulate entries from the database after the node is
back; do not manufacture cache values manually.

If authentication fails, stop retry storms, rotate the Redis credential in the
secret manager, update every replica atomically and perform a rolling restart.
Never paste the credential into an issue, log or chat.

## Rollback

Rollback means restoring the previous secret boundary and release, then
restarting replicas one at a time. Removing the distributed-cache variable is
an explicit degraded mode: each replica uses local memory and TTL, and
cross-replica invalidation is no longer immediate. Record that mode and its
security/consistency implications before using it in production.
