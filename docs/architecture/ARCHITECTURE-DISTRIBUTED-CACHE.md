# Distributed snapshot cache architecture

This document describes a provider-neutral pattern for running an identity
service with several replicas while keeping the database as the source of
truth. It intentionally contains no deployment names, addresses or vendor-
specific credentials.

## Responsibilities

The cache has three layers:

1. **Local memory** is the hot path for a replica.
2. **A distributed cache** shares snapshots between replicas and avoids a
   database read on every request.
3. **The database** remains authoritative and is consulted on a miss or when
   an entry expires.

The distributed cache is an optimization and coordination boundary. It must
never become the only copy of a key, secret or authorization decision.

## Snapshot contents

Snapshots may contain encrypted ciphertext, AAD, versions, metadata, wrapped
key material and public JWKs. They must never contain plaintext secrets,
passwords, private keys or connection strings.

Deserialization must validate the entry type, schema version, context and
integrity metadata before it is used. Decryption happens only after the
database record has been located and authorization has succeeded.

## Invalidation

Every mutation that changes a snapshot publishes an invalidation event with a
stable schema and a namespaced channel. A replica receiving the event removes
its local entry and reloads it on the next request.

The event bus is best effort. A bounded local/distributed TTL is still
required, because a subscriber can be offline or the broker can be
unavailable. Direct database edits do not publish an event and therefore
require a controlled invalidation or restart.

## Redis Cluster guidance

Redis Cluster may be used as the distributed cache and invalidation bus. Use
private, encrypted transport (for example, a service VPN with firewall rules
or TLS), authentication managed by the deployment secret store, and a
dedicated namespace for the identity service.

Configure all known cluster endpoints in the client connection string. The
cluster announcement address must be reachable from every replica; do not
announce loopback, container-only or public addresses that bypass the private
network.

Multi-master is not replication. Masters own different hash slots. If a
master has no replica and is lost, keys in its slots are unavailable until the
master returns. This is acceptable only when the cache is disposable and the
database can repopulate it. Use replicas and a tested failover policy when
cached data must remain available during a node loss.

`cluster-require-full-coverage no` can keep unaffected slots available during
partial failure, but it does not restore keys owned by the failed master.
Document this trade-off explicitly for the service's availability target.

## Security requirements

- Keep the connection string in the host secret manager or protected
  environment file, never in source control or ordinary JSON settings.
- Use a dedicated Redis identity and rotate its credential independently from
  application signing keys.
- Restrict TCP and cluster-bus ports to the replica network and Redis peers.
- Do not grant management users direct Redis access; cache contents are not an
  administrative API.
- Scrub connection strings from logs, diagnostics and support bundles.
- Treat a cache compromise as exposure of encrypted blobs and metadata, not as
  permission to bypass database authorization.

## Failure semantics

On a Redis timeout, authentication failure or topology error, the service
should log a bounded warning, remove the failed distributed entry and fall
back to the database. A stale or corrupted entry must never override a fresh
database decision. If the deployment requires a shared cache for correctness,
fail startup or readiness explicitly rather than silently operating with
per-replica state.

## Validation checklist

- Each replica can authenticate to every configured endpoint without printing
  the credential.
- Cluster state is `ok`, every expected slot is assigned and no node is in
  `fail`/`pfail`.
- A key written through one endpoint can be read through another endpoint and
  expires according to the configured TTL.
- A Pub/Sub invalidation published on one node is observed by a subscriber on
  another node.
- Restarting one replica does not erase the database or leave plaintext in
  the cache.
- Health, readiness, cache errors and invalidation lag are monitored.
