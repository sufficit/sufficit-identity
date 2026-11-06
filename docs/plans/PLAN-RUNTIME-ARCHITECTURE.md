# PLAN — Runtime boundaries, sessions and migration verification

Status: F4 local Redis Cluster election completed; production/combined fault gates remain open; F1.1, F2.1, F2.2, F4.1 and local F5.2 completed on 2026-11-06. Remaining scope below.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Preserve existing distributed session caching and invalidation. Separate cancellation propagation and outage tests from architectural extraction. Production HTTP migration rejection already exists.

## Acceptance

Feature-owned posture checks, one management executor/options contract, cancellation and bounded stale-session behavior, tested migration failure/retry/rollback.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

Deployment evidence: [2026-11-06 publication](../activities/202611061353-production-session-publication.md).

CI repair evidence: [synchronization and historical scan](../activities/202611061407-ci-session-rehearsal-contracts.md).

## F1 — Posture contributors inside the feature contract

F1.1 is implemented: `IProtocolFeature.EvaluatePosture` owns protocol findings,
aggregated by the STS contributor. CIBA, DPoP and SSF retain their original gates,
identifiers, severity and messages. Cross-cutting STS policies and independent
Management/SCIM/Vault contributors retain their boundaries. Token exchange is
not currently a member of the protocol feature catalog and remains STS-owned.

Evidence and validation: [feature-owned posture activity](../activities/202611061737-feature-owned-posture.md).

## F2 — One management operation executor

F2.1 is implemented by the scoped `ManagementOperationExecutor`: repeated
capability demand and best-effort audit helpers now delegate to one implementation.
Service-specific policies and transactional success writes retain their original
boundaries. See the [executor activity](../activities/202611061742-management-operation-executor.md).
STS and Management also share the application-abstractions options contract;
see the [F2.2 activity](../activities/202611061115-shared-management-options.md).

## F4 — Sessions off the per-request write path

Distributed ticket cache, timeout fallback, invalidation and opt-in stamp caching already exist. F4.1 is closed by the [repository extraction](../activities/202611061246-session-repository-extraction.md) and [cancellation activity](../activities/202611061240-session-ticket-cancellation.md). Combined fault/consistency coverage remains.

Evidence: [OidcUserSessionTicketStore.cs](../../src/sts/OidcUserSessionTicketStore.cs), [SessionValidity.cs](../../src/core/Sessions/SessionValidity.cs), [ServerSideSessionsTests.cs](../../src/tests/ServerSideSessionsTests.cs), [SessionValidityCacheIntegrationTests.cs](../../src/tests/SessionValidityCacheIntegrationTests.cs), [ARCHITECTURE-SESSION-VALIDITY.md](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).

- [ ] **F4.2 · partial** — Complete the joint database/cache failure behavior and stale-revocation bounds. Cache timeout/failure already falls back to authoritative storage; include failed invalidation, disconnected notification channel and database outage cases. Renewal after database deletion is fixed by the [conditional-renewal activity](../activities/202611061258-session-renewal-after-revocation.md). The [publication-deadline activity](../activities/202611061303-session-cache-publication-deadline.md) bounds delayed renewal/read cache writes and verifies failed invalidation with a controlled shared cache. The [bulk-snapshot activity](../activities/202611061318-bulk-session-revocation-snapshot.md) covers insertion, deletion and same-key recreation between selection and deletion. The [local Redis rehearsal](../activities/202611061339-session-redis-outage-rehearsal.md) verifies real cache outage, database fallback and recovery after revocation across independent cache clients. The [persisted-cache rehearsal](../activities/202611061343-persisted-session-cache-recovery.md) checks stale RDB restoration and expiry without extending the original deadline. The [MariaDB outage rehearsal](../activities/202611061349-session-mariadb-outage.md) verifies warm/cold cache behavior, mutation failures and recovery against an owned real database. The [combined-outage rehearsal](../activities/202611061355-combined-session-outage.md) verifies both recovery orders with real MariaDB and Redis. The [restored-cache/database-outage activity](../activities/202611061910-restored-cache-database-outage.md) combines stale RDB restoration with unavailable MariaDB and verifies expiry, failed renewal and recovery without resurrecting the revoked row. The [controlled clock-offset activity](../activities/202611061432-session-replica-clock-offsets.md) characterizes early/late ticket expiry and the independent shared-cache deadline. The [replica-promotion activity](../activities/202611061437-session-redis-replica-promotion.md) verifies acknowledged revocation across explicit Redis primary loss/promotion. The [missed-invalidation replica activity](../activities/202611061440-session-replica-missed-invalidation.md) models a replica detached before deletion and verifies the original TTL despite attempted renewal. The [notification-transition activity](../activities/202611061745-session-notification-transitions.md) verifies warm-cache disconnect and bounded stale acceptance after reconnect using independent stamp caches and simulated publisher state. The [real NATS recovery activity](../activities/202611061809-session-nats-recovery.md) adds actual two-bridge delivery and broker stop/restart recovery with authoritative stamp validation. The [isolated-connection activity](../activities/202611061818-session-isolated-notification-path.md) verifies a severed TCP path to one of three live bridges, unaffected peer delivery and restored notifications. The [silent-loss activity](../activities/202611061823-session-silent-notification-loss.md) discards broker-to-client bytes while Connected remains true and verifies the original cache bound. Still cover production HA election/discovery, kernel-level packet-loss and heartbeat behavior, Galera failover and quantitative host/provider clock-skew evidence; these local rehearsals do not establish production-cluster behavior. The [production application-clock observation](../activities/202611061844-production-application-clock-observation.md) records conservative SSH intervals on the three LXC application nodes; The [hypervisor time-source observation](../activities/202611061849-production-hypervisor-time-sources.md) confirms current LXC placement and synchronized chrony sources on the three Proxmox hosts. The [provider topology activity](../activities/202611061855-production-provider-topology.md) identifies a live six-node Redis Cluster with three primaries on the application hosts and configured HAProxy database candidates including google-data. Replica placement, selected database backend health/time and a sustained skew budget remain unverified. The [local Cluster election rehearsal](../activities/202611061906-session-redis-cluster-election.md) tracks automatic election and existing-client discovery; production behavior and combined failure gates remain open.
- [ ] **F4.3 · partial** — Add remaining combined multi-replica stale-cache, failover and cancellation scenarios, reusing ServerSideSessionsTests, SessionValidityCacheIntegrationTests and recorded replica-revocation evidence.

## F5 — Schema migration out of the web process

Completed local implementation/verification is archived in the
[F5.2 completion activity](../activities/202611061708-migration-verification-complete.md).
Production HTTP rejects AutoMigrate; dedicated migrators, partial-DDL repair,
concurrency and the recorded old binary's password/MFA/OIDC compatibility were
verified against disposable MariaDB. This closes the original local F5.2 scope.

Deployment-specific posture and representative volume/data evidence remain under
[production rollout gates](PLAN-PRODUCTION-GATES.md#schema-rollout-evidence), not
implicit claims of this local verification. Other runtime sections remain open.

## F14 — Security-critical protocol annotations

The targeted F14.1/F14.2 review is complete; findings, corrected comments and
verification are archived in the [security annotation activity](../activities/202611061723-security-annotation-reconciliation.md).
The review covered schema provisioning/template guidance, cookie/session cache
semantics, protocol-feature hook dispatch and signing/encryption composition.
Future security changes must keep these annotations aligned with executable behavior.

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
