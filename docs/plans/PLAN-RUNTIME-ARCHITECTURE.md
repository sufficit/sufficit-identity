# PLAN — Runtime boundaries, sessions and migration verification

Status: queued; F2.2, F4.1 and local F5.2 completed on 2026-11-06. Remaining scope below.

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

IProtocolFeature has configuration/discovery hooks but no posture contributor hook; findings remain separately composed.

Evidence: [ProtocolFeature.cs](../../src/sts/Features/ProtocolFeature.cs), [StsProductionPostureContributor.cs](../../src/sts/Security/StsProductionPostureContributor.cs).

- [ ] **F1.1 · pending** — Add the posture contributor to the feature contract, so a feature owns its production findings the same way it owns its discovery metadata (today the findings live in four separate `IProductionPostureContributor` implementations, one of which carries every STS finding regardless of which feature owns the setting — which is how the coverage fell behind the configuration surface in the first place)

## F2 — One management operation executor

The shared guard exists; operation wrappers remain repeated. STS and Management now use the same application-abstractions options contract; see the [F2.2 activity](../activities/202611061115-shared-management-options.md).

Evidence: [ManagementOperationGuard.cs](../../src/management/Audit/ManagementOperationGuard.cs), [ManagementOptions.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/ManagementOptions.cs).

- [ ] **F2.1 · pending** — Replace the `DemandAsync`/`TryWriteAuditAsync` pair repeated across the remaining management services with a `ManagementOperationExecutor`

## F4 — Sessions off the per-request write path

Distributed ticket cache, timeout fallback, invalidation and opt-in stamp caching already exist. F4.1 is closed by the [repository extraction](../activities/202611061246-session-repository-extraction.md) and [cancellation activity](../activities/202611061240-session-ticket-cancellation.md). Combined fault/consistency coverage remains.

Evidence: [OidcUserSessionTicketStore.cs](../../src/sts/OidcUserSessionTicketStore.cs), [SessionValidity.cs](../../src/core/Sessions/SessionValidity.cs), [ServerSideSessionsTests.cs](../../src/tests/ServerSideSessionsTests.cs), [SessionValidityCacheIntegrationTests.cs](../../src/tests/SessionValidityCacheIntegrationTests.cs), [ARCHITECTURE-SESSION-VALIDITY.md](../architecture/ARCHITECTURE-SESSION-VALIDITY.md).

- [ ] **F4.2 · partial** — Complete the joint database/cache failure behavior and stale-revocation bounds. Cache timeout/failure already falls back to authoritative storage; include failed invalidation, disconnected notification channel and database outage cases. Renewal after database deletion is fixed by the [conditional-renewal activity](../activities/202611061258-session-renewal-after-revocation.md). The [publication-deadline activity](../activities/202611061303-session-cache-publication-deadline.md) bounds delayed renewal/read cache writes and verifies failed invalidation with a controlled shared cache. The [bulk-snapshot activity](../activities/202611061318-bulk-session-revocation-snapshot.md) covers insertion, deletion and same-key recreation between selection and deletion. The [local Redis rehearsal](../activities/202611061339-session-redis-outage-rehearsal.md) verifies real cache outage, database fallback and recovery after revocation across independent cache clients. The [persisted-cache rehearsal](../activities/202611061343-persisted-session-cache-recovery.md) checks stale RDB restoration and expiry without extending the original deadline. The [MariaDB outage rehearsal](../activities/202611061349-session-mariadb-outage.md) verifies warm/cold cache behavior, mutation failures and recovery against an owned real database. The [combined-outage rehearsal](../activities/202611061355-combined-session-outage.md) verifies both recovery orders with real MariaDB and Redis. The [controlled clock-offset activity](../activities/202611061432-session-replica-clock-offsets.md) characterizes early/late ticket expiry and the independent shared-cache deadline. The [replica-promotion activity](../activities/202611061437-session-redis-replica-promotion.md) verifies acknowledged revocation across explicit Redis primary loss/promotion. The [missed-invalidation replica activity](../activities/202611061440-session-replica-missed-invalidation.md) models a replica detached before deletion and verifies the original TTL despite attempted renewal. Still cover automatic HA election/discovery, network-partition behavior, Galera failover and quantitative host/provider clock-skew evidence; these local rehearsals do not establish production-cluster behavior.
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
