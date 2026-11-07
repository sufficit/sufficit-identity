# PLAN — Runtime boundaries, sessions and migration verification

Status: local F4 acceptance matrix verified; production HA/observation acceptance inputs remain unresolved; F1.1, F2.1, F2.2, F4.1 and local F5.2 completed on 2026-11-06. Remaining scope below.

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

- [ ] **F4.2 · partial** — Complete the joint database/cache failure behavior and stale-revocation bounds. Cache timeout/failure already falls back to authoritative storage; include failed invalidation, disconnected notification channel and database outage cases. Renewal after database deletion is fixed by the [conditional-renewal activity](../activities/202611061258-session-renewal-after-revocation.md). The [publication-deadline activity](../activities/202611061303-session-cache-publication-deadline.md) bounds delayed renewal/read cache writes and verifies failed invalidation with a controlled shared cache. The [bulk-snapshot activity](../activities/202611061318-bulk-session-revocation-snapshot.md) covers insertion, deletion and same-key recreation between selection and deletion. The [local Redis rehearsal](../activities/202611061339-session-redis-outage-rehearsal.md) verifies real cache outage, database fallback and recovery after revocation across independent cache clients. The [persisted-cache rehearsal](../activities/202611061343-persisted-session-cache-recovery.md) checks stale RDB restoration and expiry without extending the original deadline. The [MariaDB outage rehearsal](../activities/202611061349-session-mariadb-outage.md) verifies warm/cold cache behavior, mutation failures and recovery against an owned real database. The [combined-outage rehearsal](../activities/202611061355-combined-session-outage.md) verifies both recovery orders with real MariaDB and Redis. The [restored-cache/database-outage activity](../activities/202611061910-restored-cache-database-outage.md) combines stale RDB restoration with unavailable MariaDB and verifies expiry, failed renewal and recovery without resurrecting the revoked row. The [controlled clock-offset activity](../activities/202611061432-session-replica-clock-offsets.md) characterizes early/late ticket expiry and the independent shared-cache deadline. The [replica-promotion activity](../activities/202611061437-session-redis-replica-promotion.md) verifies acknowledged revocation across explicit Redis primary loss/promotion. The [missed-invalidation replica activity](../activities/202611061440-session-replica-missed-invalidation.md) models a replica detached before deletion and verifies the original TTL despite attempted renewal. The [notification-transition activity](../activities/202611061745-session-notification-transitions.md) verifies warm-cache disconnect and bounded stale acceptance after reconnect using independent stamp caches and simulated publisher state. The [real NATS recovery activity](../activities/202611061809-session-nats-recovery.md) adds actual two-bridge delivery and broker stop/restart recovery with authoritative stamp validation. The [isolated-connection activity](../activities/202611061818-session-isolated-notification-path.md) verifies a severed TCP path to one of three live bridges, unaffected peer delivery and restored notifications. The [silent-loss activity](../activities/202611061823-session-silent-notification-loss.md) discards broker-to-client bytes while Connected remains true and verifies the original cache bound. Still cover production HA election/discovery, kernel-level packet-loss and heartbeat behavior, Galera failover and quantitative host/provider clock-skew evidence; these local rehearsals do not establish production-cluster behavior. The [production application-clock observation](../activities/202611061844-production-application-clock-observation.md) records conservative SSH intervals on the three LXC application nodes; The [hypervisor time-source observation](../activities/202611061849-production-hypervisor-time-sources.md) confirms current LXC placement and synchronized chrony sources on the three Proxmox hosts. The [provider topology activity](../activities/202611061855-production-provider-topology.md) identifies a live six-node Redis Cluster with three primaries on the application hosts and configured HAProxy database candidates including google-data. The [live Galera inventory](../activities/202611061915-production-galera-inventory.md) confirms three synchronized MariaDB 10.4.34 nodes in a four-member component, correlates google-data with the fourth advertised address, and records cluster weight 6 plus eveo sync-wait 14; local Google root SQL authentication was blocked; the later application-credential compatibility gate below succeeds. Rehearsals on standalone MariaDB 10.11 do not prove this topology. The [weights/routing activity](../activities/202611061918-galera-weights-routing-health.md) records weights 2/1/1, global sync-wait 14 on all three queried nodes (without the SELECT bit), healthy ordinary HAProxy targets and unchecked duplicate backups on Castrum/Apoint. The [local causal-read probe](../activities/202611061928-local-galera-causal-reads.md) reproduces stale SELECT with 14 and barrier error/recovery with 15 on matching MariaDB/Galera versions, using three isolated nodes and a minimal SQL row. The [Identity Galera integration activity](../activities/202611061948-identity-galera-session-reads.md) extends the probe through the real repository/ticket store and separate caches with a test-only barrier. The [opt-in causal-read policy](../activities/202611062018-galera-causal-read-policy.md) implements a session-local production interceptor with failure/cancellation propagation; activation defaults off. The [pooled-session regression](../activities/202611062118-galera-pooled-session-policy.md) verifies policy reapplication on the same physical connection across sync/async logical opens, with connector reset both enabled and disabled. The [application-session compatibility gate](../activities/202611062028-galera-session-compatibility.md) found dirty reads ON on all four candidates, added session-only disabling to the policy, and verified successful preparation on all candidates from Eveo (including direct Google SQL). The [gradual activation](../activities/202611062102-galera-causal-read-activation.md) enabled the policy on all three application hosts with compatibility and readiness gates; weighted production HA and sustained observation remain pending. The [cache-outage/apply-lag scenario](../activities/202611062132-cache-outage-galera-apply-lag.md) verifies an injected cache outage falling back to a real delayed Galera reader, rejecting stale data and observing revocation after database recovery. The [owned weighted-quorum rehearsal](../activities/202611062107-local-weighted-galera-quorum.md) now verifies sequential process loss, protected read refusal outside the Primary component and convergence after resuming all four local nodes. The [four-voter/time-source observation](../activities/202611062138-galera-voter-clock-observation.md) directly confirms weights 2/1/1/2 and synchronized chrony on the Google host, with another healthy post-activation application snapshot. The [Redis placement inventory](../activities/202611062149-redis-replica-placement.md) confirms cross-site replicas on port 6380, one per primary; sustained database/cache timing evidence and a sustained skew budget remain unverified. The [local Cluster election rehearsal](../activities/202611061906-session-redis-cluster-election.md) tracks automatic election and existing-client discovery; production behavior and combined failure gates remain open.
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

## Execution to completion — 2026-11-06

The active goal covers this runtime plan. Completed F1/F2/F4.1/F5-local/F14
work is not reopened. F4.2/F4.3 remain open until the following evidence exists.

1. **completed** — Complete current provider inventory: Redis primary/replica
   placement, routing/health and available clock/telemetry evidence.
2. **completed** — Close the identified deterministic cancellation/fallback gap;
   [22 passing checks](../activities/202611062152-cache-fallback-cancellation.md).
   Live-driver cancellation and broader combined HA are not implied.
3. **completed** — Exercise kernel packet loss/heartbeat and combined provider
   failures in owned fixtures; distinguish each from production HA.
4. **blocked on operational inputs** — Evaluate and execute production HA/observation gates where a
   bounded, reversible procedure and acceptance thresholds are established.
   Record missing maintenance/workload/skew decisions explicitly instead of
   injecting cluster-wide production faults without a defined recovery envelope.
5. **completed** — Run the relevant final validation; reconcile each acceptance
   item against actual evidence and retain any concrete blockers.
6. **in progress** — Archive completed scope as activities, preserve still-open
   ownership, commit/push and verify remote state.

No invented SLA or clock-skew acceptance budget. Production publication already
completed; additional test/documentation work alone requires no new deployment.
The six unrelated lockfiles must remain excluded. Exactly one step is active.

### Remaining acceptance matrix (fixed scope for this execution)

| Requirement | Evidence / next acceptance | Current state |
|---|---|---|
| Cache failure + durable lag | Real Galera + injected cache exception, refusal and recovery | verified |
| Cancellation on fallback | Signaled factory + caller abort after cache failure, no publication | verified locally |
| Stale replicas and original deadline | Existing restored-cache, missed-invalidation and clock-offset activities | verified in their documented fixtures |
| Redis election/discovery | Owned six-node cluster automatic election | verified locally; production not exercised |
| Galera weighted quorum | Owned 2/1/1/2 pause/recovery test; weights confirmed live | verified locally; production not exercised |
| Kernel loss + heartbeat | [Owned NATS netem and full-suite evidence](../activities/202611062158-kernel-loss-runtime-verification.md) | passed; 6-minute observed run |
| Production fault acceptance | Shared Redis/Galera affect consumers beyond Identity; require affected-service envelope and abort limits before disruption | unresolved operational input |
| Sustained observation/skew | Existing snapshots plus 38-minute post-activation check; duration/workload/error/skew acceptance not specified | unresolved operational input |

Do not invent additional test permutations after these acceptance items. Any
newly discovered defect receives its own concrete reproduction and scope.

The [production HA procedure](../runbooks/RUNBOOK-RUNTIME-HA-VALIDATION.md)
concretely lists preflight, one-fault sequencing, abort/restore and the missing
acceptance inputs. No production fault is claimed from the local fixtures.
