# Database-controlled token maintenance

Implemented in the normal Identity host; not published or installed in production.
All implementation checkpoints completed: contracts/coordination, implementation,
validation and operational documentation. The temporary G8 section is removed
from the consolidated plan under its delivered-work convention.

## Result

- Additive EF migration and SQL add disabled `tokenmaintenance` and
  `tokenmaintenanceruns`; canonical empty-database SQL and schema tests updated.
- Existing BackgroundService polls the database every 30 seconds. A two-minute
  lease and revision writes in every deletion transaction fence stale owners.
  Claim and takeover commit before work; history counters commit with deletions.
- Completed runs reschedule by configured interval; failures retry after five
  minutes. Requests made during a run remain pending. Disabling stops subsequent
  batches. Existing bounded atomic token/parent deletion is preserved.
- Management API and Settings page expose policy, request and last 30 runs.
  Dedicated read/manage capabilities use existing authorization/MFA and audit.
  UI uses scoped service adapters, English/Portuguese resources and BrowserTime.
- New CLI rejects managed mode; old deployed binaries cannot enforce that guard.
  The existing external timer must be drained before activation.

## Validation

111 focused tests passed, zero warnings, with a real isolated MariaDB 10.4.34
container and Chromium fixture host. Filter included TokenMaintenanceTests,
Token_maintenance_browser_flow, OpenIddictAtomicPruningTests,
OpenIddictPruningWorkerTests, TokenPruningCommandTests, MarkdownCoverageTests,
Architecture and DatabaseSchemaContractTests.

Tests exercise disabled/due schedules, competing/stale claims, lease expiry,
stale completion, successor fencing, queued requests, authorization denial,
validation, audit, legacy-mode refusal, full EF migration, and 251-token/one-parent
pruning with persisted counters on MariaDB. Existing atomic batch regression
checks remain green. `git diff --check` passed.

Browser fixture validated navigation from Settings, enable/save, request feedback,
retained settings, history and no mobile overflow. Desktop 1440px and mobile 390px
screenshots were inspected at `/tmp/identity-maintenance-screenshots/`. This validates
UI interaction against a fixture, not production authentication or deletion.
The mobile history was adjusted to label each value. The browser package was
selected to match the installed Chromium; no browser installation was needed.

Build restore uses `-p:SufficitUseLocalSui=false` consistently; EF generation had
restored local project references, so assets were restored again for package use.
EF CLI 10.0.11 warned about runtime 10.0.13; generated SQL matches the canonical
script contract and full migration succeeded against MariaDB 10.4.34.

## Design decisions

Reference lock: existing Settings/TrustedProxies form patterns and SUI controls;
Database history conventions; DESIGN-MANAGEMENT-UI / DESIGN-SYSTEM retain brand
and semantic tokens. Read policy first, edit/request next, history last. No new
palette or periodic render timer. Mobile rows pair labels with values.

## Delivery boundaries

See [runbook](../operations/RUNBOOK-TOKEN-PRUNING.md) for migration, capabilities,
monitoring, cutover and rollback. Database keeps full run-level history; UI bounds
its latest-run query. Production replication settings, timers and releases were
not changed. The temporary MariaDB container was removed after tests.

No multi-node Galera failover/load rehearsal was performed. That rehearsal and
coordinated production rollout remain operational gates, not successful tests.
Changes are on disk in the working checkout, uncommitted/unpublished. Existing
claim-delivery documentation and EffectiveClaimsControllerTests changes were
preserved. The earlier atomic-pruning fix remains part of this session's work.
