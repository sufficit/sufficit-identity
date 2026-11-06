# PLAN — Database provider provenance and supported baseline

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Choose provider and database compatibility together. Retain the current lane until additive migration, rollback and restore evidence exists. Verify upstream availability when executing.

## Acceptance

Pinned reproducible provenance or validated upstream replacement; vulnerability/license evidence; dual-version CI and a successful production-shaped canary/restore.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## F6 — Provider fork retirement and provenance

The fork/local feed and checksum gate remain. CI already audits dependency vulnerabilities; reproducible fork provenance, license coverage and upstream compatibility still need evidence.

Evidence: [Directory.Packages.props](../../Directory.Packages.props), [ci.yml](../../.github/workflows/ci.yml).

- [ ] **F6.1 · pending** — Validate the upstream EF Core 10 provider against the canonical MariaDB schema, migrations, concurrency behaviour and connection-pool settings
- [ ] **F6.2 · pending** — Run the upstream provider in CI and in a production-shaped canary before changing the central package source
- [ ] **F6.3 · pending** — Remove `.nuget-feed` and the fork-integrity step only after provenance, migration output and runtime behaviour match
- [ ] **F6.4 · pending** — If the fork has to remain, publish it under a Sufficit-owned package ID with repository URL, commit, license, deterministic-build and SBOM metadata, build it in CI from a pinned commit and compare the produced artifact hash — the checksum of an opaque committed package is not provenance
- [ ] **F6.5 · partial** — Retain existing CI dependency vulnerability auditing; add source-to-artifact license/provenance coverage for the fork and final dependency graph, with reviewable output.

## F7 — Supported MariaDB baseline

The committed database lane remains MariaDB 10.4.34. No dual-version cutover/restore completion evidence was found; choose a supported target at execution time.

Evidence: [ci.yml](../../.github/workflows/ci.yml), [MariaDbMigrationIntegrationTests.cs](../../src/tests/MariaDbMigrationIntegrationTests.cs).

- [ ] **F7.1 · pending** — Select a currently supported MariaDB LTS target compatible with the provider
- [ ] **F7.2 · pending** — Run both versions in CI: canonical schema, additive rehearsal, grants, concurrency, locking, collations, index-width behaviour
- [ ] **F7.3 · operational** — Canary production-shaped traffic, migrate replicas and backups, retain 10.4 compatibility until the cutover completes
- [ ] **F7.4 · pending** — Remove the 10.4 lane only after rollback and restore rehearsals succeed on the target

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
