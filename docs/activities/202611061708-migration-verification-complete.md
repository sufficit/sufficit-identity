# F5.2 — Local migration verification complete

Date: 2026-11-06 (America/Sao_Paulo).
Parent: [runtime architecture](../plans/PLAN-RUNTIME-ARCHITECTURE.md#f5--schema-migration-out-of-the-web-process).

## Delivered scope

The original local F5.2 scope (concurrent migrator startup, failure/retry and
old-binary compatibility on the upgraded schema) is complete. Detailed evidence:

- [Production/Staging HTTP schema guard](202611061446-production-schema-guard.md).
- [Real advisory-lock exclusion and failure cleanup](202611061451-migration-advisory-lock-recovery.md).
- [Partial-DDL failure, explicit repair and retry](202611061457-real-migration-failure-recovery.md).
- [Deterministically overlapping canonical migrators](202611061519-concurrent-canonical-migrations.md).
- [Two dedicated OS host processes](202611061539-dedicated-migrator-processes.md).
- [Populated identity data preservation](202611061549-populated-migration-recovery.md).
- [Unchanged historical build and readiness](202611061555-historical-host-schema-compatibility.md).
- [Password login and advisory-lock timeout fix](202611061633-historical-password-login.md).
- [Recovery-code MFA and single-use enforcement](202611061641-historical-mfa-recovery.md).
- [TOTP authentication](202611061646-historical-totp-login.md).
- [OIDC code/PKCE and signed ID-token validation](202611061657-historical-oidc-code-flow.md).

The old binary is unchanged revision `4493f97`, predating AddTokenMaintenance.
Recovery repairs only known empty fixture-owned DDL; it is not a general
automated production repair procedure. Old-binary testing keeps the upgraded
schema, rather than running destructive Down migrations.

## Final validation at 3d0223a

- Opt-in MariaDB/historical/schema/synchronization group: **18 passed**, none skipped,
  including disk-backed migration fixtures. Historical authentication uses tmpfs.
- Entire `Sufficit.Identity.Tests` project, without opt-in environment variables:
  **2118 passed, 12 skipped**, zero failures (TRX counters: 2130 total/2118 executed).
  Optional real-service tests are not represented by the skipped cases as passed.
- [GitHub CI 42284189690](https://github.com/sufficit/sufficit-identity/actions/runs/42284189690): success.
- [CodeQL 42284189669](https://github.com/sufficit/sufficit-identity/actions/runs/42284189669): success.

Local command: `dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-build
--no-restore`. The targeted run sets `SUFFICIT_TEST_MARIADB_DOCKER=1` and
`SUFFICIT_TEST_HISTORICAL_HOST_DLL=/tmp/identity-rollback-4493f97/src/server/bin/Debug/net10.0/Sufficit.Identity.Server.dll`,
with the seven migration/historical/schema/synchronization classes as its filter.

## Remaining work belongs to its owner

[Production rollout evidence](../plans/PLAN-PRODUCTION-GATES.md#schema-rollout-evidence)
retains production-shaped configuration and representative sanitized data/volume
acceptance. The workload/thresholds and rollback artifact must be selected before
that gate can be closed. This is not deployment, certification, production-volume
evidence or a guarantee for every historical protocol/client combination.

Other runtime work (F1, F2.1, residual F4 and F14) and the other focused product
plans remain open. This activity closes F5.2 locally, not the entire Identity roadmap.

## Delivery

MarkdownCoverageTests: **8 passed**; `git diff --check`: clean.
This activity accompanies the completion commit on main. Commit/push is not deploy.
