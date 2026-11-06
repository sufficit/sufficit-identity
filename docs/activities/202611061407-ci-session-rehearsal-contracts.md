# Activity — Session rehearsal CI contracts

Date: 2026-11-06. CI repair takes precedence over pending clock-skew coverage in
the [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Findings

[CI run 42257029208](https://github.com/sufficit/sufficit-identity/actions/runs/42257029208)
failed with two synchronization-contract tests and one historical gitleaks
finding. Its 2102 other tests passed and browser-host checks succeeded.
[CodeQL](https://github.com/sufficit/sufficit-identity/actions/runs/42257029157)
passed. The previously deployed revision's CodeQL run was superseded/cancelled;
it was not rerun blindly.

The selected functional suites had missed the repository-wide synchronization
contracts. New readiness polling and the Redis wall-clock loop violated them.
The cancellation test's two infinite waits were also missing explicit justification.

## Changes

Redis startup now awaits its readiness log signal. MariaDB startup follows logs
from the current container start, waiting for its final TCP-port readiness
(the initialization server uses port zero), then verifies an actual connection.
The log observer process is stopped after the signal; no existing service is touched.

The persisted Redis test performs repeated reads and then waits only for the
remaining absolute TTL. There is no wall-clock polling loop. The exact single
TTL wait and two infinite cancellation waits are justified in the existing
contract table; the guards themselves remain enabled and unchanged.

The historical gitleaks match was natural-language prose, not a credential.
Rephrased current prose and added only its exact historical fingerprint to
.gitleaksignore. No rule, directory or secret type is broadly excluded.

## Validation

With both local-service opt-ins enabled:
`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~TestSynchronizationContractTests|FullyQualifiedName~SessionTicket'
--nologo --verbosity quiet`: **27 passed, zero warnings**, including actual
Redis/MariaDB and combined recovery cases.

Full-history `gitleaks detect --source /repo --config /repo/.gitleaks.toml --redact`
using the local gitleaks Docker image: **1391 commits scanned, no leaks found**.
The scan used the exact historical ignore, with no history rewrite.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.

## Delivery scope

Test and documentation changes only; no additional production deployment.
Production remains at revision 206fbb94d331c3ff37c50ddcb591593fdca8d954.
Clock-skew and cluster-failover scenarios remain pending.
Delivery commit title: `Align session rehearsals with CI synchronization contracts`.

## Remote verification completed

Code/test revision: `dce1c037687fa780d216dbdd38907f6d58f31788`.
[CI 42258934109](https://github.com/sufficit/sufficit-identity/actions/runs/42258934109)
completed successfully: **2104 passed, 5 skipped**, plus **2 MFA browser tests**.
The five opt-in local-service integration cases were separately executed locally
in the 27-test run above. Browser-host checks, MariaDB canonical/additive SQL,
production container build, API-only smoke and dependency audit all passed.
Gitleaks passed remotely and again locally after the commit (1392 commits scanned).
[CodeQL 42258934051](https://github.com/sufficit/sufficit-identity/actions/runs/42258934051)
also completed successfully.

All three repair checkpoints completed. This final evidence-only update does not
change the tested code or the deployed production revision.
