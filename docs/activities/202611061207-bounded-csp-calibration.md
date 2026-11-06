# Activity — Bounded CSP calibration exception

Date: 2026-11-06. Scope: authorization plan D1.1.

## Delivered behavior

The real STS posture contributor no longer marks report-only CSP as acknowledged
from `Csp:AcknowledgeReportOnly`, even with the legacy boolean bridge enabled.
The property remains bindable for compatibility. A production calibration window
uses the existing `Security:Acknowledgements:csp-report-only` contract: owner,
reason and a future expiry. This avoids a second deadline mechanism and prevents
an expired structured acknowledgement falling back to the old boolean.

See the [calibration runbook](../runbooks/RUNBOOK-CSP-CALIBRATION.md) for migration,
rollback and removal of the acknowledgement when enforcement is enabled.

This is a startup gate. Expiry does not terminate running hosts or switch their
headers. Production settings and deployment were not changed. Operators relying
on the boolean must migrate before upgrading to avoid refused startup.

## Validation

- Before the fix, all six new regression cases failed: missing deadline, expired
  deadline, exact boundary, missing owner, missing reason, and a valid exception
  reevaluated at its expiry. All use the real STS contributor and legacy bridge.
- `rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
  -p:SufficitUseLocalSui=false --filter
  'FullyQualifiedName~ProductionPostureCheckTests|FullyQualifiedName~CspHeaderTests'
  --nologo --verbosity quiet`: **68 passed, zero warnings** after the fix.
- `MarkdownCoverageTests`: **8 passed, zero warnings**. `git diff --check`: clean.
- All three execution checkpoints completed; delivery is recorded below.

Delivery: changes are committed on main under `Require bounded CSP calibration acknowledgements`;
commit/push is separate from production rollout.
