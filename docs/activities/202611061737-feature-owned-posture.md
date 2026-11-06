# Activity — Feature-owned production posture

Date: 2026-11-06. Scope: runtime plan F1.1.

## Change and boundary

Added `EvaluatePosture(ProtocolPostureContext)` to the internal protocol feature
contract and catalog. CIBA, DPoP and Shared Signals now own the production checks
for their options; `StsProductionPostureContributor` aggregates their findings.
Identifiers, messages, remedies, severity and conditional gates are preserved.
Feature findings are now enumerated in catalog order before cross-cutting checks.
No protocol endpoint, option default or enforcement policy changed.

Cross-cutting STS checks remain in the STS contributor. Token exchange is outside
the current feature catalog; its checks remain there too. Management, SCIM and
Vault retain their module contributors rather than acquiring an STS dependency.
Features without an existing posture finding use the empty default hook; this
refactor does not claim a new exhaustive security audit of all options.

## Verification

- Release test build with `--no-restore -warnaserror`, focused on
  `ProtocolFeatureCatalogTests|ProductionPostureCheckTests`: 46 passed.
- Added enabled/disabled and permissive/enforced combinations, inactive stream
  management, missing cache, blocking severity and aggregation/no-duplicate checks.
- Extended the existing architecture contract to keep feature option checks out
  of the central posture contributor.
- Full Release regression suite (`--no-build --no-restore`): 2132 passed,
  12 skipped, zero failures (2144 total, TRX counters).
- Markdown coverage after documentation changes: 8 passed.

## Execution checkpoints

1. Completed — contract/context and migration of the three feature checks.
2. Completed — Release build, focused/full tests and Markdown coverage.
3. Completed locally — delivery record, owning-plan update and diff review.
   Commit/push verification is reported with the delivery result.

## Delivery

Owning [runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md) keeps F2/F4 pending;
this completed implementation is recorded as an activity rather than another plan.
No deployment is claimed by this record. Six pre-existing package lock edits are
excluded from this task's commit.
