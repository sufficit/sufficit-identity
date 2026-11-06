# PLAN — SCIM operation policy and query processing

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Inventory required consumer operations before expanding filters or enabling enforcement. Coordinate email mapping with the account-email plan.

## Acceptance

Parameterized filter parsing, resource limits, operation-specific authorization and interoperability evidence; unsupported features remain unadvertised.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## A3 — SCIM operation policy

Per-operation enforcement is implemented. What remains is deployment/consumer inventory, not another authorization implementation.

Evidence: [ScimOperationAuthorization.cs](../../src/scim/ScimOperationAuthorization.cs), [ScimOperationAuthorizationTests.cs](../../src/tests/ScimOperationAuthorizationTests.cs), [202609201900-scim-per-operation.md](../activities/202609201900-scim-per-operation.md).

- [ ] **A3.1 · operational** — Before enabling SCIM or broadening its use, inventory provisioning clients, grant scim.destructive only where needed, bind their tokens and verify OperationPolicyMode=Enforce. Confirm the deployment state first; the per-operation policy is already implemented.

## F3 — SCIM decomposition and query processing

Equality/member-path regex parsing and private PATCH helpers remain. Sorting is not advertised; no shared AST/filter repository implementation was found.

Evidence: [ScimProvisioningService.Support.cs](../../src/scim/ScimProvisioningService.Support.cs), [ScimProvisioningService.cs](../../src/scim/ScimProvisioningService.cs), [ScimDiscoveryController.cs](../../src/scim/ScimDiscoveryController.cs), [ScimProvisioningTests.cs](../../src/tests/ScimProvisioningTests.cs).

- [ ] **F3.1 · pending** — Extract `IScimFilterParser` and a typed filter AST from `ScimProvisioningService`; translate only validated nodes to parameterized LINQ. Filtering is two regexes today — `EqualityFilterRegex` and `MemberPathFilterRegex` — so equality is all a caller gets
- [ ] **F3.2 · pending** — Add `co`, `sw`, `ew`, logical composition and the multi-valued email/member filters current consumers need
- [ ] **F3.3 · pending** — Extract the repositories and promote the PATCH applicator to a shared one; `NormalizePatchOperation`/`ValidatePatchRequest` are private statics in `ScimProvisioningService.Support.cs`. The service is already split into `.Users`, `.Groups` and `.Support`
- [ ] **F3.4 · pending** — Add bulk, sorting and ETags — intentionally unadvertised today; enable per demand, from this same extraction rather than a parallel contract
- [ ] **F3.5 · pending** — Tests: resource limits, parser timeout, invalid filter, MariaDB translation, interoperability

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
