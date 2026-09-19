# Protected principals on every mutation that reaches a user

Plan: `PLAN-IDENTITY.md` section A1, first item, delivered.

## Before any code: the plan was wrong

A1 as consolidated asked for a persisted `ContextId` on every object, an
`IManagementContextResolver`, a backfill into a global context and context
predicates on every query. That is precisely the machinery removed on
2026-08-15 by product decision (`cd67f51`): one deployment serves one
organization, isolation between organizations is one deployment each with its
own database, and `ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md` says not to
reintroduce tenant data or authority without a new decision.

It came from the 2026-08-07 evaluation (V-19), which predates the decision, and
survived two passes — the consolidation, and the check that each item was real.
That check found zero occurrences of `IManagementContextResolver` and kept the
item. Absence was the decision, not the backlog. A missing symbol does not
prove pending work, and building it would have undone a deliberate product
choice. The plan was corrected in its own commit (`96bed80`) before anything
here was written.

## The real gap

Rewriting A1 around the current contract — capability, MFA step-up, protected
principals — turned up a hole in the third of those.

`ConfigurationManagementObjectAccessPolicy` consulted the protected-principal
policy only when the resource was a `User` and the capability was one of four
`Users*` mutations. But a user can be reached without addressing the user:

| Capability | Resource | What it does to the user |
|---|---|---|
| `ClaimsCreate` | `ClaimCollection` | grants a claim |
| `ClaimsUpdate` | `Claim` | rewrites one |
| `ClaimsDelete` | `Claim` | strips one away |
| `SessionsRevoke` | `Session` / `SessionCollection` | signs them out |
| `AuthorizationsRevoke` | `Authorization` | revokes a grant and every credential it issued |

None of those reached the protected-principal policy, so an operator below a
protected principal's tier could change that principal's claims or sign them
out — which is exactly what the tier exists to prevent.

## The fix

`ManagementResource` gained an optional `SubjectId`: the user an operation
reaches when it reaches one through something other than the user itself. The
object policy now decides on `resource.Type == User ? resource.Id :
resource.SubjectId`, over all nine capabilities.

For collections the id already *is* the user, so the service passes it as the
subject in the same demand. For items — a claim, a session, an authorization —
the owner is only known once the item is loaded, and the services demand
**twice**: once on the capability before the lookup, as before, then again on
the owner after it. Loading first and deciding once would have let an operator
without the capability probe which ids exist; this keeps that property and
still decides on the principal.

## Verification, and two tests that lied first

1,459 tests pass, Release warning-clean.

The first integration test returned `Created` for a claim granted to a tier-9
principal. Not a defect in the change: `ManagementTestFactory` replaces the
whole `IManagementAuthorizationEvaluator` with one that allows everything, and
that evaluator is what calls the object policy — the code under test never ran.

Putting the real evaluator back produced `403` for the protected principal, as
hoped, and `403` for the ordinary-account control as well. The control's body
said `operator_not_authenticated`: the harness's principal is anonymous, so
**both** protected-principal refusals were false positives. Without a control
that should succeed, the test would have been reported as proof.

The test that stands calls `IClaimManagementService` directly with an
authenticated operator holding every capability at tier 1. Both directions of
the change were checked by reverting them:

- policy reverted to `User`-only — all seven new tests fail;
- policy kept, but the claim service no longer naming the owner — the service
  test fails, so it proves the service passes the subject rather than just the
  policy reading it.

## What remains in A1

Separating operator entitlements from the roles and scopes issued to managed
identities, and a test that break-glass through a claim, session or
authorization is audited the same way as through a user.
