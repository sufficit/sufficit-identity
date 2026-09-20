# SCIM decides each operation on its own terms

Plan: `PLAN-IDENTITY.md` section A3. What remains is the operational rollout.

SCIM authorization was one answer for the whole surface: a single `[Authorize]`
policy on the controllers. A client that could provision could also delete
every account in the directory and set anyone's password, because those are
the same policy.

They are not the same risk. A directory sync that creates and updates accounts
needs neither to remove them nor to become their owner.

## The operations

`IScimOperationAuthorizationPolicy` decides `Read`, `Provision`,
`PasswordMutation`, `MembershipMutation` and `Delete` separately.

The decision is made **inside the provisioning service**, not by a filter on
the route, because what a request does is in its payload: a `PATCH` that
carries a password is a password mutation, and the route cannot tell. A user
`PATCH` reaches it through `ReplaceUserAsync`, so it is covered by the same
check.

Deleting and setting a password require `scim.destructive`, a scope separate
from `scim`. Beyond that, what a caller must add depends on what it is:

- **A person or a delegated session** presents a second factor.
- **An application** cannot — a client-credentials token has no person behind
  it and never carries `amr`. What it can present is a token bound to a key its
  holder must prove, mTLS or DPoP, so a copy taken from a log or a misrouted
  response is not enough on its own.

Membership changes are ordinary provisioning traffic by default. A directory
sync moves people between groups all day, and treating that as destructive
would break every one of them; a deployment that disagrees sets
`RequirePermissionForMembership`.

## Observe by default

`OperationPolicyMode` defaults to `Observe`: the refusal is logged and the
request proceeds. Every provisioning client in existence today holds the `scim`
scope and a plain bearer token, so enforcing on upgrade would stop them all.
The rollout is the operational item — grant the scope to the clients that
legitimately delete, bind their tokens, then enforce.

## Verification

1,538 tests pass, Release warning-clean. Ten new tests: read and provision
need nothing extra, delete and password each need their own scope, an
application needs a bound token, a person needs a second factor, membership is
ordinary unless configured otherwise, and Observe allows what Enforce refuses.

Two of them go through the endpoint rather than the policy, because the policy
being right proves nothing if the service never asks it: a DELETE is refused
under `Enforce` and the same DELETE succeeds under `Observe`. Removing the
demand from `DeleteUserAsync` turns the first back into `NoContent`.

## What the per-operation decision was added on top of

Read before writing, and unchanged by this work. `ScimOptions.RequireAllowedClient`
defaults to `true`; `ClientPolicyMode` carries the same `Observe`/`Enforce`
pair; `RequireScope` is decided independently of the client decision, so
neither can silently stand in for the other; `RequireMfa` is enforced for
people; and `ScimAuthorizationAuditFilter` audits both decisions rather than
only the refusal.

The posture check reports `scim-client-allow-list-disabled`,
`scim-client-policy-observe` and `scim-mfa-disabled`, and — added on
2026-09-20 — the advisory `scim-client-allow-list-empty`, which is what a
deployment sees when SCIM is enabled with no allowed client and therefore
refuses every provisioning request.
