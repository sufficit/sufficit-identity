# Scope-driven entitlement — 2026-08-17

## Purpose

Make a native client's authentication sufficient to use a downstream API
without a manual administrator grant, while preserving least privilege.

## Contract

- Approval of a configured scope (e.g. `example_api`) persists the configured
  `directive=exampleuser:00000000-0000-0000-0000-000000000000` claim.
- The operation is idempotent and runs at device approval and user-token
  redemption. The latter repairs refresh tokens issued before this feature.
- The empty context is interpreted by Identity Core as the authenticated
  user's own subject context; it is not global authorization.
- Registration, email confirmation and login preserve the local device-flow
  return URL so a newly created account returns directly to device approval.

Configuration lives under `Sufficit:Identity:ScopeEntitlements`. Deployments can
replace the default scope-to-claim mapping without changing the token pipeline.

## Verification

`DeviceFlowTests` covers approval, one-time persistence, simulated removal of a
legacy entitlement and automatic repair on refresh-token redemption.
