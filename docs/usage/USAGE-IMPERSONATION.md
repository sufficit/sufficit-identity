# Impersonation (acting as a person)

A staff member obtains a short-lived access token in the name of a person, to reproduce exactly what that person
sees in an application: the token's `sub` is the person, so resources and `/connect/userinfo?entitlements=current`
resolve the person's real grants, and its `act` claim names the staff member (RFC 8693 §4.1).

## Request

The application exchanges the staff member's own access token (issued to that application) at the token endpoint:

```http
POST /connect/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=<application>
&subject_token=<staff access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&impersonated_subject=<user id of the person>
&scope=<optional; at most the staff token's scopes>
```

The answer is an access token only (no refresh token), valid for `AccessTokenLifetimeMinutes` (default 30, 5–60).
`offline_access` is never granted. A token that already carries `act` cannot impersonate again.

## Rules

- The feature and the application are enabled in `Sufficit:Identity:TokenExchange:Impersonation`
  (`Enabled`, `AllowedClientIds`). This list is separate from the general token-exchange allow-list.
- The application needs the `gt:urn:ietf:params:oauth:grant-type:token-exchange` permission.
- The staff sign-in behind the subject token is at most `MaxAuthAgeMinutes` old (default 480) and, with
  `RequireSecondFactor` (default true), carries a presented second factor (not a remembered one).
- The staff member holds `identity.users.impersonate` through a role (`Management:Authorization:RoleCapabilities`)
  or a full administrator role.
- The person can sign in and is not an administrator, a `manager`, a holder of a role with management capabilities,
  or a protected principal. The staff member cannot target themselves.
- Every decision writes a management audit row (`identity.users.impersonate`, allowed or denied with a reason) that
  never expires. If the issuance cannot be audited, nothing is issued.

## Configuration example

```json
"Sufficit": { "Identity": {
  "TokenExchange": { "Impersonation": { "Enabled": true, "AllowedClientIds": [ "my-app" ] } },
  "Management": { "Authorization": { "RoleCapabilities": { "support": [ "identity.users.impersonate" ] } } }
} }
```

Applications should show who is being impersonated, block actions that would act for the person beyond viewing,
and let the staff member leave at any time. Tests: `src/tests/ImpersonationTests.cs`.
