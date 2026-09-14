# Current claim delivery

## Existing contracts

`GET /connect/userinfo` resolves the authenticated access-token subject and loads
current user data. Claim release follows configured scope mappings. The OIDC
discovery document identifies this endpoint; `/me` is not a registered alias in
the current runtime. `GET /api/claims` is a separate management operation and
requires management authorization. `/api/account/personal` returns profile
fields, not an effective authorization snapshot.

## Optional server-resolved keys

`Sufficit:Identity:ClaimScopeMap:ServerResolvedEntitlementKeys` is an empty-by-default,
deployment-configured list of opaque keys. For a configured key, stored
`entitlements` and `directive` values are excluded from newly issued access and
identity tokens, even when their mapped scope is present. They are also excluded
from ordinary UserInfo responses.

An explicit `GET /connect/userinfo?entitlements=current` returns an additive
`authorization` object with `schemaVersion: 1` and a `grants` array. This array
contains configured-key assignments currently stored on the authenticated user
or their current Identity roles. A caller cannot select another user by passing
a query parameter. SCIM group membership does not implicitly create role grants.

Keys are compared exactly against the portion before the first `:` (or the full
value when no delimiter exists). Values are opaque: Identity does not parse
GUIDs, interpret empty identifiers, infer permission hierarchies, or grant any
business action. Bounds are 256 characters per value, no control characters and
1024 returned grants. Exact duplicate strings are removed. Responses use
`Cache-Control: no-store`.

Example **deployment** configuration for a generic resource server:

```json
{
  "Sufficit": {
    "Identity": {
      "ClaimScopeMap": {
        "ServerResolvedEntitlementKeys": ["example.read", "example.operate"]
      }
    }
  }
}
```

Resource servers own value validation, interpretation, cache isolation, TTLs
and invalidation. They must not treat a user-selected filter as authorization.
No provider-side key list grants permission; it only controls delivery of
assignments already stored in Identity.

## Rollout

Deploy and verify the provider configuration on all issuer replicas before
assigning keys that must never appear in tokens. Merge key lists deliberately;
do not replace another application's configuration. Changing delivery rules does
not remove claims from already-issued tokens. Existing token invalidation or
expiry remains necessary when retiring earlier token-carried grants. Consumers
must use the current snapshot, not those old claims.

The empty default preserves legacy claim delivery. A missing deployment key list
is **not** equivalent to server-only delivery and must fail release acceptance.
No application-specific defaults are embedded in the public provider.
