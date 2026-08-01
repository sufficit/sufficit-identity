# SCIM 2.0 provisioning

Sufficit Identity exposes an optional SCIM 2.0 service provider in the same
composition host as the STS and Management UI. It implements the core resource
model from [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) and the HTTP
protocol from [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644).

## Boundary

- Base path: `/scim/v2`.
- Media type: `application/scim+json`.
- Users are backed by ASP.NET Core Identity plus `scimuserprofiles`.
- Groups are backed by `scimgroups` and their membership tables.
- SCIM Groups are opaque provisioning resources. They are never ASP.NET
  Identity roles and carry no Sufficit `Administrator`, `Manager`, directive,
  tenant or reseller meaning.
- Management and SCIM call the same
  `IIdentityAccountLifecycleService` for activation, lockout, session/token
  revocation and deletion.
- Passwords are accepted only as write-only input and are never returned.
- SCIM changes write redacted entries to the canonical management audit table.

This first protocol surface is global to the configured identity store. The
deployment must issue the configured SCIM scope only to provisioning clients
that are allowed to administer that directory. Tenant or organization
partitioning is not inferred from application claims.

## Endpoints

- `GET /scim/v2/service-provider-config`
- `GET /scim/v2/resource-types`
- `GET /scim/v2/resource-types/{id}`
- `GET /scim/v2/schemas`
- `GET /scim/v2/schemas/{id}`
- `GET|POST /scim/v2/users`
- `GET|PUT|PATCH|DELETE /scim/v2/users/{id}`
- `GET|POST /scim/v2/groups`
- `GET|PUT|PATCH|DELETE /scim/v2/groups/{id}`

Lists use one-based `startIndex` and bounded `count`. The current filter subset
supports equality (`eq`) for:

- Users: `id`, `userName`, `externalId`;
- Groups: `id`, `displayName`, `externalId`.

PATCH supports `add`, `replace` and `remove` for implemented mutable User
attributes and Group membership. Bulk, sort and ETags are explicitly advertised
as unsupported by service-provider discovery.

## Configuration

The secure default is disabled and bearer-protected:

```json
{
  "Sufficit": {
    "Identity": {
      "Scim": {
        "Enabled": false,
        "RequireAuthorization": true,
        "RequiredScope": "scim",
        "MaxResults": 100
      }
    }
  }
}
```

When enabled, a bearer principal must be authenticated and contain the exact
configured scope. `RequireAuthorization=false` exists only for controlled local
tests and must not be used on a network-exposed deployment.

## Database rollout

- Canonical migration: `20260730220100_AddScimProvisioning`.
- Empty database source of truth:
  `docs/migration/sql/001-create-empty-database.sql`.
- Existing MariaDB deployment:
  `docs/migration/sql/070-add-scim-provisioning.sql`.

The operational script creates only SCIM-owned tables and records the migration
in `__sufficit_identity_migrations`; it does not alter the legacy roles or
business claims.
