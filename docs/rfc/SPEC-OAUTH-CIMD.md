# OAuth Client ID Metadata Document (CIMD)

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | In-house |
| Spec | `draft-ietf-oauth-client-id-metadata-document` (Internet-Draft) |

## What it is

Instead of registering the client ahead of time, the `client_id` **is** an
HTTPS URL that serves the metadata document itself. The AS fetches the
document the first time it sees that identifier. The MCP authorization spec
**deprecates DCR** (RFC 7591) in favor of this mechanism.

## Implementation

| Component | Role |
|---|---|
| `src/sts/Cimd/ClientIdMetadataResolver.cs` | Fetches and validates the document |
| `src/sts/Cimd/CimdApplicationProvisioner.cs` | Creates the application on first use |

The hook sits in `/connect/authorize`: when `FindByClientIdAsync` doesn't find
the client, `TryProvisionAsync` is called before failing
(`src/sts/Controllers/AuthorizationController.cs:176-190`). An identifier that
doesn't have the shape of a CIMD URL falls through to the normal unknown-client
error.

## Fetch and validation rules

`ClientIdMetadataResolver.cs:36-48`:

| Rule | Value |
|---|---|
| Only `200 OK` | Redirects are **not** followed |
| Maximum response size | `Mcp:ClientIdMetadataDocuments:MaxDocumentBytes`, default 5120 |
| Timeout | `FetchTimeoutSeconds`, default 3, capped at 30 |
| Cache | `CacheTtlSeconds`, default 300 |
| Document's `client_id` | Must be **exactly equal** to the identifier used |
| `redirect_uris` | Validated by the same policy as other clients |
| HTTP egress | Through the anti-SSRF guard |

Not following redirects is the detail that stops an apparently external
`client_id` from pointing, by indirection, to an internal document.

## Provisioned client

Born as a public client, with the MCP client profile, PKCE required and
explicit consent. `private_key_jwt` for CIMD clients is marked in the code as a
future extension (`CimdApplicationProvisioner.cs:20`).

## Announcement

`client_id_metadata_document_supported` is published in the discovery document
following the `Mcp:ClientIdMetadataDocuments:Enabled` flag, which is `false` by
default (`src/sts/OpenIddictServerConfiguration.cs:572-577`,
`src/sts/Options/McpOptions.cs:199`).

## Market position

Keycloak only got experimental CIMD in 26.6 (2026). Having this implemented
and correctly announced is a competitive advantage in the MCP landscape.

## Gaps

- No periodic revalidation of the document after the cache expires for already
  provisioned clients: the persisted registration is the source of truth after
  first use.
- No `private_key_jwt` for CIMD clients.

## Tests

`CimdTests`.
