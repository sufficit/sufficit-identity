# Production-safe security remediation — 2026-08-07 — GPT-5

## Deployment invariant

This remediation is designed for a running STS. Existing OAuth/OIDC grants,
PAT behavior, internal HTTP integrations, SSF streams and account-management
flows remain available during the compatibility phase. Security enforcement is
activated only after the corresponding telemetry and inventory are clean.

Do not roll database migrations back after an application rollback. Both new
migrations are additive; the previous binary ignores their columns/tables.

## Required rollout order

### 1. Inventory before changing the binary

1. Record every current SSF stream's `streamid`, `audience` and creating OAuth
   client. The additive migration initially uses `audience` as the only durable
   owner hint for historical rows. If an audience is not the creating
   `client_id`, correct `ownerclientid` to the verified client before exposing
   stream management through the new binary.
2. Inventory every outbound destination used by SSF push, back-channel logout,
   human verification, breached-password lookup and metrics export. Put
   legitimate internal/private names in
   `Sufficit:Identity:OutboundHttp:AllowedPrivateHosts`; put intentional
   clear-text destinations in `AllowedHttpHosts`. Prefer exact names; wildcard
   suffixes are supported only for controlled internal DNS zones.
3. Confirm `Sufficit:Identity:Issuer`, `PublicUrl`, `AllowedHosts` and
   `TrustedProxies` describe the public deployment. Do not enable public-origin
   enforcement until requests through every proxy produce the canonical URL.
4. Preserve the current certificate files and Data Protection key ring. Verify
   both token certificates have private keys and more than the configured
   rotation window remaining.

### 2. Apply additive schema first

Apply, in order:

1. `20260807135147_HardenSsfStreams`
2. `20260807140821_AddAtomicProtocolState`

The first migration adds SSF ownership/challenge fields and an idempotent
delivery key. The second adds database-authoritative DPoP replay and CIBA
pending-state tables. Keep the old application running while these migrations
are applied.

Verification:

```sql
SELECT `MigrationId`
FROM `__sufficit_identity_migrations`
WHERE `MigrationId` IN (
  '20260807135147_HardenSsfStreams',
  '20260807140821_AddAtomicProtocolState'
)
ORDER BY `MigrationId`;

SELECT `streamid`, `audience`, `ownerclientid`, `verificationstate`
FROM `ssfstreams`;
```

### 3. Deploy in compatibility mode

Use these settings for the first rolling deployment:

```json
{
  "Sufficit": {
    "Vault": {
      "RequireEncryptionInProduction": false
    },
    "Identity": {
      "PublicOrigin": { "Mode": "Audit" },
      "CredentialMutations": {
        "StepUpMode": "Audit",
        "MaximumAuthenticationAgeMinutes": 15
      },
      "ClaimScopeMap": {
        "IncludeUnmappedClaimsInAccessTokens": true
      },
      "Certificates": {
        "MinimumRemainingLifetimeDays": 30,
        "FailOnExpiringCertificate": false
      },
      "Smtp": { "RequireTls": false }
    },
    "Exchange": {
      "RabbitMQ": { "RequireTls": false }
    }
  }
}
```

Keep `TokenExchange:Enabled` at its current value. The new implementation
attenuates scopes/resources without removing the grant. PAT requests that omit
`scopes` retain their historical scope set; new clients can request an explicit
subset immediately.

The CIBA and DPoP stores use the database as the authority while mirroring or
importing legacy distributed-cache state. This permits replicas to be upgraded
one at a time.

### 4. Canary checks

On one replica, verify:

- discovery, authorization code + PKCE, refresh, client credentials, password
  grant if used, token exchange, userinfo, revocation and introspection;
- existing PAT use plus explicit-scope PAT creation;
- DPoP token endpoint and a DPoP-protected `/api/account/*` call;
- CIBA authorize/approve/poll/revoke and concurrent poll behavior;
- SSF list/get/verify/delete as the owning client, poll delivery, event filter
  matching and an existing pre-migration stream;
- password, MFA, passkey and external-login mutation from an old browser
  session (allowed in Audit mode), followed by confirmation that other
  sessions and OAuth credentials were revoked;
- password-reset and email-confirmation URLs use `PublicUrl`, regardless of the
  incoming Host header;
- every configured outbound integration connects; no legitimate target is
  rejected by the SSRF guard;
- SCIM denial creates a `scim.authorization` audit event and custom Management
  `RoutePrefix` resolves only at the configured path.

Watch specifically for `would require step-up`, request-derived public-origin,
plaintext Vault compatibility, plaintext SMTP/AMQP and certificate-expiry
warnings. They are migration signals, not reasons to disable a feature.

### 5. Tighten one boundary at a time

After a clean observation window:

1. Set `PublicOrigin:Mode=Enforce`.
2. Enable SMTP and RabbitMQ TLS, validate server certificates, then set each
   `RequireTls=true`.
3. Enable the Vault. The encrypted Vault reads historical `pt1.*` values while
   all new writes use envelope encryption. Rewrite/rotate legacy records, then
   set `RequireEncryptionInProduction=true` only after no plaintext-read warning
   remains.
4. Map every application claim to a scope and migrate consumers; then set
   `IncludeUnmappedClaimsInAccessTokens=false`.
5. Ensure users can reauthenticate from credential-management screens; then set
   `CredentialMutations:StepUpMode=Enforce`.
6. Rotate certificates before the warning window and finally set
   `FailOnExpiringCertificate=true`.

Each switch is independent. If a canary fails, revert only that enforcement
switch and keep the hardened binary and additive schema active.

## Application rollback

Activate the previous release with `helpers/activate-release.sh`. Do not run the
`Down` methods for the two migrations: old binaries ignore the added schema,
while removing it would destroy DPoP/CIBA replay state and SSF ownership data.
The rolling cache adapters allow old and new replicas to overlap during the
rollback window.

## Validation evidence

- `dotnet build Sufficit.Identity.sln --no-restore -p:TreatWarningsAsErrors=true`:
  12 projects, 0 errors, 0 warnings.
- `dotnet test Sufficit.Identity.sln --no-build --no-restore
  -p:TreatWarningsAsErrors=true`: 418 tests passed.
- `dotnet-ef migrations has-pending-model-changes`: no pending model changes.
- `dotnet list Sufficit.Identity.sln package --vulnerable
  --include-transitive`: no vulnerable packages in the configured sources.
