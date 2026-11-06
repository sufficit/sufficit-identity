# Activity — Browser-session repository extraction

Date: 2026-11-06. Completes F4.1 together with the earlier
[cancellation delivery](202611061240-session-ticket-cancellation.md).

## Delivered boundary

Added internal `IOidcUserSessionRepository` and its EF implementation, registered
as singleton over IDbContextFactory. Persistence owns a short-lived context per
operation and takes cancellation for every path. The ticket store retains
serialization/protection, HTTP metadata, expiry and activity policy, and cache
operations; it no longer performs EF queries or mutations.

Protected ticket format, Data Protection purpose, cache key format, cookie
contract and database schema are unchanged. Renewals retain the existing upsert
behavior and preserve original creation/IP/user-agent metadata. Activity touch
updates only that field from the detached snapshot, ignores a concurrent removal
and does not recreate the row. Subject deletion returns affected-count and the
selected session IDs for the existing cache invalidation loop.

The [session architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md)
records the boundary and residual consistency limits. This does not solve the
existing renewal-versus-revocation or selection-versus-deletion races; F4.2/F4.3
retain those scenarios and combined database/cache/notification failures.

## Validation

`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`: **40 passed, zero warnings**.

Five new SQLite cases verify renewal metadata preservation, concurrent renewal
versus activity touch and deletion versus touch, subject isolation/exclusion and
invalidation IDs, and ticket-store disposal of expired/corrupt records. Existing
interactive-session, cancellation, cache-timeout fallback and validity suites
remain green. No synthetic test merely asserts the new class/interface exists.

`MarkdownCoverageTests`: **8 passed, zero warnings**. `git diff --check`: clean.
All three repository execution checkpoints completed. Delivery commit title:
`Extract cancellable browser-session persistence repository`. No deployment,
production session change or schema migration was performed.
