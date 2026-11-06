# Activity — Controlled replica clock offsets

Date: 2026-11-06. Partial F4.2/F4.3 evidence in the
[runtime plan](../plans/PLAN-RUNTIME-ARCHITECTURE.md).

## Characterized behavior

Five new deterministic cases use real SQLite persistence, shared protection,
independent injected reader clocks and a controlled shared-cache clock:

- Reader two seconds ahead: expiry on a cache hit or database read rejects the
  ticket and removes the durable row, even before the other clock reaches expiry.
- Reader two seconds behind: after the cache expires, database fallback can still
  accept the ticket until the reader catches up. Persisted expiry is unchanged.
- Readers two seconds ahead/behind after revocation and failed invalidation:
  once the shared cache deadline expires, the absent database row remains absent.

This documents existing time dependence; no product behavior or tolerance was
changed. No test changes the operating-system clock, polls time or sleeps.

## Validation

`rtk dotnet test src/tests/Sufficit.Identity.Tests.csproj --no-restore
-p:SufficitUseLocalSui=false --filter
'FullyQualifiedName~SessionTicketCacheRaceTests|FullyQualifiedName~TestSynchronizationContractTests|FullyQualifiedName~OidcUserSessionRepositoryTests|FullyQualifiedName~SessionTicketCancellationTests|FullyQualifiedName~ServerSideSessionsTests|FullyQualifiedName~InteractiveSignInServiceTests|FullyQualifiedName~SessionValidity'
--nologo --verbosity quiet`: **60 passed, zero warnings**.

## Read-only production observation

On eveo-apps, castrum-apps and apoint-apps, timedatectl reported
`NTPSynchronized=yes` and `NTP=no`. All three report `lxc` from
systemd-detect-virt. No chronyc executable or running chrony/ntp/timesync service
was found inside these containers. These observations do not measure clock
offset or establish the parent hosts' time-service health. Parent-host evidence
remains operational work; no container/host clock or service was changed.

MarkdownCoverageTests: **8 passed, zero warnings**. `git diff --check`: clean.
All three execution checkpoints completed.

## Limits and delivery

Controlled-cache expiry is an abstraction boundary test, not an implementation
of StackExchange.Redis clock conversion. Writer/provider skew, quantitative
host offsets and HA failover remain pending. The
[architecture](../architecture/ARCHITECTURE-SESSION-VALIDITY.md) states the distinction.
No deployment or production session mutation.
Delivery commit title: `Characterize session expiry under replica clock offsets`.
