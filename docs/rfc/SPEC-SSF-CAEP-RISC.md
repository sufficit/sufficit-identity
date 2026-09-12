# Shared Signals Framework, CAEP and RISC

| | |
|---|---|
| Role | Transmitter |
| Coverage | **C — Partial** |
| Origin | In-house |
| Specs | OpenID SSF 1.0, CAEP 1.0, RISC 1.0 — all **Final** since September 2025 |

The envelope and delivery are covered in
[RFC-8417-SECURITY-EVENT-TOKEN.md](RFC-8417-SECURITY-EVENT-TOKEN.md). This
document covers the signal semantics.

## Surface

| Role | Path |
|---|---|
| Transmitter configuration | `GET /.well-known/ssf-configuration` |
| Stream management | `/ssf/streams` (`SsfStreamsController`) |
| Poll | `SsfPollController` |

Stream management requires the `sufficit-ssf-transmitter` policy: bearer with
a dedicated scope and, by default, evidence of MFA
(`src/sts/ServiceCollectionExtensions.cs:907-913`).
`SharedSignals:RequireMfa` turned off is a finding reported by the posture
check (`src/sts/Security/StsProductionPostureContributor.cs:50-52`).

## Emitted events

`src/sts/SharedSignals/CaepEventGenerator.cs:12-20`:

| Event | URI | Trigger |
|---|---|---|
| Session Revoked | `…/caep/event-type/session-revoked` | Logout, session revocation, credential mutation |
| Credential Change | `…/caep/event-type/credential-change` | Password change, passkey created or removed, 2FA changed |
| Device Change | `…/caep/event-type/device-change` | Passkey registration (`AspNetCoreIdentityPasskeyService.cs:202`) |
| Assurance Level Change | `…/caep/event-type/assurance-level-change` | Session LoA change |
| RISC Verification | `…/risc/event-type/verification` | Stream test, on demand |

Triggers are coupled through `SharedSignalsSecurityEventTrigger`, not spread
across the account services.

## Stream subscription

`SsfSubscriptionMatcher` decides which streams receive each event by subject
and type (`src/sts/SharedSignals/SsfSubscriptionMatcher.cs`). A stream created
without a filter used to receive everything — the comment at
`SsfStreamsController.cs:135` notes that this was the broadest possible
configuration and was restricted.

## Receiver endpoint protection

A push stream's `endpoint_url` goes through
`SafeHttpHandlerFactory.ValidateRequestUri` (`SsfStreamStore.cs:181`). Without
this, anyone able to create a stream would turn the transmitter into an
internal network scanner — an SSRF with credentials.

## Gaps

| Item | Status |
|---|---|
| **Receiver** role (consuming third-party signals) | Not implemented |
| Retry with backoff on push | No |
| Stream verification via `verification_endpoint` per SSF §7.1.4 | Partial |
| `Continuous Access Evaluation` applied to its own tokens | No — signals are emitted, not consumed |

The last row is the most relevant: Identity **warns** others about
revocation, but does not **receive** external signals to revoke its own
sessions.

## Market comparison

Keycloak only reached SSF transmitter status experimentally in 26.7 (2026).
Having push and poll working with CAEP and RISC puts this item above most
open-source competitors.

## Tests

`SharedSignalsTests`, `SharedSignalsTests.Streams`, `SsfStreamsControllerTests`,
`SsfSubscriptionMatcherTests`.
