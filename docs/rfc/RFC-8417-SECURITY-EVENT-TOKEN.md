# RFC 8417, 8935 and 8936 — Security Event Token and its delivery

| | |
|---|---|
| Role | Security event transmitter |
| Coverage | **B — Substantial** |
| Origin | In-house |
| Specs | RFC 8417 (SET), RFC 8935 (push), RFC 8936 (poll) |

## Implementation

The SET is the envelope; the semantic content (CAEP, RISC) is described in
[SPEC-SSF-CAEP-RISC.md](SPEC-SSF-CAEP-RISC.md). This document covers the
format and the delivery.

| Component | Role |
|---|---|
| `src/sts/SharedSignals/CaepEventGenerator.cs` | Builds and **signs** the SET |
| `src/sts/SharedSignals/SharedSignalsDispatcher.cs` | Decides push vs. poll and delivers |
| `src/sts/SharedSignals/SsfStreamStore.cs` | Persists streams and the poll queue |
| `src/sts/Controllers/SsfPollController.cs` | Pull endpoint |

## SET format

`CaepEventGenerator` issues a JWT signed with the auxiliary credential, with
a random 128-bit `jti` (`:312`) and `events` as a map from type URI to
payload. The URIs used are the canonical OpenID ones:
`https://schemas.openid.net/secevent/caep/event-type/…` and
`…/risc/event-type/verification` (`:12-20`).

| RFC 8417 requirement | § | Status |
|---|---|---|
| `iss`, `iat`, `jti`, `aud` | 2.2 | Yes |
| `events` as a JSON object | 2.2 | Yes |
| Signed SET (JWS) | 3 | Yes |
| `sub` outside `events` discouraged | 2.2 | Yes, the subject is carried in the event payload |
| Encrypted SET (JWE) | 3 | No |

## Push delivery (RFC 8935)

`DeliverPushStreamAsync` issues a `POST` to the receiver's configured
endpoint, with the stream's optional `Authorization` header
(`SsfStreamsController.cs:104`). Failed deliveries are logged, and a
receiver failure **does not** undo the local operation that generated the
signal — the call runs with a bounded deadline and exceptions are swallowed
(`AuthorizationController.Logout.cs`, the `_sharedSignalsDispatcher` block).

The destination endpoint goes through `SafeHttpHandlerFactory.ValidateRequestUri`
(`SsfStreamStore.cs:181`), which prevents an operator from turning the
transmitter into an internal network scanner.

## Poll delivery (RFC 8936)

Poll streams receive no HTTP call; the SET is enqueued in `ssfsetdeliveries`
(`SharedSignalsDispatcher.cs:162-173`) and pulled by the receiver via
`SsfPollController`, authenticated by the same `sufficit-ssf-transmitter`
policy.

| RFC 8936 requirement | Status |
|---|---|
| On-demand delivery | Yes |
| Acknowledgment (`ack`) | Yes, via the delivery queue |
| `maxEvents` / `returnImmediately` | Partial |

## Gaps

- No encrypted SET.
- No automatic retry with backoff on push; the failure is logged and the
  event is not resent to an unavailable receiver.

## Tests

`SharedSignalsTests`, `SharedSignalsTests.Streams`, `SsfStreamsControllerTests`,
`SsfSubscriptionMatcherTests`.
