# Application usage metrics

Sufficit Identity records successful and rejected OAuth/OIDC operations by
`client_id` so operators can identify the most-used applications and investigate
changes in traffic. Collection is generic: no Sufficit business role, directive
or domain-specific event is part of the contract.

## Availability contract

Authentication only calls `TryWrite` on a bounded in-memory channel. It never
waits for MySQL/MariaDB or an external metrics destination. The channel holds at
most 50,000 observations; when full, new observations are dropped and the
`identity.metrics.dropped` counter plus the management dashboard expose that
pressure. A single background reader persists bounded batches.

The collector emits `identity.metrics.accepted` and
`identity.metrics.dropped` through `System.Diagnostics.Metrics`. Persistence,
export counters and queue depth are available at `GET /api/metrics/overview`.

## Privacy

The local event contains client ID, endpoint/grant dimensions, outcome and UTC
time. A user subject, when present, is stored only as a lowercase SHA-256 hash.
Tokens, claims, request payloads, IP addresses and user agents are never stored.
External export contains no subject hash.

## Configuration

Configuration lives in the singleton `identitymetricsconfiguration` database
row and is changed through `PUT /api/metrics/configuration` or the embedded
management UI. The UI and HTTP controller invoke the same application service;
neither connects directly to the metrics backend.

Supported providers:

- `internal`: local database only.
- `victoria_metrics`: best-effort Influx line protocol export to
  `<endpoint>/write?db=<database>&precision=millisecond`.

External credentials are accepted only when the internal vault is enabled and
are encrypted under the `identity-metrics-export` key. Three consecutive export failures open a
five-minute circuit. Export, retention cleanup and persistence failures are
logged but never fail an authentication request.

## Retention and schema

Migration `20260807020859_AddIdentityApplicationMetrics` creates
`identityapplicationusageevents` and `identitymetricsconfiguration`, seeded
enabled with 90-day retention, 250-event batches and external export disabled.
Retention cleanup runs at most once per 24 hours. Dashboard filters use the
`days` and `client` query parameters, so operational views remain linkable.
