# PLAN — Sufficit Identity

Status: active index, reviewed 2026-11-06 against `a66456e`. Work lives in the
focused plans below. Section IDs and the old headings remain stable so existing
links and historical references keep resolving. Completed work is recorded in
[the reconciliation activity](../activities/202611061100-plan-reconciliation-split.md),
not reintroduced as unchecked tasks.

## How to execute

Select one bounded item, mark it in progress in its owning file, and record
implementation, tests and operational evidence there. Keep exactly one selected
item in progress; the other plans stay queued. New priorities must update the
active checkpoint rather than silently replacing unfinished work.

`pending` means a code/test gap was retained; `partial` names existing foundations
and the remaining gap; `operational` requires current deployment evidence;
`decision` needs an owner choice; `dependency` must follow its referenced owner;
`deferred` is intentionally outside the immediate queue. A present test is not
proof of deployment. Historical production findings are explicitly dated.

## Delivery constraint

Preserve grants, endpoints, users, clients and integrations through additive
schema, compatibility adapters, shadow decisions, dual-read/backfill and rolling
deployment. Enforce policies only after telemetry proves the affected cohort
ready. Keep features disabled if their invariant cannot be met. Do not remove
production functionality to close a task. Commit/push does not prove deploy.

Keep provider authorization generic. Application claims require explicit release
destinations. Manifest-managed configuration remains manifest-owned. No credentials
belong in lists, URLs, drafts, logs or audit snapshots; profile audit remains
allowlisted and access-controlled under its documented retention policy.

## Focused plans

| Plan | Original sections | Next bounded work |
|---|---|---|
| [Authorization and security policy](PLAN-AUTHORIZATION.md) | A2, A4, D1 | Verify A2 observation evidence; then scope enforcement decision |
| [SCIM operation policy and query processing](PLAN-SCIM.md) | A3, F3 | Inventory consumers; then filter parser design |
| [Token exchange, CIBA and dynamic registration](PLAN-PROTOCOL-ASSURANCE.md) | B3, B5, B9, F10 | B3 rollout inventory; B5 external interoperability evidence |
| [Keys, vault rotation and encryption budget](PLAN-KEYS-VAULT.md) | C1, C2, F12 | C1 authority evidence; C2 lifecycle gap review |
| [Client console lifecycle and operation](PLAN-CLIENT-CONSOLE.md) | E2, E3, E4, E6, E8 | E3 audit timeline using delivered API |
| [Pluggable UI and remote interaction](PLAN-UI-COMPOSITION.md) | E7 | E7 phase 2 semantic endpoint contract |
| [Runtime boundaries, sessions and migration verification](PLAN-RUNTIME-ARCHITECTURE.md) | F1, F2, F4, F5, F14 | F4 cancellation and residual fault matrix |
| [Database provider provenance and supported baseline](PLAN-DATABASE-PROVIDER.md) | F6, F7 | F6/F7 provider and database compatibility matrix |
| [Account email identity and recovery](PLAN-ACCOUNT-EMAILS.md) | F9, F15, G5 | F9 race matrix, then F15 additive email model |
| [Security observability and assurance](PLAN-OBSERVABILITY-CONFORMANCE.md) | G1, G2, G3 | G3 residual coverage matrix, then G1 durable events |
| [Production rollout and legacy retirement](PLAN-PRODUCTION-GATES.md) | C4, C5, F11, G4, G7 | Verify overdue calendar gates with current evidence |
| [Deferred protocol roadmap](PLAN-PROTOCOL-ROADMAP.md) | G6 | Demand-driven design only; not a production prerequisite |

## Execution order and dependencies

1. Verify the overdue A2/legacy-client calendar gates; evidence first, no automatic
   enforcement or deletion. See [production calendar](PLAN-PRODUCTION-GATES.md).
2. C1 mixed rotation and B3 regressions are delivered. C1 authority separation
   and B3 production inventory still need operational evidence.
3. E3 console audit timeline reuses the delivered search API. E2 credential UI
   follows A2 secret-reference parity; E4 owns typed application claims.
4. F9/F15 share one email race matrix. F6/F7 select provider/database together;
   production canaries follow passing compatibility evidence.
5. E7 phases are sequential. G assurance runs across deliveries; B9 and the G6
   roadmap remain deferred until their explicit trigger.

## Operational calendar

The complete original calendar is in [Production gates](PLAN-PRODUCTION-GATES.md).
November 3/4 are past eligibility dates awaiting verification; November 20 is
the recorded earliest old-certificate retirement date, subject to expiry recheck.

## Stable section directory

### A2 — Operator-aware client scope and secret authorization

Owner: [PLAN-AUTHORIZATION](PLAN-AUTHORIZATION.md).

### A3 — SCIM operation policy

Owner: [PLAN-SCIM](PLAN-SCIM.md).

### A4 — Step-up enforcement and one MFA evidence policy

Owner: [PLAN-AUTHORIZATION](PLAN-AUTHORIZATION.md).

### B3 — Token exchange provenance and delegation

Owner: [PLAN-PROTOCOL-ASSURANCE](PLAN-PROTOCOL-ASSURANCE.md).

### B5 — CIBA trust boundary completion

Owner: [PLAN-PROTOCOL-ASSURANCE](PLAN-PROTOCOL-ASSURANCE.md).

### B9 — FAPI 2.0: how an expired `request_uri` is reported **(deferred by decision)**

Owner: [PLAN-PROTOCOL-ASSURANCE](PLAN-PROTOCOL-ASSURANCE.md).

### C1 — Vault production enablement and rotation

Owner: [PLAN-KEYS-VAULT](PLAN-KEYS-VAULT.md).

### C2 — Signing and encryption key separation

Owner: [PLAN-KEYS-VAULT](PLAN-KEYS-VAULT.md).

### C4 — Verified transport everywhere

Owner: [PLAN-PRODUCTION-GATES](PLAN-PRODUCTION-GATES.md).

### C5 — Legacy credential inventory and rotation **(operational)**

Owner: [PLAN-PRODUCTION-GATES](PLAN-PRODUCTION-GATES.md).

### D1 — CSP from telemetry to enforcement

Owner: [PLAN-AUTHORIZATION](PLAN-AUTHORIZATION.md).

### E2 — Application lifecycle: credentials and cloning

Owner: [PLAN-CLIENT-CONSOLE](PLAN-CLIENT-CONSOLE.md).

### E3 — Application operation and scale

Owner: [PLAN-CLIENT-CONSOLE](PLAN-CLIENT-CONSOLE.md).

### E4 — Application advanced settings (only where enforcement is real)

Owner: [PLAN-CLIENT-CONSOLE](PLAN-CLIENT-CONSOLE.md).

### E6 — Mobile-first validation and rollout

Owner: [PLAN-CLIENT-CONSOLE](PLAN-CLIENT-CONSOLE.md).

### E7 — Pluggable UI, phases 2–5

Owner: [PLAN-UI-COMPOSITION](PLAN-UI-COMPOSITION.md).

### E8 — Accessibility and localization

Owner: [PLAN-CLIENT-CONSOLE](PLAN-CLIENT-CONSOLE.md).

### F1 — Posture contributors inside the feature contract

Owner: [PLAN-RUNTIME-ARCHITECTURE](PLAN-RUNTIME-ARCHITECTURE.md).

### F2 — One management operation executor

Owner: [PLAN-RUNTIME-ARCHITECTURE](PLAN-RUNTIME-ARCHITECTURE.md).

### F3 — SCIM decomposition and query processing

Owner: [PLAN-SCIM](PLAN-SCIM.md).

### F4 — Sessions off the per-request write path

Owner: [PLAN-RUNTIME-ARCHITECTURE](PLAN-RUNTIME-ARCHITECTURE.md).

### F5 — Schema migration out of the web process

Owner: [PLAN-RUNTIME-ARCHITECTURE](PLAN-RUNTIME-ARCHITECTURE.md).

### F6 — Provider fork retirement and provenance

Owner: [PLAN-DATABASE-PROVIDER](PLAN-DATABASE-PROVIDER.md).

### F7 — Supported MariaDB baseline

Owner: [PLAN-DATABASE-PROVIDER](PLAN-DATABASE-PROVIDER.md).

### F9 — Unambiguous normalized email identity

Owner: [PLAN-ACCOUNT-EMAILS](PLAN-ACCOUNT-EMAILS.md).

### F10 — Dynamic client registration lifecycle

Owner: [PLAN-PROTOCOL-ASSURANCE](PLAN-PROTOCOL-ASSURANCE.md).

### F11 — Breached-password availability policy

Owner: [PLAN-PRODUCTION-GATES](PLAN-PRODUCTION-GATES.md).

### F12 — GCM budget

Owner: [PLAN-KEYS-VAULT](PLAN-KEYS-VAULT.md).

### F14 — Security-critical protocol annotations

Owner: [PLAN-RUNTIME-ARCHITECTURE](PLAN-RUNTIME-ARCHITECTURE.md).

### F15 — Multiple email addresses per account

Owner: [PLAN-ACCOUNT-EMAILS](PLAN-ACCOUNT-EMAILS.md).

### G1 — Security decisions must be observable

Owner: [PLAN-OBSERVABILITY-CONFORMANCE](PLAN-OBSERVABILITY-CONFORMANCE.md).

### G2 — Conformance and certification

Owner: [PLAN-OBSERVABILITY-CONFORMANCE](PLAN-OBSERVABILITY-CONFORMANCE.md).

### G3 — Distributed, browser and fault verification

Owner: [PLAN-OBSERVABILITY-CONFORMANCE](PLAN-OBSERVABILITY-CONFORMANCE.md).

### G4 — Legacy cutover operational gates **(operational)**

Owner: [PLAN-PRODUCTION-GATES](PLAN-PRODUCTION-GATES.md).

### G5 — Confirmed-email rollout **(operational)**

Owner: [PLAN-ACCOUNT-EMAILS](PLAN-ACCOUNT-EMAILS.md).

### G6 — Forward-looking protocol work

Owner: [PLAN-PROTOCOL-ROADMAP](PLAN-PROTOCOL-ROADMAP.md).

### G7 — Coordinated disclosure **(operational)**

Owner: [PLAN-PRODUCTION-GATES](PLAN-PRODUCTION-GATES.md).

## Closure criteria

- [ ] **CR1** — Every item above is either implemented and regression-tested, or linked
  to an explicitly accepted risk with an owner and an expiry date
- [ ] **CR2** — Observe-mode telemetry shows no unexplained future denials for the cohort
  being enabled
- [ ] **CR3** — No production feature, grant, endpoint, client type or user journey was
  removed to close an item
- [ ] **CR4** — Fresh-install and additive-upgrade schemas are equivalent at HEAD
- [ ] **CR5** — CI covers the supported database versions, a locked restore/container
  build, the security-boundary tests and secret scanning
- [ ] **CR6** — Every operational item has environment evidence in the format of
  [`RUNBOOK-PRODUCTION-EVIDENCE.md`](../runbooks/RUNBOOK-PRODUCTION-EVIDENCE.md)
- [ ] **CR7** — Release build plus the focused and full regression suites are green
