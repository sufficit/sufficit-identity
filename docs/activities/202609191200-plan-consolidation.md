# Twelve plans became one, and the first verification pass was wrong

Plan: `PLAN-IDENTITY.md` — this is how that file came to exist.

Seventeen plan documents were reconciled into one on 2026-09-19. Each item was
checked against the working tree rather than against the plan it came from.

## What the first pass found

Five items were already delivered and were deleted rather than carried over:
the protocol feature registrar and the feature-unit composition
(`IProtocolFeature` and its eleven features), the `#if APPLICATION_CONTRACTS`
dual compilation, the systemd sandboxing, and CIBA answering 404 when
disabled. Four more were rewritten because the code had moved further than the
item admitted: SCIM extraction, session activity writes, `AutoMigrate`, and
the breached-password failure mode.

## What the first pass got wrong

It searched for symbols. A missing type was read as missing work, and that was
wrong often enough to matter:

- the tenant machinery (A1) was absent because a product decision removed it,
  not because it was pending — `ContextId`, `IManagementContextResolver`,
  per-query predicates and SCIM partitions were exactly what commit `cd67f51`
  deleted, and `ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md` says not to
  reintroduce them without a new decision
- JAR and JARM (B6) were built; what was missing was tests for the refusals
- the DPoP nonce (B4) had the right store written and the wrong one registered

The second pass, on 2026-09-20, read the code instead, and corrected A3, A4,
B3, B5, C4, D1, D6 and E4 to what it actually does. It also marked one item as
a decision rather than a task — A4's remembered-MFA question, where an
evaluation asked the plan to reverse a deliberate fix. The owner answered it
the same day: a remembered device satisfies Management but does not mint
credentials.

**The rule this produced:** absence of a symbol is not evidence of absent
work, and a plan item that contradicts a recorded decision is the item that is
wrong. Check `README`, `ARCHITECTURE-*` and commits before believing a
checkbox.

## Where the retired plans went

| Retired plan | Now |
|---|---|
| `PLAN-GPT-5-REMAINING` | A1, A4, B1–B3, B5, C2, C4, D2, D6, F3, F4, F5, F10, F13, G1, G2, G3 |
| `PLAN-GLM-5-2-REMAINING` | A1, A2, A3, B1, F3, F6, F11 |
| `PLAN-SECURITY-HARDENING-WAVE-2` | A1, A2, A3, B2, B3, B5, B7, B8, C2, C3, C4, D1, D3, F6–F10, F14, closure criteria |
| `PLAN-FABLE-5-TRIAGE` | A4, B2, B3, C2, D6, F2, F12 |
| `PLAN-PRODUCTION-READINESS` | C1, C2, C5, D1, D4, D5, E8, F3, G2, G5, G6 |
| `PLAN-MANAGEMENT-APPLICATIONS` (+ `-NEXT`) | A2, E1–E4, E6 |
| `PLAN-CLIENT-OPERATIONAL-STATE` | E1 |
| `PLAN-MANAGEMENT-UI-STATE-CONSISTENCY` | E5 |
| `PLAN-PLUGGABLE-UI-PHASES-2-5` | E7 |
| `PLAN-LEGACY-CUTOVER-OPS` | G4 |
| `PLAN-FAPI2-CONFORMANCE` | B9 |
| `PLAN-VAULT`, `PLAN-VAULT-UI`, `PLAN-STRIX-IDENTITY`, `PLAN-SHARED-FRONTEND-STRATEGY`, `PLAN-20260814-EVEO-APPS-HEALTHCHECK` | delivered; retired 2026-09-19 |

The delivered work behind every one of them is in `../activities/`. The vault's
operational procedure is `../runbooks/RUNBOOK-VAULT.md`; the conformance
environment and its accepted results are `conformance/README.md` and
`conformance/config/`.
