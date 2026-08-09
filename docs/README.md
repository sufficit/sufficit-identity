# Documentation index

This directory is organized by document purpose. `README.md` is reserved for
indexes; every other Markdown file uses `TYPE-SUBJECT.md`, with an uppercase
type prefix and an uppercase kebab-case subject. Completed work is archived in
`activities/` with a `YYYYMMDDHHmm-` timestamp prefix.

## Naming convention

| Prefix | Use |
| --- | --- |
| `ARCHITECTURE-` | Durable boundaries, ownership and technical decisions |
| `DESIGN-` | Product intent, interaction and visual-system rules |
| `PLAN-` | Active work with explicit gates — only pending items |
| `RUNBOOK-` | Ordered operational procedure, validation and rollback |
| `USAGE-` | Configuration and consumer-facing use of an implemented feature |
| `EVALUATION-` | Evaluation instructions or dated assessment |
| `INVESTIGATION-` | Time-bounded evidence, diagnosis and conclusions |

Dated evaluations that are useful only as historical evidence live under
`archive/evaluations`.

## Active plans (pending work)

- [Claude Fable 5 evaluation — remaining work](plans/PLAN-CLAUDE-FABLE-5-REMAINING.md) — fail-closed posture, protocol invariants, vault custody and key lifecycle
- [GPT-5 evaluation — remaining work](plans/PLAN-GPT-5-REMAINING.md) — residual protocol, trust-boundary and production-assurance work
- [GLM-5.2 evaluation — remaining work](plans/PLAN-GLM-5-2-REMAINING.md) — residual authorization, secret and maintainability work
- [Management applications](plans/PLAN-MANAGEMENT-APPLICATIONS.md) — complete OAuth/OIDC application lifecycle in the Management console
- [Production readiness](plans/PLAN-PRODUCTION-READINESS.md) — certification, CSP calibration, WCAG, forward protocols
- [Legacy cutover — operational gates](plans/PLAN-LEGACY-CUTOVER-OPS.md) — clients, keys, rehearsals
- [Pluggable UI — phases 2-5](plans/PLAN-PLUGGABLE-UI-PHASES-2-5.md) — remote UI, BFF, SDK
- [Internal vault](plans/PLAN-VAULT.md) — Phase 1 delivered; named-secret and signing-key phases remain

## Completed work (activities/)

- [Vault signing-key lifecycle and KEK separation](activities/202608092355-completed-vault-signing-key-lifecycle.md)
- [Vault production fail-closed boundaries](activities/202608091930-completed-vault-fail-closed-boundaries.md)
- [DPoP/mTLS sender-constraint exclusivity](activities/202608091925-completed-sender-constraint-exclusivity.md)
- [Client and Request Object invariants](activities/202608091918-completed-pkce-jar-invariants.md)
- [Security-sensitive policy defaults](activities/202608091911-completed-secure-policy-defaults.md)
- [Production posture — contributors and fail-closed](activities/202608091904-completed-production-posture-contributors.md)
- [Security hardening wave 2](activities/202608071330-completed-security-hardening-wave-2.md)
- [GPT-5 evaluation remediation](activities/202608071227-completed-gpt-5-remediation.md)
- [GLM-5.2 evaluation remediation](activities/202608071210-completed-glm-5-2-remediation.md)
- [Protocol roadmap baseline](activities/202608011800-completed-protocol-roadmap-baseline.md)
- [Legacy cutover — DB/provider gates](activities/202608011820-completed-legacy-cutover-db-provider.md)
- [Pluggable UI — phases 0-1](activities/202608012000-completed-pluggable-ui-phase0-phase1.md)
- [Internal vault — Phase 1](activities/202608081430-completed-vault-phase-1.md)
- [Internal vault — Phases 2/3 foundation](activities/202608081745-vault-phases-2-3-foundation.md)
- [Internal vault — signing provider and JWKS](activities/202608081530-completed-vault-signing-provider-jwks.md)

## Architecture

- [Repository and module architecture](architecture/ARCHITECTURE-REPOSITORY.md)
- [Single-source UI boundary](architecture/ARCHITECTURE-SINGLE-SOURCE-UI.md)
- [Management authorization boundary](architecture/ARCHITECTURE-MANAGEMENT-AUTHORIZATION.md)
- [Public UI architecture](architecture/ARCHITECTURE-PUBLIC-UI.md)

## Design

- [Product definition](design/DESIGN-PRODUCT.md)
- [Visual and interaction system](design/DESIGN-SYSTEM.md)
- [Management product definition](design/DESIGN-MANAGEMENT-PRODUCT.md)
- [Management visual contract](design/DESIGN-MANAGEMENT-UI.md)

## Usage

- [Embedded public and Management UIs](usage/USAGE-EMBEDDED-UI.md)
- [SCIM 2.0](usage/USAGE-SCIM.md)
- [Database migration assets](migration/README.md)

## Operations

- [Deployment configuration](runbooks/RUNBOOK-DEPLOYMENT.md)
- [Database connection resilience and monitoring](runbooks/RUNBOOK-DATABASE-CONNECTION-RESILIENCE.md)
- [CSP calibration](runbooks/RUNBOOK-CSP-CALIBRATION.md)
- [Confirmed-email rollout](runbooks/RUNBOOK-CONFIRMED-EMAIL.md)
- [Internal vault](runbooks/RUNBOOK-VAULT.md)

## Investigations

- [Production-readiness assessment](investigations/INVESTIGATION-PRODUCTION-READINESS.md)

## Evaluations

- [Evaluation prompt](evaluations/EVALUATION-PROMPT.md)

An evaluation describes the repository at a point in time. Findings that still
require work must be copied into the relevant active plan; an archived evaluation
must never silently become the current roadmap.
