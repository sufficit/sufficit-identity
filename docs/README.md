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

- [GPT-5 evaluation — remaining work](plans/PLAN-GPT-5-REMAINING.md) — residual protocol, trust-boundary and production-assurance work
- [GLM-5.2 evaluation — remaining work](plans/PLAN-GLM-5-2-REMAINING.md) — residual authorization, secret and maintainability work
- [Management applications](plans/PLAN-MANAGEMENT-APPLICATIONS.md) — complete OAuth/OIDC application lifecycle in the Management console
- [Production readiness](plans/PLAN-PRODUCTION-READINESS.md) — certification, CSP calibration, WCAG, forward protocols
- [Legacy cutover — operational gates](plans/PLAN-LEGACY-CUTOVER-OPS.md) — clients, keys, rehearsals
- [Pluggable UI — phases 2-5](plans/PLAN-PLUGGABLE-UI-PHASES-2-5.md) — remote UI, BFF, SDK

## Completed work (activities/)

- [GPT-5 evaluation remediation](activities/202608071227-completed-gpt-5-remediation.md)
- [GLM-5.2 evaluation remediation](activities/202608071210-completed-glm-5-2-remediation.md)
- [Protocol roadmap baseline](activities/202608011800-completed-protocol-roadmap-baseline.md)
- [Legacy cutover — DB/provider gates](activities/202608011820-completed-legacy-cutover-db-provider.md)
- [Pluggable UI — phases 0-1](activities/202608012000-completed-pluggable-ui-phase0-phase1.md)

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

## Investigations

- [Production-readiness assessment](investigations/INVESTIGATION-PRODUCTION-READINESS.md)

## Evaluations

- [Evaluation prompt](evaluations/EVALUATION-PROMPT.md)

An evaluation describes the repository at a point in time. Findings that still
require work must be copied into the relevant active plan; an archived evaluation
must never silently become the current roadmap.
