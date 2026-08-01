# Documentation index

This directory is organized by document purpose. `README.md` is reserved for
indexes; every other Markdown file uses `TYPE-SUBJECT.md`, with an uppercase
type prefix and an uppercase kebab-case subject.

## Naming convention

| Prefix | Use |
| --- | --- |
| `ARCHITECTURE-` | Durable boundaries, ownership and technical decisions |
| `DESIGN-` | Product intent, interaction and visual-system rules |
| `PLAN-` | Active roadmap or controlled migration with explicit gates |
| `RUNBOOK-` | Ordered operational procedure, validation and rollback |
| `USAGE-` | Configuration and consumer-facing use of an implemented feature |
| `EVALUATION-` | Evaluation instructions or dated assessment |
| `INVESTIGATION-` | Time-bounded evidence, diagnosis and conclusions |

Dated evaluations that are useful only as historical evidence live under
`archive/evaluations`. That directory is local-only because evaluations can
contain environment-sensitive observations. Its content is not an active plan
and is intentionally ignored by Git.

## Current source of truth

- [Active roadmap](plans/PLAN-ROADMAP.md)
- [Pluggable and remote user interfaces](plans/PLAN-PLUGGABLE-USER-INTERFACES.md)
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
- [Confirmed-email rollout](runbooks/RUNBOOK-CONFIRMED-EMAIL.md)
- [Legacy cutover and rollback gates](plans/PLAN-LEGACY-CUTOVER.md)

## Evaluations

- [Evaluation prompt](evaluations/EVALUATION-PROMPT.md)

An evaluation describes the repository at a point in time. Findings that still
require work must be copied into `PLAN-ROADMAP.md`; an archived evaluation must
never silently become the current roadmap.
