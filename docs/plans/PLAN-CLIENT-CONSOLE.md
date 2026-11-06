# PLAN — Client console lifecycle and operation

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

A2 owns secret-reference API parity; E2 owns console adoption. E4 owns typed application claims. Reuse the existing audit search, metrics and revocation surfaces.

## Acceptance

No secret copied by cloning or list rendering; capability checks on mutations; a paginated client audit timeline; measured scale and mobile/accessibility evidence.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## E2 — Application lifecycle: credentials and cloning

Rotation, overlap/revocation, one-time display and metadata-only lists exist. Rotation currently uses ClientsUpdate, not its own capability. Vault provenance in the UI and safe cloning remain.

Evidence: [ClientEdit.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/ClientEdit.razor), [ClientManagementService.Mutations.Lifecycle.cs](../../src/management/Clients/ClientManagementService.Mutations.Lifecycle.cs), [ClientsControllerTests.Credentials.cs](../../src/tests/ClientsControllerTests.Credentials.cs), [USAGE-MANAGED-CLIENT-CREDENTIALS.md](../usage/USAGE-MANAGED-CLIENT-CREDENTIALS.md).

- [ ] **E2.1 · partial** — Integrate vault SecretReference selection/provenance into the console credential surface, reusing create/update backend support. Depend on A2.4 for rotate/additional-credential parity.
- [ ] **E2.2 · partial** — Give existing explicit secret rotation its own capability, with compatibility rollout and tests. It currently demands ClientsUpdate; do not implement another rotation engine.
- [ ] **E2.3 · partial** — Keep existing metadata-only credential lists and one-time secret display; add missing safe vault origin/version/date context. Do not restore secret-derived hints, already removed by migration 107.
- [ ] **E2.4 · pending** — Cloning that copies no secret, token, authorization or operational state
- [ ] **E2.5 · partial** — Complete and verify the impact/revocation matrix for remaining credential/lifecycle actions. Reuse the existing disable-client confirmation and policy-controlled token revocation; do not revoke every token unconditionally.
- [ ] **E2.6 · partial** — Extend existing managed-credential overlap/revocation documentation with explicit rollback and recovery for vault-reference adoption and cloning.

## E3 — Application operation and scale

Client-filtered metrics and links to filtered session/authorization revocation already exist. The audit backend now filters resources, but Audit.razor still uses the newest-event list.

Evidence: [Metrics.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/Metrics.razor), [MetricsManagementService.cs](../../src/management/Metrics/MetricsManagementService.cs), [ClientDetail.razor](../../src/ui/Sufficit.Identity.UI.Management/Components/Pages/ClientDetail.razor), [SessionsAndAuthorizationsControllerTests.cs](../../src/tests/SessionsAndAuthorizationsControllerTests.cs), [USAGE-AUDIT-HISTORY.md](../management/USAGE-AUDIT-HISTORY.md).

- [ ] **E3.2 · partial** — Build the client audit timeline in the console using POST /api/audit/search with resourceType/client ID, interval and cursor. Backend filtering/pagination and access control are implemented; do not rebuild them.
- [ ] **E3.4 · pending** — Volume test with thousands of clients

## E4 — Application advanced settings (only where enforcement is real)

The management contract exposes lifetimes, PAR and authentication settings, not the requested complete typed metadata/claim extension model. Existing claim-release policy must be reused.

Evidence: [ClientManagementContracts.cs](../../src/application/Sufficit.Identity.Application.Abstractions/Management/Clients/ClientManagementContracts.cs), [TokenIssuancePolicies.cs](../../src/sts/TokenIssuancePolicies.cs), [ClientDefinitionPolicyTests.cs](../../src/tests/ClientDefinitionPolicyTests.cs).

- [ ] **E4.1 · pending** — Typed public metadata (`description`, `client_uri`, `logo_uri`)
- [ ] **E4.2 · pending** — Application claims with allow-list and destinations, through a release policy that sees client, grant, scopes, resources and destination and is shared by the grants and the privileged mints ([`202610240200`](../activities/202610240200-no-unified-issuance-service.md))
- [ ] **E4.3 · pending** — Advanced properties with a namespace and reserved keys
- [ ] **E4.4 · partial** — Inventory runtime-supported per-client DPoP/JAR/CIBA/FAPI settings and expose only validated options. Reuse current PAR, lifetimes and authentication-method controls.

Acceptance rule E4.5: every new profile includes a validator, explanation and tests.

## E6 — Mobile-first validation and rollout

Page overflow and drawer tab order already have responsive coverage; this is not evidence for all create/edit interactions, real virtual keyboards or concurrent editing.

Evidence: [ManagementConsoleResponsiveTests.cs](../../src/tests/Sufficit.Identity.BrowserTests/ManagementConsoleResponsiveTests.cs), [202610282200-plan-closed-sections.md](../activities/202610282200-plan-closed-sections.md).

- [ ] **E6.1 · partial** — Validate create/edit configurator interactions at 320–430 px, tablet and desktop. Reuse the existing all-page overflow and drawer tab-order tests; they do not cover every form interaction.
- [ ] **E6.2 · pending** — Validate keyboard, focus, virtual keyboard, deep link, F5 and concurrency on the creation and edit flows
- [ ] **E6.3 · operational** — Publish the update capability per deployment and validate the real clients

## E8 — Accessibility and localization

Responsive and keyboard checks are partial evidence, not a completed WCAG 2.2 AA audit of both UIs.

Evidence: [ManagementConsoleResponsiveTests.cs](../../src/tests/Sufficit.Identity.BrowserTests/ManagementConsoleResponsiveTests.cs).

- [ ] **E8.1 · pending** — WCAG 2.2 AA accessibility audit of both embedded UIs

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
