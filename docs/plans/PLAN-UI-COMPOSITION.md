# PLAN — Pluggable UI and remote interaction

Status: queued; reviewed on 2026-11-06 against `a66456e`. No work item is in progress.

[Index and delivery rules](PLAN-IDENTITY.md) · [Item-by-item reconciliation](../activities/202611061100-plan-reconciliation-split.md)

## Scope and order

Execute phases 2, 3, 4 and 5 in order; a validated module registry is the existing starting point. Remote interaction requires a threat model before implementation.

## Acceptance

Semantic endpoints, standalone hosts, versioned contracts, no browser token leakage, replay/CSRF/logout tests and a distributable conformance kit.

Operational statuses describe evidence still required; historical records are not
a fresh production inventory. Source/tests present does not mean deployed.

## E7 — Pluggable UI, phases 2–5

Module registry/version validation is implemented. The requested semantic endpoint contract, standalone BFF/public interaction protocol and third-party kit are not established by these artifacts.

Evidence: [UiModuleRegistry.cs](../../src/ui/Sufficit.Identity.UI.Abstractions/Hosting/UiModuleRegistry.cs), [UiModuleRegistryTests.cs](../../src/tests/UiModuleRegistryTests.cs), [USAGE-EMBEDDED-UI.md](../usage/USAGE-EMBEDDED-UI.md).

- [ ] **E7.1 · pending** — **Phase 2:** semantic endpoint registration (module-declared routes rather than hard-coded paths); an official standalone embedded-composition executable, not just the API host
- [ ] **E7.2 · pending** — **Phase 3 — remote Management UI:** publish the complete versioned Management HTTP contract (BFF API spec); a standalone BFF host with code flow, PKCE and server-side tokens; end-to-end authorization/CSRF/logout/ token-leakage tests
- [ ] **E7.3 · pending** — **Phase 4 — remote public interaction:** specify and threat-model the opaque interaction protocol (login, consent, device, logout); durable distributed interaction state with replay protection; replace hard-coded UI redirects with semantic endpoint resolution; end-to-end coverage of login, external, MFA, passkeys, consent, logout, device and registration
- [ ] **E7.4 · pending** — **Phase 5 — third-party SDK:** templates, examples, packages and a compatibility policy; a conformance kit published and run in CI; documented trusted-package approval and remote-provider registration

## Validation required when executing

Run the tests cited in the evidence and targeted regressions for the remaining
behavior. Record exact commands, outcomes, release/commit and limitations.
For UI changes use the repository design/browser workflow; for production gates
attach dated redacted evidence and rollback. Do not close an item solely because
a related type, test name or historical deployment exists.
