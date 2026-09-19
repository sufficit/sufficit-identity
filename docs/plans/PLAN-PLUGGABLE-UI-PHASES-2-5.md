# Pluggable UI — phases 2-5 pending

> **Status:** Phases 0-1 complete; Phase 2 partially delivered (reconferido 2026-09-19) (see `202608012000-pluggable-ui-phase0-phase1.md`). The embedded deployment works; the items below are for remote/BFF UI hosting and third-party SDK support.

## Phase 2 — explicit embedded composition
- [x] Versioned module descriptor (`UiModuleDescriptor`, `IUiModuleRegistry`)
- [ ] Semantic endpoint registration (module-declared routes, not hard-coded paths)
- [ ] Official embedded composition executable (standalone, not just the API host)
- [x] Reject missing/duplicate/incompatible UI modules at startup
  (`UiCompositionValidation`, `UiCompositionException`)

## Phase 3 — remote Management UI
- [ ] Publish complete versioned Management HTTP contract (BFF API spec)
- [ ] Standalone BFF host with code flow, PKCE, server-side tokens
- [ ] End-to-end authorization/CSRF/logout/token-leakage tests

## Phase 4 — remote public interaction
- [ ] Specify and threat-model opaque interaction protocol (login, consent, device, logout)
- [ ] Durable distributed interaction state and replay protection
- [ ] Replace hard-coded UI redirects with semantic endpoint resolution
- [ ] End-to-end coverage (login, external, MFA, passkeys, consent, logout, device, registration)

## Phase 5 — third-party SDK
- [ ] Publish templates, examples, packages, compatibility policy
- [ ] Publish and run conformance kit in CI
- [ ] Document trusted package approval and remote-provider registration
