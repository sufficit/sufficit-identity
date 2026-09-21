# Guided Vault entry for agent-managed integrations

Agents could tell a user to create a provider API key, but had no safe way to
prepare the exact personal Vault destination. Users were left to find the
right screen and choose a name, or were tempted to paste credentials into the
conversation.

The Identity MCP now exposes `vault_prepare_entry`. It validates and
canonicalizes a personal secret name in the authenticated user's context and
returns a complete `/vault/new?name=...` URL plus existence metadata. It never
creates an empty secret and never accepts or returns the secret value. After
the user saves, the agent can check the exact returned name with
`vault_get_info`.

The new authenticated Vault page presents the canonical name read-only and
accepts only the value. It attempts clipboard read after the interactive page
loads, keeps manual paste available when the browser denies permission, never
overwrites concurrent typing, and saves only after the user's explicit action.
Existing entries show a replacement warning. Names are checked with a bounded,
linear character-and-segment validation so query input cannot cause expensive
regular-expression evaluation.

## Decisions

- Provider keys remain in the existing personal Vault and never enter the chat,
  URL, logs, or MCP result.
- The URL carries metadata only; it cannot select another user or redirect to an
  external origin.
- Clipboard access is convenience only because browsers may deny it even in a
  secure context.
- The first concrete consumer is the production ASAAS onboarding flow, while the
  contract remains provider-neutral.

## Verification and delivery

- 1,557 Identity tests passed before delivery; the final MCP/UI-focused run
  passed 20 tests with no warnings.
- Release build passed with warnings treated as errors.
- Chromium checks covered automatic paste, explicit save, replacement warning,
  invalid links, denied clipboard fallback, and a 390 px viewport.
- Commit `91163e2` was packaged and activated on the three production Identity
  nodes with healthy readiness checks and matching certificates/JWKS.
- PR #78 records the delivery. A CodeQL review then identified the original
  bounded name regex; this activity includes its equivalent linear replacement.
