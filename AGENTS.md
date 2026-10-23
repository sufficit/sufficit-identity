# Contributor instructions

Sufficit Identity is a public, general-purpose identity provider for any person or
organization. Follow the generic product boundary in `PRODUCT.md`.

- Do not add the maintainer's or a consumer's business model, domain roles,
  commercial rules or product-specific workflows/integrations to Identity.
- Keep authorization mechanisms generic. Treat consumer-defined entitlement,
  scope and claim values as opaque data, subject to generic security policies.
- Use fictional service/application names in examples, fixtures and tool guidance.
- Project branding, package/namespace names and attribution may retain Sufficit.
- Preserve compatibility contracts without interpreting consumer business semantics.
- Every Markdown file must be reachable through relative links starting at
  `README.md`, linked from its natural parent (the `docs/README.md` section of
  its type, a project README, or the document it extends), and must not link to
  missing `.md` files (`src/tests/MarkdownCoverageTests.cs`). Only historical
  records are exempt, via `.markdown-coverage-ignore`.
- Agent skill: [temporary management token](.claude/skills/identity-temporary-token/SKILL.md).
