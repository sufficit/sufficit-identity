# Product

## Register

product

## Users

Two distinct audiences share the same surface, with very different mental models:

1. **End users (the people logging in).** Subscribers and account holders of the
   Sufficit ecosystem (telephony/PABX, provisioning, billing). Their context when
   reaching the Identity UI is almost always *interrupted*: they were trying to do
   something in another product, got bounced to a login or consent screen, and want
   to get back to their task as fast as possible. Their job-to-be-done is
   "authenticate and return." Trust signals matter — a login screen that looks
   unpolished or insecure makes them doubt the whole platform. They are not
   technical; many are small-business owners in Brazil, often on mobile, sometimes
   on poor connections.

2. **Administrators (Sufficit staff and resellers).** Use the management surface to
   create clients, manage scopes, inspect sessions, rotate secrets, provision users.
   Their workflow is slower, more deliberate, table-driven. They need density,
   clarity, and auditability — not marketing polish.

## Product Purpose

Sufficit Identity is the OAuth 2.1 / OIDC identity provider for the entire Sufficit
platform. This UI project replaces the legacy Skoruka-based STS frontend with a
modern, secure, fast Blazor Server interface that talks to the new OpenIddict 7.6
backend.

Success looks like:
- A login page a user can complete in under 30 seconds on mobile data.
- A consent screen that makes it *obvious* what a third-party client is asking for —
  no dark patterns, no buried defaults.
- Passwordless (passkey/WebAuthn) as a first-class option, not a hidden feature.
- A management surface that lets an admin ship a new OAuth client in minutes.
- Visual cohesion with the broader Sufficit brand so the identity screen never feels
  like a different company is "verifying" the user.

## Brand Personality

**Profissional. Seguro. Direto.** (Professional. Secure. Direct.)

Three words, in priority order:
1. **Profissional** — competent, polished, never amateurish. The visual language of a
   serious infrastructure provider, not a startup landing page.
2. **Seguro** — trustworthy by posture, not by slogans. Security is communicated
   through restraint, clarity, and absence of gimmicks — the way a bank vault
   communicates "your assets are safe" without a single word.
3. **Direto** — respect for the user's time. No vanity animation, no marketing copy
   on a login screen, no friction for friction's sake.

**Emotional goal:** when a user lands here, they should feel "I'm in competent hands"
within the first second. Not delight, not surprise — *reassurance*. The fastest way to
lose that feeling is to look like a template or a side project.

**Voice/tone:**
- Brazilian Portuguese, formal-adjacent (você), concise.
- Error messages state what happened and what to do next. Never blame the user.
- Empty states explain the path forward. Never "No results." alone.

**References (the feel we want, not layouts to copy):**
- **Auth0** (Universal Login) — the gold standard for "an identity screen that doesn't
  feel like a captive portal." Centered card, generous whitespace, passkey-first,
  brandable but disciplined.
- **Authentik** — open-source IDP whose management UI proves that "secure" does not
  have to mean "ugly." Dense, expert-friendly admin without sacrificing polish.
- **Zitadel** — the right balance of brand presence and functional restraint on the
  login surface.

## Anti-references

The user did not name specific anti-references. From the product context, the
following are implicit anti-patterns this UI must avoid:

- **Captive-portal aesthetics** — government/ISP login pages that look trapped,
  unstyled, or like a 2008 form. The identity screen must never look like the user
  is being held hostage.
- **Generic Bootstrap/Tailwind defaults** — the default `$primary: blue` look that
  signals "we didn't design this." Sufficit has a brand red (`#cc0000`); use it.
- **Dark patterns in consent** — pre-checked "allow everything" boxes, hidden
  scopes, "Decline" buttons styled as ghost text while "Allow" is a giant CTA.
  Consent must be a genuine, reversible choice.
- **Marketing on auth surfaces** — no "Try our new features!" banners on the login
  page. The login screen has exactly one job.
- **Gamified security** — progress bars for "password strength" that congratulate the
  user, cartoon mascots, confetti for enabling MFA. Security is not a game.

## Design Principles

These are strategic principles derived from the brand intent. They are NOT visual
rules (those live in DESIGN.md).

1. **Practice what you preach.** This is an identity provider. If our own login page
   looks insecure, slow, or janky, no one will believe our security claims. The UI
   itself is the strongest (or weakest) marketing for trust.

2. **Show, don't tell.** Don't write "Your data is safe with us." Show passkeys
   offered first-class. Show exactly which scopes a client is requesting, named in
   plain language. Show session lifetime as a visible countdown. Trust is earned
   through visible competence, not declared through copy.

3. **Expert restraint.** The Sufficit brand red is a resource, not a theme park. Use
   it where it carries meaning (primary action, brand mark, critical alert) and step
   back everywhere else. A page that is 70% red communicates "alarm," not "brand."

4. **Speed is a security feature.** A login page that takes 3 seconds to render on
   3G looks unprofessional and erodes trust before the user even sees the form. Ship
   minimal CSS, inline critical path, no render-blocking JS. The fastest secure UI is
   the most trustworthy-feeling UI.

5. **Accessibility is the floor, not a feature.** WCAG 2.2 AA is the minimum. Login
   forms are used by everyone — there is no "accessibility mode." Color contrast,
   keyboard navigation, focus management, screen-reader labels are non-negotiable
   from day one.

6. **Uma única fonte de verdade em runtime.** UI e controllers da API chamam os
   mesmos use cases de aplicação. HTTP é opcional dentro do mesmo processo; o
   que não pode existir é acesso direto da UI a banco, Identity, OpenIddict ou
   uma segunda implementação das regras.

## Accessibility & Inclusion

- **Target: WCAG 2.2 AA.** All interactive elements must be operable by keyboard
  alone, including the consent flow, passkey enrollment, and session revocation.
- **Contrast:** Sufficit red `#cc0000` on white passes AA for large text and UI
  components but fails AA for body text — never use it for paragraph copy. Body text
  uses the charcoal `#343132` token.
- **Reduced motion:** all transitions must honor `prefers-reduced-motion`. No
  auto-playing animations, no parallax on auth surfaces.
- **Color blindness:** never communicate state (success/error) by color alone. Pair
  every red error state with an icon and text. Sufficit red and Sufficit green
  must never be the sole differentiator.
- **Input modes:** support passkey/WebAuthn, hardware keys, TOTP, and password — in
  that priority order — so users with different abilities and threat models have a
  path that works for them.
- **Localization:** the surface is pt-BR first, but the design must accommodate
  longer strings (Spanish/English) without layout breakage.
