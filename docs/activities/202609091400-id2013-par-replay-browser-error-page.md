# ID2013 PAR replay — browser-friendly authorization error page — 2026-09-09

## Purpose

Investigate and fix the production report: clicking **"Continuar com esta
conta"** on `https://identity.sufficit.com.br/account/login` (session-active
card, `returnUrl=/connect/authorize?...request_uri=urn:ietf:params:oauth:
request_uri:Vglkej6...`) returned a raw

```
error:invalid_token
error_description:The specified token has already been redeemed.
error_uri:https://documentation.openiddict.com/errors/ID2013
```

## Root cause

- The relying party (`SufficitBlazorServer`, .NET 10 OIDC client /
  IdentityModel 8.19.2) uses **PAR automatically** whenever the discovery
  document advertises `pushed_authorization_request_endpoint` (confirmed
  present; `request_uri_parameter_supported=false`, so PAR is the only path).
- Per RFC 9126 §6.1 a PAR `request_uri` is **single-use**. OpenIddict 7.6
  (`ValidateTokenPrincipal`/redeem path, `RestorePushedAuthorizationRequest-
  Parameters`) redeems the request token when the authorization completes
  successfully, not on the anonymous challenge round-trip.
- The user completed the flow earlier (cookie issued, code issued, request
  token redeemed — production `tokens` table shows 449 `redeemed`
  `request_token` rows for this client), then re-opened a **stale login tab**.
  With the session active, `/account/login` renders the "Você já está
  autenticado" card, whose button is a plain link to the `returnUrl` — i.e. a
  re-GET of `/connect/authorize` with the **already-redeemed** `request_uri`.
- On replay the validation pipeline rejects the request **before** the
  controller runs and before any `redirect_uri` can be restored from the
  redeemed token (the validation context is rejected, so
  `AttachRedirectUri` leaves the response without a redirect target).
  OpenIddict's terminal `ProcessLocalErrorResponse` therefore writes the bare
  `text/plain` body above — which humans see raw.

Evidence gathered:

- `ParLoginRoundTripTests` pins the semantics end-to-end: anonymous 1st GET →
  login challenge; authenticated 2nd GET with the SAME `request_uri` → code
  issued (the healthy flow works); 3rd GET → `invalid_token` replay rejection.
  So this is NOT a systemic PAR-login failure.
- Production DB (via `SUFFICIT_SECRET_DATABASE_CONNECTION_STRING`, db
  `identity`): healthy PAR chains for the client all day (e.g. 13:37:28 push →
  redeem 584 ms later → code → tokens); the incident token `Vglkej6...` no
  longer exists (expired ≤1 h / pruned) but the error text proves it was in
  `redeemed` state at click time.
- nginx access log uses the sanitized `identity_sanitized` format (no query
  strings by design), and the STS journal does not log validation rejections —
  which is why the incident left no server-side trail beyond the DB state.

## Fix

`src/sts/ErrorPages/BrowserAuthorizationErrorPage.cs` — custom OpenIddict
server handler (`ApplyAuthorizationResponseContext`) registered in
`OpenIddictServerConfiguration.ConfigureOpenIddictServer`, alongside the
other custom server handlers:

- Runs immediately **before** `ProcessLocalErrorResponse` (order −500).
- Only engages when: the response carries a protocol error, **no**
  `context.RedirectUri` is recoverable (errors deliverable to the RP —
  `prompt=none`, normal code-flow errors — are never intercepted), and the
  request is a top-level **browser navigation** (`Accept: text/html`).
- Renders a self-contained, CSP-safe pt-BR HTML page (no scripts/styles/
  remote resources) explaining that the authorization request was already
  used or expired, with the technical details (error/description/uri and
  `trace_id`) folded into a `<details>` block for support.
- Machine clients (OAuth libraries, tests, health probes — anything not
  sending `Accept: text/html`) keep the raw protocol payload unchanged.

## Files changed

- `src/sts/ErrorPages/BrowserAuthorizationErrorPage.cs` (new)
- `src/sts/OpenIddictServerConfiguration.cs` (handler registration; the
  custom-handler registration block moved here from
  `ServiceCollectionExtensions` during the main-branch refactor)
- `src/tests/ParLoginRoundTripTests.cs` (new — reproduction + pinned
  semantics: round-trip survives, replay rejected, dual transport)

## Verification

- `dotnet test --filter ParLoginRoundTripTests` → 1/1 (browser gets the
  humanized HTML with `data-openiddict-error="invalid_token"`; machine client
  still gets the raw `invalid_token` payload).
- Full suite: **798/798 passed** (no regression from the globally registered
  handler).

## Follow-ups

- [ ] Deploy the fix (production still runs release
      `20260905T182543Z-5010513`, which predates this change).
- [ ] Optional hardening: emit `Cache-Control: no-store` on
      `/account/login` responses so stale tabs at least re-validate with the
      server on history/back navigation (does not fix pinned-open tabs, only
      cached ones).
