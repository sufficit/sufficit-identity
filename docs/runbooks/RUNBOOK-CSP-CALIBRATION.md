# RUNBOOK — CSP Calibration

> **Goal:** calibrate the Content-Security-Policy against the real Blazor UI, collect violation reports, tighten directives, and flip from Report-Only to Enforce.

## Why this runbook exists

The STS ships CSP in **Report-Only** mode by default (`CspOptions.ReportOnly=true`). This is deliberate: a misconfigured CSP in Enforce mode breaks the UI (login, consent, device verification, logout, account management) — the highest-impact pages on an IdP. Report-Only mode emits violations to the browser console and the configured `report-uri` without blocking anything, so you can calibrate safely before enforcing.

**You must complete this calibration before any production deployment where the UI is exposed to end users.**

## Prerequisites

- The STS running with the embedded UI enabled, behind a reverse proxy with HTTPS
- A browser with DevTools (Chrome, Firefox, Edge)
- (Optional) a `report-uri` endpoint collector — the STS has a built-in CSP report endpoint at `/security/csp-report`

## Step 1 — Configure the report collector

In `appsettings.json` (or User Secrets), set the CSP report URI to the STS's own collector:

```jsonc
{
  "Sufficit": {
    "Identity": {
      "Csp": {
        "Enabled": true,
        "ReportOnly": true,
        "ReportUri": "/security/csp-report"
      }
    }
  }
}
```

Restart the STS. Verify the header is present:

```sh
curl -sk https://localhost:5001/account/login -o /dev/null -D - | grep -i content-security
```

Expected: `Content-Security-Policy-Report-Only: ...; report-uri /security/csp-report`

## Step 2 — Exercise every UI page

Open a browser and navigate through **every** interactive page. For each page, check:

1. **Browser DevTools Console** — look for CSP violation messages (red errors starting with "Refused to...")
2. **Network tab** — check that all resources load (no blocked scripts/styles/images)
3. **Server logs** — the `/security/csp-report` endpoint logs sanitized violation reports

### Pages to exercise

| Page | URL | What to test |
|---|---|---|
| Login | `/account/login` | Password login, external provider login, passkey login |
| Login with 2FA | `/account/loginwith2fa` | TOTP code entry, recovery code entry |
| Consent | `/consent` | Scope checkboxes, allow/deny (requires an OAuth client redirect) |
| Registration | `/account/register` | Form submission, validation messages |
| Forgot password | `/account/forgotpassword` | Email form |
| Reset password | `/account/resetpassword` | Password reset form |
| Confirm email | `/account/confirmemail` | Token redemption |
| Device verification | `/device` | User code entry, approve/deny |
| Account manage | `/manage` | Profile view |
| Change password | `/manage/changepassword` | Password change form |
| Passkey management | `/manage/passkeys` | Passkey registration, rename, removal |
| 2FA setup | `/manage/twofactor` | Authenticator setup, recovery codes |
| Sessions | `/manage/sessions` | Session list, revoke |
| Grants | `/manage/grants` | Connected applications, revoke |
| External logins | `/manage/externallogins` | Link/unlink providers |
| Personal data | `/manage/personaldata` | Data export |
| Logout | `/account/logout` | RP-initiated logout confirmation |

## Step 3 — Analyze violations

For each violation reported (console or server log), note:

1. **Which directive was violated** (e.g., `script-src`, `style-src`, `img-src`, `connect-src`)
2. **What resource was blocked** (a specific URL, inline script, inline style, WebSocket)
3. **Whether it's a false positive** (Blazor framework needs) or a **real policy gap**

### Common Blazor Server violations and their fixes

| Violation | Cause | Fix |
|---|---|---|
| `style-src 'unsafe-inline'` | Blazor injects inline styles for component state | Keep `'unsafe-inline'` in `style-src` OR add nonces (requires Blazor config change) |
| `connect-src` WebSocket blocked | SignalR circuit to same origin | Already covered by `'self'` — if blocked, check the proxy WebSocket forwarding |
| `img-src` avatar blocked | Avatar from a different domain | Add the domain to `img-src` (or use `data:` for inline avatars) |
| `script-src` blocked | Third-party script (analytics, etc.) | The default policy is `script-src 'self'` — add the domain only if the script is trusted |

## Step 4 — Tighten the policy

Edit `Csp.Policy` in `appsettings.json` based on the violations found:

```jsonc
{
  "Sufficit": {
    "Identity": {
      "Csp": {
        "Enabled": true,
        "ReportOnly": true,  // Keep Report-Only until Step 5
        "Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
      }
    }
  }
}
```

Restart and re-exercise all pages. Confirm **zero violations** in the console and server logs.

## Step 5 — Flip to Enforce

Once you see zero violations for a full UI exercise cycle:

```jsonc
{
  "Sufficit": {
    "Identity": {
      "Csp": {
        "Enabled": true,
        "ReportOnly": false,  // ← FLIP TO ENFORCE
        "Policy": "...your calibrated policy..."
      }
    }
  }
}
```

Restart. The header changes from `Content-Security-Policy-Report-Only` to `Content-Security-Policy`. Any future violation will **block** the resource.

## Step 6 — Verify enforcement

```sh
curl -sk https://localhost:5001/account/login -o /dev/null -D - | grep -i content-security
```

Expected: `Content-Security-Policy: default-src 'self'; ...` (no `-Report-Only` suffix).

Do one final full UI exercise to confirm nothing breaks under enforcement.

## Rollback

If enforcement breaks the UI in production:

1. Set `Csp.ReportOnly` back to `true` in `appsettings.json`
2. Restart the STS
3. Collect the new violations and repeat Step 3-4

## What NOT to do

- **Do not** disable CSP (`Csp.Enabled=false`) to work around violations — fix the policy
- **Do not** add `'unsafe-inline'` to `script-src` — that defeats the XSS containment CSP provides
- **Do not** add wildcard domains (`*`) — list explicit trusted origins
- **Do not** skip exercising the Management UI (`/management/*`) — it has its own Blazor circuit and may need different directives
