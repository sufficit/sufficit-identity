# Sufficit Identity design system

> Visual system of record. Every component, page, and variant must stay on-brand
> with what is defined here. Where this file and a page disagree, this file wins.
>
> Built for: a Blazor Server static-SSR identity provider surface (login,
> consent, device, register, manage). Companion to
> [`DESIGN-PRODUCT.md`](DESIGN-PRODUCT.md).

## Source of truth

This palette is **extracted from the real Sufficit brand assets** — not invented:

| Token            | Value      | Provenance                                            |
|------------------|------------|-------------------------------------------------------|
| Brand red        | `#cc0000`  | `Papelaria/Logo.png` — dominant non-white pixel mass  |
| Brand charcoal   | `#343132`  | `Papelaria/Logo.png` — logotype text color            |
| Mid gray         | `#58595b`  | `Papelaria/Logo.png` — secondary tone                 |
| Site footer gray | `#4f4f4f`  | `www.sufficit.com.br` — `#footer` background          |

The legacy site (`www.sufficit.com.br`) confirms the discipline: red is used
sparingly as an accent on a white/light-gray field, with charcoal carrying all body
text. That restraint is the design language we extend here.

## Design rationale (the "why")

**Profissional. Seguro. Direto.** The visual system encodes those three words:

- **Profissional** → disciplined 4px-grid spacing, single-weight borders, no
  decorative shadows, one typeface with a tight size ramp. Nothing screams
  "template."
- **Seguro** → sufficit red is reserved for *action* and *brand* only. Surfaces are
  calm white/gray. Critical actions earn the red; everything else is charcoal on
  paper. A page that is mostly red reads as *alarm* — so we keep red scarce.
- **Direto** → no marketing chrome on auth surfaces. The login card has one job.
  Generous whitespace, single column, primary action pinned to the bottom of the
  form. Touch targets are 44px minimum. Speed is a feature, so the CSS ships as one
  small file.

References (feel, not layout): **Auth0 Universal Login** (centered card, passkey
first-class, brandable but disciplined), **Zitadel** (brand presence without
screaming), **Authentik** (dense admin that still looks modern).

---

## 1. Color

### Tokens (CSS custom properties)

Defined on `:root`. All derived colors use OKLCH for perceptual uniformity; the
brand reds stay as exact hex to match the logo.

```css
:root {
  /* === Brand (exact, from logo) === */
  --brand:            #cc0000;   /* primary action, brand mark, critical alert     */
  --brand-hover:      #a30000;   /* :hover / :active on brand                      */
  --brand-press:      #7a0000;   /* :active depth                                  */
  --brand-soft:       #fbe9e9;   /* tint background for brand accents (10% red)    */
  --brand-ring:       rgba(204, 0, 0, 0.28); /* focus ring around brand controls */

  /* === Ink (text) — charcoal family from the logo === */
  --ink:              #343132;   /* body text, headings                            */
  --ink-strong:       #1f1d1e;   /* near-black for max emphasis                    */
  --ink-muted:        #58595b;   /* secondary text, captions                       */
  --ink-subtle:       #8a8b8d;   /* placeholders, disabled labels                  */

  /* === Surfaces === */
  --surface:          #ffffff;   /* cards, inputs, topbar                          */
  --surface-page:     #f6f6f7;   /* page background (cooler than pure gray)        */
  --surface-sunken:   #efeeef;   /* inset areas: code blocks, qr bg, profile card  */
  --surface-overlay:  rgba(34, 32, 33, 0.55); /* modal/redirect scrim             */

  /* === Lines === */
  --line:             #e2e1e3;   /* default 1px borders, dividers                  */
  --line-strong:      #cfced1;   /* input borders on focus-adjacent, table heads   */

  /* === Status (paired with icon + text, never color alone) === */
  --danger:           #b42318;   /* errors, destructive primary — AA on white      */
  --danger-soft:      #fef3f2;
  --success:          #157f3f;   /* confirmation — AA on white                     */
  --success-soft:     #effaf2;
  --warning:          #b54708;   /* caution — AA on white                          */
  --warning-soft:     #fff8eb;
  --info:             #175cd3;   /* informational — AA on white                    */
  --info-soft:        #eff4ff;

  /* === Radii === */
  --radius-sm:        6px;
  --radius:           8px;
  --radius-lg:        12px;
  --radius-pill:      9999px;

  /* === Shadow (single, restrained) === */
  --shadow-card:      0 1px 2px rgba(34,32,33,.06), 0 1px 3px rgba(34,32,33,.04);
  --shadow-pop:       0 8px 24px rgba(34,32,33,.12), 0 2px 6px rgba(34,32,33,.06);

  /* === Motion === */
  --ease:             cubic-bezier(.2,.0,.0,1);
  --dur-fast:         120ms;
  --dur:              180ms;
}
```

### Usage rules

- **Brand red is a budget, not a theme.** Per surface, red appears in at most:
  the logo mark, one primary button, and (optionally) one critical alert. Anything
  more dilutes the signal.
- **Body text is always `--ink` on `--surface` / `--surface-page`.** Never red.
  Red on white fails AA at body sizes.
- **Status colors always carry an icon and a text label.** A red border alone is
  not an error state.
- **Dark mode is out of scope for v1.** Auth surfaces benefit from the calm of a
  light field; a half-baked dark mode erodes trust faster than no dark mode. The
  tokens are structured so a future `[data-theme="dark"]` override is mechanical.

---

## 2. Typography

One family. Tight ramp. No display fonts on auth surfaces.

```css
:root {
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Code",
               "Courier New", monospace;
}
```

**Why Inter:** open-source, optimized for screens at small sizes, has the
professional-but-neutral character the references share. Falls back to system fonts
gracefully (no FOUT on slow connections — the system stack renders instantly and
Inter refines in). **Do not** load Proxima Nova (legacy site font) — it is a
licensed web font and adds a render-blocking request on a page where speed is
trust.

| Token            | Size  | Weight | Line  | Use                                  |
|------------------|-------|--------|-------|--------------------------------------|
| `--text-display` | 28px  | 600    | 1.2   | Home hero only                       |
| `--text-h1`      | 22px  | 600    | 1.25  | Auth card title ("Entrar")           |
| `--text-h2`      | 18px  | 600    | 1.3   | Manage section headings              |
| `--text-h3`      | 16px  | 600    | 1.4   | Card sub-sections, fieldset legends  |
| `--text-body`    | 16px  | 400    | 1.5   | Default body, form labels            |
| `--text-small`   | 14px  | 400    | 1.45  | Secondary text, helper, nav links    |
| `--text-caption` | 13px  | 500    | 1.4   | Badges, meta, timestamps             |
| `--text-mono`    | 14px  | 500    | 1.4   | Device codes, recovery codes, keys   |

- **Base size 16px** — never smaller on inputs (prevents iOS zoom-on-focus).
- **Weight 600** for headings (not 700) — the reference surfaces are confident, not
  shouty.
- **Letter-spacing:** default. The legacy site's `small-caps` / `Sketch3D`
  experiments are marketing-site only; never on auth surfaces.

---

## 3. Spacing & layout

### Spacing scale (4px base)

`4 · 8 · 12 · 16 · 20 · 24 · 32 · 40 · 56 · 80`

Exposed as `--space-1` through `--space-10`. No off-grid values.

### Auth card geometry

The centered `.auth-card` is the atomic unit of this UI:

- `max-width: 420px` on desktop, full-bleed minus padding on mobile.
- `padding: 32px` desktop / `24px` mobile.
- One card per page. The card is the whole content area — no sidebars on auth
  surfaces.
- Card sits in a vertically-centered flex column with `min-height: 100vh`, so
  short forms (login) and long forms (manage) both feel grounded.

### Manage layout

The `/manage/*` surface breaks the single-card rule — it is a product surface, not
an auth surface:

- Left rail (200px): nav links.
- Main column (`max-width: 640px`): forms, lists, tables.
- Collapses to a single stacked column under 768px; nav becomes a horizontal
  scroller of pill links at the top.

### Container widths

| Surface        | Max width | Notes                                  |
|----------------|-----------|----------------------------------------|
| Auth card      | 420px     | login, register, consent, forgot, 2FA  |
| Manage main    | 640px     | forms, lists                           |
| Manage wide    | 960px     | grants table, sessions list            |
| Page padding   | 16px mobile, 24px desktop                                  |

---

## 4. Components

### 4.1 Buttons

Three variants. Red is the default *only* for the single primary action on an auth
surface.

```
.btn              base: 44px tall, --radius, weight 500, --dur transition
.btn-primary      bg --brand, color #fff, hover --brand-hover
.btn-secondary    bg --surface, border --line, color --ink, hover bg --surface-sunken
.btn-danger       bg --danger, color #fff  (delete account, revoke session)
.btn-ghost        bg transparent, color --ink-muted, hover bg --surface-sunken
.btn-block        width: 100%
.btn-sm           32px tall, --text-small
.btn-external     full-width secondary w/ provider icon (Google/Facebook)
.btn-passkey      full-width, secondary styling, 🔑 glyph + "Entrar com passkey"
```

- Focus ring `3px var(--brand-ring)` on every variant.
- `:disabled` → `opacity: .55; cursor: not-allowed` — never just gray-out without
  explanation (pair with a helper text or `aria-disabled`).
- `prefers-reduced-motion: reduce` → drop the transition.

### 4.2 Form controls

```
.form-control     44px tall, --radius, 1px --line border, 16px font (no iOS zoom)
                  :focus → border --brand, box-shadow 0 0 0 3px --brand-ring
                  :invalid (server-validated) → border --danger + .validation-message
.form-group       margin-bottom --space-4
label             --text-small weight 500, --ink, margin-bottom --space-1
.validation-message  --danger, --text-caption, margin-top --space-1
.form-check       checkbox + label inline, gap --space-2
```

- Inputs use `autocomplete` attributes (already present) — keep them; password
  managers are a security feature.
- `autofocus` on the first field of every auth form (already present on login).
- Never `placeholder`-as-label. Every input has a visible `<label>`.

### 4.3 Alert

Inline, full-width, icon + text. Four kinds map to the status tokens.

```
.alert            --radius, padding 12px 16px, --text-small, icon + text
.alert-error      bg --danger-soft, color --danger, border-left 3px --danger
.alert-success    bg --success-soft, color --success, border-left 3px --success
.alert-warning    bg --warning-soft, color --warning, border-left 3px --warning
.alert-info       bg --info-soft, color --info, border-left 3px --info
```

- Always `role="alert"` for error/success; `role="status"` for info.
- Border-left (not full border) — signals "a stripe of attention" without boxing
  the message in red.

### 4.4 Badge

```
.badge            --radius-pill, --text-caption, padding 2px 10px
.badge-neutral    bg --surface-sunken, color --ink-muted
.badge-success    bg --success-soft, color --success
.badge-warning    bg --warning-soft, color --warning
.badge-brand      bg --brand-soft, color --brand
```

### 4.5 Auth card

```
.auth-card        bg --surface, --radius-lg, --shadow-card, padding 32px (24px mobile)
                  max-width 420px, margin auto
.auth-card h1     --text-h1, margin-bottom --space-4
.auth-links       margin-top --space-5, text-center, --text-small, --ink-muted
```

### 4.6 Scope list (consent)

The consent screen is the highest-stakes surface for trust. Scopes must read as a
*plain-language bill of materials*, not a checklist of jargon.

```
.scope-list fieldset   border none, padding 0
.scope-item            flex, gap 12px, padding 12px, --radius, 1px --line border
                       hover → bg --surface-sunken
.scope-name            --text-body weight 500, --ink
.scope-desc            --text-small, --ink-muted
```

- Checkboxes **default to checked** (already implemented) — opt-out consent, not
  opt-in dark pattern.
- The "Autorizar" button is `btn-primary`; "Negar" is `btn-secondary` with **equal
  visual weight**. Never make Deny a ghost link.

### 4.7 External login separator

```
.separator         flex w/ two 1px --line rules and a centered label chip
                   bg --surface on the chip to mask the rule
```

### 4.8 Spinner / redirect overlay

```
.spinner           32px, 3px --line ring, border-top --brand, 0.8s linear
.redirect-overlay  fixed inset 0, bg rgba(246,246,247,.94), z-index 1000
```

- Already implemented in `App.razor` + `identity.js`. Keep the JS-driven approach
  (no Blazor interactivity needed for a pre-navigation scrim).
- Spinner honors `prefers-reduced-motion`: replace rotation with a static "•••".

### 4.9 Manage: profile card, nav, lists

```
.profile-card      flex, gap 16px, padding 16px, bg --surface-sunken, --radius
.profile-avatar    56px circle, bg --brand, color #fff, --text-h1 weight 600
                   (user initials)
.manage-link       block, padding 12px 16px, 1px --line border, --radius
                   hover → bg --surface-sunken; active → border-left 3px --brand
.passkey-list li   flex justify-between, padding 8px 0, border-bottom --line
.grant-item        flex justify-between, padding 12px, 1px --line border, --radius
```

### 4.10 Device code

```
.device-code       --font-mono, 32px, letter-spacing .2em, text-center, uppercase
.device-info       --text-small, --ink-muted, max-width 480px, text-center
```

---

## 5. Iconography

- **No icon font, no icon library** on auth surfaces. Each icon is an inline SVG
  sprite — keeps the payload tiny and avoids a render-blocking request.
- Stroke-based, 1.5px stroke, 20px box, `currentColor`.
- Required set: `alert`, `check`, `check-circle`, `x`, `key` (passkey), `mail`,
  `lock`, `shield`, `external-link`, `google`, `facebook`, `spinner`.
- Status alerts always pair text with one of `alert` / `check-circle` / `info`.

---

## 6. Motion

- Default transition `--dur` (180ms) with `--ease`.
- **No entrance animations** on auth surfaces. The card does not fade-in; the form
  does not slide. Speed is trust.
- **No auto-advancing carousels, no parallax, no count-up.** Ever.
- `prefers-reduced-motion: reduce` → all transitions to `0.01ms`, spinner becomes
  static dots.
- The only motion that ships: button hover/press, input focus ring, dropdown
  reveal.

---

## 7. Topbar & footer

```
.topbar            bg --surface, border-bottom 1px --line, padding 12px 24px
                   sticky top 0, z-index 100
.topbar-brand      logo mark (red square w/ "S" or full Logo.png) + "Identity" wordmark
                   color --ink, weight 600
.topbar-nav        gap 16px, --text-small
.nav-link          color --ink-muted; hover --ink; [aria-current] → color --brand
.footer            text-center, padding 16px, --text-caption, --ink-subtle
                   border-top 1px --line
```

- The wordmark should pair the Sufficit logo mark with the literal text
  "Identity" — so the brand is present without the full "Sufficit Identity"
  repetition that crowds a 420px card on mobile.

---

## 8. Responsive

Two breakpoints, mobile-first:

| Breakpoint | Width   | Behavior                                            |
|------------|---------|-----------------------------------------------------|
| base       | < 768px | Single column, card full-bleed minus 16px padding   |
| `md`       | ≥ 768px | Card centered, manage nav becomes left rail         |
| `lg`       | ≥ 1024px| Manage wide tables get full 960px                   |

- Under 640px: card loses shadow + border-radius (full-bleed feel), button groups
  stack vertically, topbar padding tightens.
- Touch targets never below 44×44px at any width.

---

## 9. Accessibility checklist (floor, not feature)

- [ ] All interactive elements keyboard-operable; visible focus ring on every one.
- [ ] Color contrast ≥ 4.5:1 for body text, ≥ 3:1 for UI components & large text.
- [ ] `prefers-reduced-motion` honored globally.
- [ ] `prefers-color-scheme: dark` → not supported v1 (document, don't break).
- [ ] Every form input has a programmatic `<label>` (no placeholder-only labels).
- [ ] Error messages `role="alert"` and `aria-describedby` linked to the field.
- [ ] Consent checkboxes: `aria-required` where the STS mandates the scope.
- [ ] Passkey button announces busy state via `aria-busy`.
- [ ] Page `<title>` is unique per route (already via `<PageTitle>`).
- [ ] `<html lang="pt-BR">` (already set in App.razor).

---

## 10. What is explicitly NOT in this system

To prevent drift, these are deliberate exclusions:

- **No dark mode** in v1. Tokens are structured for a future override, but a
  half-built dark mode erodes trust.
- **No Tailwind / Bootstrap / component library.** The existing hand-rolled CSS is
  ~340 lines and ships in one request. Adding a framework would 10× the payload on
  a surface where speed is trust. We extend the existing CSS file, not replace it
  with a framework.
- **No animation library** (Framer, GSAP, Lottie). Not needed; motion is rare and
  CSS-only.
- **No custom illustrations or mascots.** Security surfaces with cartoon characters
  read as less serious.
- **No Proxima Nova / Sketch3D** (legacy marketing fonts). Licensed, heavy, and
  wrong register for an auth surface.

---

## Implementation status

The public `site.css` and Management `app.css` use the Sufficit red/charcoal
tokens, visible focus styles and reduced-motion handling described here. This
document remains the design contract; the accessibility checklist above still
requires a recorded WCAG 2.2 AA audit before it can be marked complete.
