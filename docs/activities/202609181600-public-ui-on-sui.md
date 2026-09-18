# Public UI rebuilt on Sufficit.Blazor.UI — 2026-09-18

The public sign-in and account UI now draws its buttons, fields, alerts,
badges, avatar and icons from `Sufficit.Blazor.UI` instead of from a private
copy in `site.css`. The brief was "as much SUI as possible without losing the
current look", and the look was treated as the acceptance criterion, not as a
hope.

## How it was kept

A disposable stack (MariaDB in Compose + the host on `https://localhost:5001`)
and a Playwright script screenshotting every public page at 1280×900 and
390×844, full page, reduced motion. Baselines were captured from a clean
checkout, then every step was re-shot and compared pixel by pixel with
ImageMagick `compare -metric AE`.

**All fourteen anonymous screenshots — login, register, forgot password, resend
confirmation, access denied, device code, home, in both widths — are byte
identical to the baseline.** The remaining differences, all on authenticated
pages, are listed below and each one is a decision.

## The mechanism

`site.css` maps `--sui-*` to the brand tokens inside `.identity-public`, the
class the public shell puts on its root. Components arrive dressed; nothing is
restyled per component. Scoping matters because the management console composes
the same stylesheet and has its own calibration.

Below the map, a short list of rules for what tokens cannot say: the 48px
control height these screens use on every pointer (SUI drops fields to 44px on
touch, which would have made the field shorter than the button above it), the
heavier button weight and the page's own leading for labels that wrap, the
alert's left rule, the field hint as instruction rather than aside.

Removed as a consequence: the whole `.btn*`, `.alert*` and `.badge*` blocks,
and `wwwroot/js/instant-feedback.js` — the press-feedback script this repo
shipped before the same mechanism was released in SUI 2.26.918.1328.

## Accepted differences

- **The back-arrow** (35 px on every `/manage/*` page) — `SUIIcon`'s
  `arrow-left` has a slightly smaller head than the hand-written path it
  replaced. Imperceptible at 16px; one icon source is worth it.
- **`/manage/deleteaccount`'s warning** — the old `.alert` was a flex container,
  so the bold lead-in became a narrow left column and the sentence continued
  beside it. `SUIAlert` puts its children in one content block, so the lead-in
  now reads as the start of the sentence, which is what the markup always
  meant. This is the one change worth looking at on purpose.
- **Two-line button labels on `/manage/personaldata`** — under 2px of vertical
  drift inside an unchanged box.

## Found on the way, not fixed here

Two gaps in SUI that this migration ran into:

- `SUICheckbox` renders no `value` attribute, so it cannot participate in a
  plain form POST. Every checkbox here submits to an endpoint that parses
  `value="true"`, so all of them stayed native.
- `SUITextField` exposes no focus handle, so the passkey rename editor — which
  must take focus the moment it appears — stayed native.

And one dead rule in this repo: `.btn.is-busy::before { animation-duration:
2.4s }` never applied, because the blanket `prefers-reduced-motion` rule in the
same file carries `!important`. The replacement is explicit about it: under
reduced motion the busy spinners slow down instead of freezing, because a
progress indicator that does not move stops being one.

## Verification

- 1405 unit tests pass (1 skipped, unrelated).
- 22 of 23 browser tests pass; `Users_filter_controls_are_styled` fails on the
  management console and fails identically on a clean checkout — pre-existing.
- Interactive states checked by hand in the browser: the invalid-credentials
  alert, field validation through `SUITextField`, and the busy spinner.
