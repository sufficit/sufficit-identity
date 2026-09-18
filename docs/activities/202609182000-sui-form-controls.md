# Form controls moved into SUI — 2026-09-18

Three gaps the public UI migration ran into earlier today were fixed in
`Sufficit.Blazor.UI` rather than worked around here, and the public UI now uses
the result. Published as **2.26.918.1935**.

## What was wrong in the library

`SUICheckbox` and `SUIChoiceCard` both accept `Name` — an attribute that exists
for one reason, taking part in an HTML form — and rendered no `value`, so the
only thing either could submit was the literal `on`. `SUIDateField` already
carried a hidden field with a real value, so the contract existed; two
components were not keeping it.

- `SUIChoiceCard` needed no new API: it already declares the option it
  represents as `Value` and simply was not telling the form. Rendered
  invariantly, because the token is read by a server. **This changes what an
  existing radio group submits.**
- `SUICheckbox` needed a name that was still free — `Value` there is the
  checked state, a boolean — so the submitted token is `FormValue`. Unset, the
  component renders no value attribute and nothing changes.
- `SUITextField` now exposes `FocusAsync`, mirroring `SUIButton`. It already
  focused its own input internally; the textarea had no reference at all, so
  focusing a multiline field would have thrown.

A fourth problem surfaced while wiring it up, and it was the one that mattered
most: `SUICheckbox` drew its tick from the bound value, so the box only filled
after a re-render. Under static server rendering that never comes — the input
toggles, the browser knows, and the box stays empty however many times it is
clicked. Two of the three checkboxes here live exactly there. The tick is now
in the markup and revealed by `:checked`, which also removes a round trip on
interactive pages.

## What changed here

- `/account/login` — "keep me signed in" is a `SUICheckbox`. Verified in the
  browser: the payload is `RememberMe=true`, which is what
  `PasswordLoginController` parses.
- `/account/loginwith2fa` — "remember this device", the statically rendered one.
- `/manage/passkeys` — the rename editor is a `SUITextField` and takes focus
  through the new handle instead of a native input.
- The consent scope list stays native: each row is a three-column grid, not a
  labelled checkbox.
- `site.css` loses `.form-control`, `.form-check` and `.field-hint`. What
  remains of the stylesheet dresses SUI; it no longer carries a control library
  of its own.

## Verification

Public pages re-shot against the same baseline used this morning: everything
identical except 140 pixels on the login family — the checkbox glyph itself,
18px and brand-filled as before, drawn by SUI now. Authenticated pages are
unchanged from their already-recorded deltas.

The rename editor could not be verified visually: it only appears while
renaming a passkey, and headless Chromium reports no platform authenticator, so
no passkey can be registered to rename. Its markup and focus wiring are covered
by tests instead.

Three contract tests were added here, and the library carries its own: 1410
unit tests and 23 of 23 browser tests pass.

## Cost noticed on the way

The WebKit browser job failed the first tagged build with a
`NullReferenceException` — the same flake that cost the previous release a
rerun. It was a real defect in the test: two boxes measured, one awaited, and a
null-forgiving operator turning `BoundingBoxAsync`'s null into a crash. Fixed
in the library.
