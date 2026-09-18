# Management console: one palette, one owner — 2026-09-18

Follow-up to the public UI migration earlier the same day. The console was
already built on SUI (250 icons, 71 badges, 33 buttons, 27 fields), so this was
not a migration: it was removing a second copy of the design decisions and
repairing the gate that was supposed to catch exactly that.

## What was wrong

`IdentitySUITheme` (C#) and `app.css :root` both declared the console's palette,
type and shape. Every value appeared twice — `#cc0000`, `#343132`, `#626064`,
`#858287`, `#e2e1e3`, `#cfced1`, the four status colours, the three radii, Inter,
the shadows. The theme's own doc comment admitted it: "Tokens mirror
`wwwroot/app.css` `:root`". Two copies in two languages, kept in step by hand.

The theme is the one that wins — `SUIThemeProvider` publishes it as `--sui-*`
on `:root` and every SUI component reads it there — so the console's tokens now
derive from it. What the theme has no concept of stays literal: the pressed and
soft brand steps, the tinted status backgrounds, the dark sidebar, the shell's
own measurements.

`.client-edit-form-grid` was repainting SUI fields — border colour, radius,
background, text colour, focus ring — to say one thing: this form's controls are
taller and its text larger than the dense filter rows. It now says that by
moving `--sui-control-h-md` and `--sui-fs-field` on the container, and colour
keeps coming from the theme.

## The gate that was red

`Users_filter_controls_are_styled` had been failing, and the console was not at
fault: `GetUnstyledFormControlsAsync` required a border **and** a non-zero
`min-height`, while `.sui-field__input` sets `height`. Every SUI field on the
page counted as unstyled, plus the hidden inputs `SUIDateField` uses to carry
its value.

Fixing the threshold was not enough — the first attempt accepted `height` as
evidence and then a bare `<input>` passed, because the user agent gives it a
border and a height too. The check now compares each control against a pristine
one of the same kind created in the same document: a field the stylesheet never
touched matches it on border, radius, background and height. A second bug fell
out of the rewrite — `closest('[class]')` starts at the element, so a styled
control was vouching for itself; it walks up from the parent now.

Verified both ways: the gate flags a bare `input` and a bare `select`, ignores
hidden and `display:none` controls, and passes both a styled field and the
pill-search pattern where the wrapper draws the box.

## Verification

The whole console was screenshot at 1440×900 and 390×844, full page, before and
after: **every page pixel identical**, which is the point — the duplicated
palette really was saying the same thing. Two pages differ between any two runs
regardless of code (`/management/audit` grows rows, `/management/database`
reports live sizes).

The client editor could not be reached without a client, so one was inserted
directly in the development database to open it. Its controls measure the same
after the change as before — 44px box, 16px text, `#cfced1` border, 8px radius —
with one deliberate 1px shift on touch widths: the old rule left SUI's
`height: 36px` fighting its own `min-height: 44px`, and the text now centres in
the box it actually occupies.

Two guard tests were added and both were shown to fail against the previous
stylesheet, so they are not vacuous.

- 1407 unit tests pass (1 skipped, unrelated).
- 23 of 23 browser tests pass — the first fully green run of that suite here.

## Noticed, not fixed

The client wizard mixes languages: the profile cards ("Web application / BFF",
"Interactive login processed by a server capable of protecting a credential.")
and the draft validation messages ("Provide a name that identifies the
application.") are English inside a Portuguese console. That is a localization
gap, not a styling one, and it belongs to whoever owns those resources.
