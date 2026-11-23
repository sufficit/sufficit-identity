# Password reset HTTP 400 recovery

The production Identity access log for 23 November 2026 shows HTTP 200 when
the reset link opened at 11:26:40 and HTTP 400 with zero response bytes when
a form submission completed at 11:27:01 (UTC−03:00). The Identity journal
confirmed that a different submission completed the reset at 11:27:02.
The rejection reason for the production request remains unknown.

The embedded public UI now renders the existing standalone error layout when
a browser navigation to the password reset page results in an empty HTTP 400.
The status and form validation are preserved. The page offers a new reset link
and advises people who already set a password to try signing in with it.
It uses a fixed recovery destination and keeps account data and submitted
fields out of the response. The response sets no-store and no-referrer headers.

A regression test reproduced the 400 from the Blazor form without antiforgery
data under production settings. The updated test verifies both supported
languages, the recovery action and the response to a client requesting JSON.
An invalid reset link still renders the existing recovery action.

Verification covered 67 focused tests, 2,170 tests in the local suite excluding
live browser and Markdown tests, the Release solution build with warnings
treated as errors, and the production container build with locked restore.
Pomelo artifact hashes, migration SQL coverage, the lock propagation tests
the local dependency audit and eight Markdown coverage tests also passed.
Source delivery targets main. Production rollout was outside this change.
