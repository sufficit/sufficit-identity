# What happens when the breach service does not answer

Plan: `PLAN-IDENTITY.md` section F11. The operational item — moving a
deployment to the stricter mode — is the only one left.

The check asks HaveIBeenPwned for the range of a password's hash prefix. When
that call fails, the deployment had two answers, both bad: `FailOpen` accepts
whatever was typed, including a password in every breach corpus; `FailClosed`
stops registration and every password change until the service returns.

## The third answer

`LocalFallback` answers from what this deployment knows without asking anyone.
Two sources, and the smaller one is the less interesting:

**The range cache.** A range answer covers every password sharing its
five-character prefix, so a host that has been running already holds the
answer for most prefixes people pick. Those are now answered from memory —
no request, and an outage does not reach them at all. The cache is bounded
(512 entries by default, one hour) and evicts by expiry rather than keeping an
exact LRU, because exact would need a lock on every read and the cost of
evicting a live entry is one more request.

**The local list.** A built-in floor of the passwords at the top of every
corpus, plus an optional deployment list
(`Password:LocalBreachedPasswordListPath`, one per line, `#` comments). A
missing or unreadable file leaves the floor in place and logs — refusing to
start over it would trade a weaker fallback for no service.

What `LocalFallback` cannot do is claim the full answer, so it refuses what it
knows and accepts the rest, and the degraded decision is recorded rather than
passed off as a completed check.

## A 200 that is not a range listing

The old reader looped over the body looking for a matching suffix and, finding
none, returned success. A maintenance page, a proxy error body or an empty
response therefore read as "this password is not breached" — the check silently
passing everything, with a 200 and no warning anywhere.

The body is parsed as what it claims to be: lines of a 35-hex-character suffix
and a count. Anything else is an outage and goes through the failure mode.
That is the case that would have hurt most, because nothing about it looks
wrong from the outside.

## Telemetry

Every decision records `breached_password_check` with the mode and one of
`completed`, `served_from_cache`, `local_fallback_match` or `degraded`, plus
why the upstream failed — `upstream_status`, `upstream_malformed`,
`upstream_unreachable`. That is what the operational item needs to decide
whether a deployment can afford the stricter mode.

## Verification

1,528 tests pass, Release warning-clean. Thirteen new tests: the three modes
against an outage, a fallback miss, the deployment list including its comment
and blank-line handling, an unreadable list, the cache answering after the
service disappears, three malformed bodies, a timeout, recovery once the
service returns, and the cache bound. Blinding the cache and the fallback fails
four of them; restoring the old reader's treatment of an unreadable body fails
the other three.
