# The secret scan was reporting the secret store

Follow-on to [`202609192100`](202609192100-secret-boundary-provenance.md), found
in the production journal rather than in a test.

`configuration-unmapped-secret` shipped on 2026-09-19 and fired on all three
nodes at the next restart, listing ten names:
`SUFFICIT_SECRET_DATABASE_CONNECTION_STRING`,
`SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD`, and so on.

Those are the secret store. Environment variables are a configuration source,
so the `SUFFICIT_SECRET_*` names appear in configuration like everything else,
and the scan read them as credentials sitting somewhere they should not be. It
told every correctly-configured deployment the opposite of the truth — the
exact failure the activity introducing it warned about, three paragraphs about
not building a scanner operators learn to skim.

They are excluded now, by the prefix the store itself defines.

## A second thing the same log showed

`SOME_OTHER_API_KEY` — a secret in an environment variable that is *not* part
of the store — was not reported either, and should be. The matcher lowercased
the leaf but kept its separators, so `API_KEY` never matched `apikey` and the
whole environment-variable spelling was invisible to it. Separators are
stripped before matching now, which is also why `ApiKeyName` and `API_KEY_NAME`
are both still excluded as settings.

## Verification

1,539 tests pass, Release warning-clean. The new test uses the real shapes from
production: the ten store variables, the `Sufficit__Identity__*` operational
settings beside them, and one environment variable that is a genuine unmapped
secret.
