# Password reset error page in production

On 23 November 2026 at 12:26 São Paulo time, eveo-apps, apoint-apps and
castrum-apps finished the rolling activation of release `20261123-f852e831`.
The shared cluster lease serialized activation and each node inherited its
four existing configuration files. The rollout required no schema migration.

| Release property | Verified value |
| --- | --- |
| Identity revision | `f852e8314e0e4c8b85c7e1eaf69d1ffb2376ce49` |
| SUI source revision | `1d09b4a62a0694a6094a42bcdf78cc508c61a5f4` |
| Package SHA-256 | `f630b2cc7a2131db27f0c3ec7c065be607aa2dc490caceb96a47d7da37091d0c` |
| Previous release on all nodes | `20261109-8cbf3c66` |

Build, browser and CodeQL jobs passed on the released source. The CI secret
scan flagged a Visual Studio project GUID on a historical squash commit.
After inspection, c72578f9 recorded its exact fingerprint. Gitleaks 8.30.1
passed locally and the GitHub secret scan passed on that follow-up.
[Source CI](https://github.com/sufficit/sufficit-identity/actions/runs/45198567836)
and [follow-up CI](https://github.com/sufficit/sufficit-identity/actions/runs/45205100906).

The cluster verifier confirmed the exact release revision, active services,
healthy liveness and readiness, and the baseline certificate and JWKS digests
on every node. Direct-node probes briefly returned HTTP 502 during restarts
and recovered before the next activation.

Public HTTPS checks verified health, readiness, the discovery issuer and
the existing invalid-link guidance on GET. An empty form submission produced
HTTP 400 with the branded recovery action in Portuguese and English. A request
preferring JSON retained the original empty 400. Chrome also displayed the
Portuguese heading, loaded the error stylesheet and opened the recovery page
when the link was clicked. These requests used no customer account or token,
and sent no recovery email. The cause of the original customer's rejected
request remains undetermined.

[Source correction](202611231150-password-reset-http-400.md) and
[cluster deployment procedure](../runbooks/RUNBOOK-CLUSTER-ROLLING-DEPLOY.md).
