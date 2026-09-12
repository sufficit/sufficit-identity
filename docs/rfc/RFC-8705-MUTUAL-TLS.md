# RFC 8705 — Mutual-TLS client authentication and certificate-bound access tokens

| | |
|---|---|
| Role | Authorization Server |
| Coverage | **B — Substantial** |
| Origin | Mixed: native OpenIddict 7.x, plus in-house policy and forwarding |
| Spec | https://www.rfc-editor.org/rfc/rfc8705 |

## Activation

Everything depends on `Sufficit:Identity:Mtls:Enabled`. When it is on
(`src/sts/OpenIddictServerConfiguration.cs:64-131`):

- The **aliases** `/connect/{token,introspect,revocation,deviceauthorization,userinfo,par}/mtls`
  are registered as real endpoints, not just published in metadata —
  registering the alias in the document without mapping the route
  authenticates no one (`:71-88`).
- `EnableSelfSignedTlsClientAuthentication()` enables
  `self_signed_tls_client_auth` (§2.2).
- `EnablePublicKeyInfrastructureTlsClientAuthentication(...)` enables
  `tls_client_auth` (§2.1) when trusted CAs are loaded by
  `MtlsCertificateAuthorityLoader` (`:96-104`).
- `UseClientCertificateBoundAccessTokens()` makes OpenIddict issue and
  validate the `cnf.x5t#S256` (§3), including during introspection
  (`:107-108`).
- The absolute aliases are published in `mtls_endpoint_aliases` from
  `Mtls:EndpointBaseUrl`, allowing the certificate handshake to be isolated
  on a dedicated port without touching the `issuer` (`:110-130`).

## Termination at the proxy

The host does **not** configure Kestrel to require a certificate; this is
deliberate and documented in `Program.cs:440-464` itself. The supported
production path is termination at nginx/Envoy, with the validated
certificate forwarded via header.

`MtlsClientCertificateForwarding` (`src/sts/Mtls/MtlsClientCertificateForwarding.cs`)
runs **before** the trusted-proxies middleware (`Program.cs:471`), because it
needs to see the real IP of the immediate peer. It:

- **strips** the configured header in every mode, so that a client cannot
  inject it;
- only projects the certificate when the peer is within one of the dedicated
  CIDRs in `Mtls:TrustedProxyNetworks`.

Startup validation requires explicit attestation of the deployment mode:
`DeploymentMode=Unattested` is rejected, and so is `TrustedProxy` without a
CIDR (`src/sts/ServiceCollectionExtensions.Validation.cs:75-120`).

## Binding and conflict with DPoP

`RejectCombinedDpopAndMtlsSenderConstraints`
(`src/sts/OpenIddictServerConfiguration.cs:342-346`) rejects a request that
tries to use both proof-of-possession mechanisms at once. Without this, it
would be undefined which `cnf` takes precedence.

`MtlsClientCertificatePolicy` (`src/sts/Mtls/MtlsClientCertificatePolicy.cs`)
checks the thumbprint against the list registered per client (`:124-131`)
and handles revocation with a bounded timeout (1 to 30 s, validated at
startup).

## Requirements

| Requirement | § | Status |
|---|---|---|
| `tls_client_auth` | 2.1 | Yes, with configured CAs |
| `self_signed_tls_client_auth` | 2.2 | Yes |
| `cnf.x5t#S256` in the access token | 3.1 | Yes (OpenIddict) |
| Binding validation at the resource server | 3.2 | Partial: exposed via introspection; the check is the RS's responsibility |
| `mtls_endpoint_aliases` in discovery | 5 | Yes |
| Revocation checking | — | Yes, with a bounded timeout |

## Gaps

- No tested recipe for direct Kestrel; the supported mode assumes a proxy.
- Checking the `cnf` on the resource call depends on each resource server.

## Tests

`MtlsPolicyTests`, `SenderConstraintTests`, `ClientsControllerTests.Credentials.Mtls`,
`DeploymentTopologyTests`.
