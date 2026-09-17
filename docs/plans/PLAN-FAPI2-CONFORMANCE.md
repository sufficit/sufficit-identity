# FAPI 2.0 conformance plan — remaining work

The OpenID conformance harness (`conformance/`) already runs the FAPI 2.0
Security Profile plan against a disposable environment:

```bash
conformance/run.sh \
  "fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi]" \
  config/fapi2.template.json
```

The environment it needs is in place: clients authenticate with
`private_key_jwt` against keys the seeder generates and registers, DPoP and the
FAPI 2 profile are on, and the pushed-request lifetime is shortened so the
expiry module fits inside the runner's budget.

**Status of the last run: 56 modules, 20 passed, 33 failed, 1 review, 2
skipped.** Only the OpenID Connect Basic plan is a nightly gate
(`.github/workflows/conformance.yml`); FAPI 2 is not, until the list below is
worked through.

## What the failures are

### 1. `id_token` signed with RS256 (~25 modules)

`FAPI2ValidateIdTokenSigningAlg` requires PS256 or ES256. The conformance
environment runs as Development, where signing uses
`AddDevelopmentSigningCertificate()` — an RSA certificate, so every `id_token`
is RS256. This single cause accounts for most of the failures.

Configuring `Certificates:SigningPath` with an EC certificate does not work yet:

- Development plus configured certificates is refused by
  `DeploymentTopologyPolicy.ValidateDevelopmentHost`. There is an explicit
  escape (`AllowDevelopmentOnPublicHost=true`), so that part is only a decision.
- With an EC PFX loaded, OpenIddict fails at startup with "a signature algorithm
  cannot be automatically inferred from the signing key". That needs
  investigation — most likely how the PKCS#12 is produced or loaded (private key
  presence, `X509KeyStorageFlags`), not the profile itself.

Options, in the order worth trying: produce the EC PFX differently and confirm
`X509Certificate2.GetECDsaPrivateKey()` is non-null inside the container; or let
the product choose the development signing key type, which is a product change
and needs a reason beyond conformance.

### 2. TLS ciphers of the test front (2 modules)

`RequireOnlyBCP195RecommendedCiphersForTLS12` inspects the TLS of the issuer
host. `conformance/proxy/nginx.conf` serves a self-signed certificate with the
image's default cipher list. Restricting it to the BCP 195 set is a change in
the harness, not in the server.

### 3. Discovery (1 module, partly fixed)

`token_endpoint_auth_signing_alg_values_supported` is now published (RFC 8414;
`DiscoveryTests.Discovery_document_names_the_client_assertion_algorithms`).
`CheckForUnexpectedParametersInServerMetadata` still warns — the document
carries properties the suite does not know; the list has to be read from the
module log and each one justified or removed.

### 4. User rejection (1 module)

`user-rejects-authentication` needs the user to deny consent. The conformance
clients are seeded with implicit consent, so no consent page is shown. It needs
a client with explicit consent and browser automation that clicks the denial.

### 5. Client assertion with the wrong audience (1 module)

`CheckErrorFromTokenEndpointResponseErrorInvalidClientOrInvalidRequest`: the
server refuses the request, but with an error the module does not accept. The
response has to be read and mapped to `invalid_client` or `invalid_request`.

### 6. Refresh tokens (1 module)

`FAPIEnsureServerConfigurationDoesNotSupportRefreshToken` — the profile expects
either a refresh token that follows its rules or a server that does not announce
the grant. The conformance clients are seeded with `refresh_token`; decide
whether the FAPI profile forbids it for profiled clients.

## What the plan already proved

Four defects the repository's own tests did not cover were found and fixed while
getting this far:

- `private_key_jwt` assertions with the standard `typ: JWT` were refused
  (`ClientAuthentication/StandardClientAssertionType.cs`).
- A DPoP proof sent with a pushed authorization request did not bind the code
  (`Dpop/DpopPushedAuthorizationBinding.cs`), and the profile demanded a
  `dpop_jkt` parameter RFC 9449 makes optional.
- DPoP proofs without `exp` were refused, though RFC 9449 4.2 does not require
  it.
- A DPoP proof whose `jwk` header carried the private key was accepted.
