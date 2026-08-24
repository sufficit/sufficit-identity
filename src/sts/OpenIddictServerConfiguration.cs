using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Configures the OpenIddict server: endpoints, grants, PKCE, token
    /// formats and lifetimes, signing and encryption material, and every
    /// opt-in protocol extension this STS implements (DPoP, FAPI 2.0, PAR,
    /// JAR, JARM, mTLS, token exchange).
    /// </summary>
    /// <remarks>
    /// This was ~580 lines inline inside <c>AddSufficitIdentitySTS</c>, a
    /// single method of roughly 1,400. Moving it changes nothing about
    /// registration: the lambda still runs at the same point in the same
    /// order, and only the text moved — but the protocol configuration is now
    /// findable, and the values it needs arrive as PARAMETERS rather than as
    /// closure captures, so what this block actually depends on is visible in
    /// the signature instead of having to be traced through the enclosing
    /// method.
    /// </remarks>
    private static void ConfigureOpenIddictServer(
        OpenIddictServerBuilder server,
        SufficitIdentityOptions options,
        VaultOptions vaultOptions,
        CertificateMaterial certificateMaterial,
        SigningCredentials auxiliarySigningCredentials,
        IConfiguration configuration,
        bool isDevelopmentEnvironment)
    {
        // -------------------------------------------------------------------
        // Endpoints (paths aligned with the legacy Duende deployment).
        // -------------------------------------------------------------------
        server.SetAuthorizationEndpointUris("connect/authorize")
              .SetEndSessionEndpointUris("connect/endsession")
              .SetTokenEndpointUris("connect/token")
              .SetUserInfoEndpointUris("connect/userinfo")
              .SetIntrospectionEndpointUris("connect/introspect")
              .SetRevocationEndpointUris("connect/revocation")
              .SetDeviceAuthorizationEndpointUris("connect/deviceauthorization")
              .SetEndUserVerificationEndpointUris("connect/device")
              .SetJsonWebKeySetEndpointUris(".well-known/openid-configuration/jwks")
              .SetPushedAuthorizationEndpointUris("connect/par");

        // -------------------------------------------------------------------
        // Mutual TLS (mTLS) endpoint aliases (RFC 8705, item 3.4).
        // Opt-in via Sufficit:Identity:Mtls:Enabled — mTLS requires the
        // HOST to request/validate client certificates at the TLS layer,
        // so the aliased paths must be registered as real protocol
        // endpoints in addition to being published in discovery.
        // private_key_jwt
        // (RFC 7523) is enabled by OpenIddict unconditionally and is
        // NOT gated here — it is the OTHER strong client-auth method.
        // -------------------------------------------------------------------
        if (options.Mtls.Enabled)
        {
            // Alias metadata alone does not map an ASP.NET endpoint.
            // Keep the original endpoints for compatible clients and
            // explicitly add the RFC 8705 aliases to OpenIddict's
            // endpoint matcher.
            server.SetTokenEndpointUris(
                      "connect/token",
                      "connect/token/mtls")
                  .SetIntrospectionEndpointUris(
                      "connect/introspect",
                      "connect/introspect/mtls")
                  .SetRevocationEndpointUris(
                      "connect/revocation",
                      "connect/revocation/mtls")
                  .SetDeviceAuthorizationEndpointUris(
                      "connect/deviceauthorization",
                      "connect/deviceauthorization/mtls")
                  .SetUserInfoEndpointUris(
                      "connect/userinfo",
                      "connect/userinfo/mtls")
                  .SetPushedAuthorizationEndpointUris(
                      "connect/par",
                      "connect/par/mtls");

            // OpenIddict 7.6 implements both RFC 8705 client
            // authentication methods itself. Enabling the native
            // validators is essential: aliases and a cnf claim alone
            // do not authenticate a confidential client.
            server.EnableSelfSignedTlsClientAuthentication();
            var certificateAuthorities =
                Mtls.MtlsCertificateAuthorityLoader.Load(
                    options.Mtls.TrustedCertificateAuthorityPaths);
            if (certificateAuthorities.Count > 0)
            {
                server.EnablePublicKeyInfrastructureTlsClientAuthentication(
                    certificateAuthorities,
                    policy => Mtls.MtlsCertificateAuthorityLoader
                        .ConfigurePolicy(policy, options.Mtls));
            }

            // Let OpenIddict create and enforce RFC 8705 cnf claims
            // for access tokens and introspection responses.
            server.UseClientCertificateBoundAccessTokens();

            // MTLS alias setters require ABSOLUTE URI strings (unlike
            // SetTokenEndpointUris, which accepts relative paths and
            // resolves them against the issuer). Build absolute URIs
            // from the dedicated public mTLS base when configured;
            // otherwise fall back to the issuer. This lets a proxy
            // isolate certificate handshakes on a dedicated port
            // without changing the ordinary issuer or clients.
            var mtlsIssuer = string.IsNullOrWhiteSpace(options.Issuer)
                ? "https://localhost/"
                : options.Issuer;
            var mtlsBase = string.IsNullOrWhiteSpace(
                options.Mtls.EndpointBaseUrl)
                ? new Uri(mtlsIssuer, UriKind.Absolute)
                : new Uri(options.Mtls.EndpointBaseUrl, UriKind.Absolute);

            server.SetMtlsTokenEndpointAliasUri(new Uri(mtlsBase, "connect/token/mtls").AbsoluteUri)
                  .SetMtlsIntrospectionEndpointAliasUri(new Uri(mtlsBase, "connect/introspect/mtls").AbsoluteUri)
                  .SetMtlsRevocationEndpointAliasUri(new Uri(mtlsBase, "connect/revocation/mtls").AbsoluteUri)
                  .SetMtlsDeviceAuthorizationEndpointAliasUri(new Uri(mtlsBase, "connect/deviceauthorization/mtls").AbsoluteUri)
                  .SetMtlsUserInfoEndpointAliasUri(new Uri(mtlsBase, "connect/userinfo/mtls").AbsoluteUri)
                  .SetMtlsPushedAuthorizationEndpointAliasUri(new Uri(mtlsBase, "connect/par/mtls").AbsoluteUri);
        }

        // -------------------------------------------------------------------
        // Issuer (#8). Without this, OpenIddict derives `issuer` /
        // the token `iss` claim from the incoming request's
        // scheme+host on every call — which silently tracks
        // whatever Host header arrived, including a spoofed one if
        // AllowedHosts/TrustedProxies (Program.cs, appsettings) are
        // ever misconfigured, and diverges between direct-to-app
        // and behind-the-proxy requests. Pinning it here makes the
        // issuer a fixed, deliberate value everywhere. Only applied
        // when Sufficit:Identity:Issuer is actually configured; an
        // empty value preserves the previous request-derived
        // behavior (relied on by the test host, which serves plain
        // HTTP on an arbitrary TestServer address — though the test
        // configuration does also set an explicit Issuer, see
        // SufficitIdentityTestFactory).
        // -------------------------------------------------------------------
        if (!string.IsNullOrWhiteSpace(options.Issuer))
        {
            server.SetIssuer(new Uri(options.Issuer, UriKind.Absolute));
        }

        // -------------------------------------------------------------------
        // Scopes advertised in discovery.
        // -------------------------------------------------------------------
        // Application-specific scopes are opt-in configuration. The
        // STS deliberately does not know domain names; a composing
        // application can map any persisted claim to any scope through
        // ClaimScopeMap.
        var configuredClaimScopes = options.ClaimScopeMap.ClaimToScope
            .Where(pair => !string.IsNullOrWhiteSpace(pair.Key)
                && !string.IsNullOrWhiteSpace(pair.Value))
            .ToArray();
        var applicationScopes = configuredClaimScopes
            .Select(pair => pair.Value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var applicationClaims = configuredClaimScopes
            .Select(pair => pair.Key.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        server.RegisterScopes([
            Scopes.OpenId,
            Scopes.Email,
            Scopes.Profile,
            Scopes.Roles,
            Scopes.OfflineAccess,
            Scopes.Address,
            "identity.management",
            "personal_tokens.manage",
            "sufficit_ai_openai_bridge",
            // Gates the MCP agent surface. The name comes from
            // Sufficit:Identity:Mcp:RequiredScope so it stays in step with
            // McpScopeProvisioner, which creates the scope and grants it to
            // the trusted first-party clients at startup.
            options.Mcp.RequiredScope,
            .. applicationScopes]);

        // MCP / agent-AI resource servers (RFC 8707, item 4.2). Every
        // resource accepted by this host must be explicitly configured
        // and registered as an audience. OpenIddict's normal resource
        // validation remains enabled, so the per-client oi_rprm
        // permission and the host allow-list both have to authorize a
        // requested resource. This prevents an unrelated client from
        // turning an arbitrary URI into an access-token audience.
        if (options.Mcp.Resources.Count > 0)
        {
            server.RegisterAudiences(options.Mcp.Resources.ToArray());
            server.RegisterResources(options.Mcp.Resources.ToArray());
        }

        // -------------------------------------------------------------------
        // Claims advertised in discovery (matches what the
        // AuthorizationController actually emits in tokens).
        // -------------------------------------------------------------------
        server.RegisterClaims([
            Claims.Subject,
            Claims.Name,
            Claims.Email,
            Claims.EmailVerified,
            Claims.Role,
            Claims.PreferredUsername,
            .. applicationClaims]);

        // -------------------------------------------------------------------
        // Grant types in use by Sufficit clients.
        // Implicit/hybrid flows are NOT enabled: OpenIddict 5+ deprecates them;
        // legacy clients must be migrated to authorization_code + PKCE.
        // Token Exchange (RFC 8693) is enabled here; the delegation/
        // impersonation logic itself lives in AuthorizationController.
        // Password and None are outside the current OAuth 2.1 draft
        // baseline. OAuth 2.1 is still a draft, so Identity keeps
        // compatibility for existing consumers behind the
        // Sufficit:Identity:LegacyGrants feature flags below (both
        // default to FALSE — secure-by-default). Do not remove these
        // switches until every dependent client has migrated and the
        // compatibility decision is recorded operationally.
        // -------------------------------------------------------------------
        server.AllowAuthorizationCodeFlow()
              .AllowClientCredentialsFlow()
              .AllowDeviceAuthorizationFlow()
              .AllowRefreshTokenFlow()
              .AllowTokenExchangeFlow();

        server.AddEventHandler(RecordIdentityUsage.Descriptor);
        server.AddEventHandler(RecordAuthorizationUsageFailure.Descriptor);
        server.AddEventHandler(RecordTokenUsageFailure.Descriptor);
        server.AddEventHandler(Tokens.ApplyAccessTokenFormat.Descriptor);
        server.AddEventHandler(
            Tokens.PrepareSelfContainedAccessToken.Descriptor);

        if (options.Fapi2.Enabled)
        {
            // These OpenIddict lifetimes are global. Tightening them
            // for all clients is backward compatible and avoids a
            // profiled client accidentally receiving a five-minute
            // authorization code or hour-long PAR request URI.
            server.SetAuthorizationCodeLifetime(TimeSpan.FromSeconds(
                options.Fapi2.AuthorizationCodeLifetimeSeconds));
            server.Configure(serverOptions =>
                serverOptions.RequestTokenLifetime = TimeSpan.FromSeconds(
                    options.Fapi2.PushedAuthorizationRequestLifetimeSeconds));

            server.AddEventHandler(Fapi.ValidateFapiAuthorizationRequest.Descriptor);
            server.AddEventHandler(Fapi.ValidateFapiPushedAuthorizationRequest.Descriptor);
            server.AddEventHandler(Fapi.ValidateFapiTokenRequest.Descriptor);
        }

        if (options.Jarm.Enabled)
        {
            server.Configure(serverOptions =>
            {
                serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.QueryJwt);
                serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.FragmentJwt);
                serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.FormPostJwt);
                serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.Jwt);
            });
            server.AddEventHandler(Jarm.JarmAuthorizationResponseHandler.Descriptor);
        }

        // ---- JWT-Secured Authorization Requests (JAR, RFC 9101) ----
        // Two endpoint hooks (authorization + PAR) that extract a
        // signed `request` parameter, validate it against the client's
        // registered keys, and merge its claims into the request. The
        // handlers are scoped (need IOpenIddictApplicationManager).
        if (options.Jar.Enabled)
        {
            server.AddEventHandler(Jar.JarRequestObjectHandler
                .ExtractAuthorizationRequestObject.Descriptor);
            server.AddEventHandler(Jar.JarRequestObjectHandler
                .ExtractPushedAuthorizationRequestObject.Descriptor);
        }

        if (options.LegacyGrants.Password)
            server.AllowPasswordFlow();

        if (options.LegacyGrants.None)
            server.AllowNoneFlow();

        // OAuth 2.1 baseline: require PKCE for every authorization-code
        // client and accept only S256. Both controls have explicit
        // migration opt-outs for legacy confidential clients.
        if (options.Pkce.RequireForAllClients)
            server.RequireProofKeyForCodeExchange();

        if (!options.Pkce.AllowPlainCodeChallengeMethod)
        {
            server.Configure(serverOptions =>
                serverOptions.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
        }

        if (options.Dpop.Enabled)
        {
            server.AddEventHandler(Dpop.AttachDpopConfirmation.Descriptor);
            server.AddEventHandler(Dpop.AttachDpopTokenType.Descriptor);
            server.AddEventHandler(Dpop.ExtractDpopUserInfoToken.Descriptor);
            server.AddEventHandler(Dpop.ValidateDpopAccessTokenProof.Descriptor);
        }

        if (options.Mtls.Enabled)
        {
            server.AddEventHandler(Mtls
                .RejectCombinedDpopAndMtlsSenderConstraints.Descriptor);
        }

        // -------------------------------------------------------------------
        // Token lifetimes (Sufficit:Identity:Tokens). Refresh rotation is
        // ON: OpenIddict's default behavior already issues a new,
        // single-use refresh token on every redemption and revokes the
        // previous one (with a small reuse leeway to absorb client
        // retries). Rotating refresh tokens are a non-negotiable part of
        // the 2026 security baseline (they bound the blast radius of a
        // stolen refresh token to a single use). Do NOT disable rotation;
        // only the lifetimes are configurable.
        // -------------------------------------------------------------------
        server.SetRefreshTokenLifetime(TimeSpan.FromDays(options.Tokens.RefreshTokenLifetimeDays));

        if (options.Tokens.AccessTokenLifetimeMinutes is { } accessMinutes)
            server.SetAccessTokenLifetime(TimeSpan.FromMinutes(accessMinutes));

        if (options.Tokens.IdentityTokenLifetimeMinutes is { } identityMinutes)
            server.SetIdentityTokenLifetime(TimeSpan.FromMinutes(identityMinutes));

        // -------------------------------------------------------------------
        // Reference tokens (P0 #5 / eval #B2). Historically hardcoded
        // unconditionally here for parity with the legacy Duende
        // deployment (sufficit-endpoints relies on introspection) —
        // but the legacy client inventory (docs/migration/PLAN.md in
        // git HEAD) shows sufficit-endpoints was the ONLY one of the
        // 26 legacy clients configured for reference tokens; the
        // rest expect a self-contained JWT they validate locally.
        // Flipping every client's token format at once is a breaking
        // migration-contract change, not a mechanical hardening — and
        // OpenIddict has no native per-client token-format switch, so
        // it cannot be fixed by config alone. Surfaced here as an
        // explicit, reversible flag
        // (Sufficit:Identity:Tokens:UseReferenceAccessTokens,
        // default true = current behavior, unchanged) so the
        // decision is deliberate and documented instead of buried in
        // a hardcoded call; see the XML doc on
        // TokenLifetimeOptions.UseReferenceAccessTokens for the full
        // JWT-vs-reference tradeoff. Do NOT flip to false without
        // coordinating with every resource server first.
        // -------------------------------------------------------------------
        // Keep both reference and JWT access-token pipelines available;
        // ApplyAccessTokenFormat chooses per resource/client and falls
        // back to the legacy global flag when no exact rule exists.
        server.UseReferenceAccessTokens();

        // -------------------------------------------------------------------
        // PAR (Pushed Authorization Request, RFC 9126). The endpoint is
        // set above (connect/par). PAR is required per-client by FAPI
        // 2.0 (ValidateFapiAuthorizationRequest); the global opt-in
        // here extends the requirement to every client, and the global
        // lifetime knob applies to non-FAPI requests.
        // -------------------------------------------------------------------
        if (options.Par.RequireForAllClients)
        {
            server.RequirePushedAuthorizationRequests();
        }

        if (options.Par.RequestUriLifetimeSeconds is { } parLifetime)
        {
            server.Configure(serverOptions =>
                serverOptions.RequestTokenLifetime = TimeSpan.FromSeconds(parLifetime));
        }

        // -------------------------------------------------------------------
        // Signing/encryption certificates (SECURITY CRITICAL). Production
        // requires persistent X.509 certificates configured under
        // Sufficit:Identity:Certificates (PFX files loaded from disk);
        // ephemeral development certificates are only ever used when
        // ASPNETCORE_ENVIRONMENT=Development, so a misconfigured
        // production deployment fails fast at startup instead of
        // silently signing tokens with a throwaway, regenerated-on-
        // every-restart key.
        // (isDevelopmentEnvironment computed once, near the top of
        // AddSufficitIdentitySTS, and reused here via closure.)
        // -------------------------------------------------------------------
        if (vaultOptions.ManageSigningKeys)
        {
            // OpenIddict token signing is replaced by the vault
            // handler registered below. Certificates remain available
            // to auxiliary protocol JWT generators.
            // OpenIddict requires one asymmetric credential during
            // options validation; this bootstrap key is never selected
            // by GenerateTokenContext and is removed from JWKS by the
            // vault discovery handler.
            server.AddEphemeralSigningKey();
            // Auxiliary JWTs (logout/JARM/SSF/CIBA) still use the
            // protocol credential resolved above. Publish their
            // public halves alongside the vault keys without making
            // them the OpenIddict token-signing choice.
            foreach (var certificate in certificateMaterial.Signing)
            {
                server.AddSigningKey(new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate));
            }
            if (isDevelopmentEnvironment)
            {
                server.AddSigningKey(auxiliarySigningCredentials.Key);
            }
        }
        else if (certificateMaterial.Signing.Count > 0)
        {
            foreach (var certificate in certificateMaterial.Signing)
            {
                server.AddSigningCertificate(certificate);
            }
        }
        else if (isDevelopmentEnvironment)
        {
            server.AddDevelopmentSigningCertificate();
            // Publish the same ephemeral public key used to sign JARM,
            // SSF/CAEP, logout_token and CIBA JWTs. Without this extra
            // signing key those JWTs worked only in-process and could
            // not be verified through the advertised JWKS endpoint.
            server.AddSigningKey(auxiliarySigningCredentials.Key);
        }
        else
        {
            throw new InvalidOperationException(
                "No signing certificate configured. Production deployments " +
                "require 'Sufficit:Identity:Certificates:SigningPath' (and " +
                "SigningPassword, if the PFX is protected) to point to a " +
                "valid PFX file. Ephemeral development certificates are only " +
                "allowed when ASPNETCORE_ENVIRONMENT=Development.");
        }

        if (vaultOptions.ManageSigningKeys)
        {
            server.AddEventHandler(Vault.VaultSigningCredentialsHandler.Descriptor);
            server.AddEventHandler(Vault.VaultJsonWebKeySetHandler.Descriptor);
        }

        if (certificateMaterial.Encryption.Count > 0)
        {
            foreach (var certificate in certificateMaterial.Encryption)
            {
                server.AddEncryptionCertificate(certificate);
            }
        }
        else if (isDevelopmentEnvironment)
        {
            server.AddDevelopmentEncryptionCertificate();
        }
        else
        {
            throw new InvalidOperationException(
                "No encryption certificate configured. Production deployments " +
                "require 'Sufficit:Identity:Certificates:EncryptionPath' (and " +
                "EncryptionPassword, if the PFX is protected) to point to a " +
                "valid PFX file. Ephemeral development certificates are only " +
                "allowed when ASPNETCORE_ENVIRONMENT=Development.");
        }

        // -------------------------------------------------------------------
        // Discovery customizations. Logout capabilities are advertised
        // only when their provider-neutral dispatcher is enabled. The
        // application cookie and ID Tokens carry the same opaque OIDC
        // sid, so session-specific support follows each dispatcher
        // flag. Every other previously-advertised flag
        // (DPoP, JAR request object signing algorithms, request_uri/
        // request parameter support, claims parameter,
        // check_session_iframe, and a non-standard backchannel_logout_url
        // — that field is per-client registration metadata, not OP
        // discovery metadata) has been removed entirely: none of those
        // features are actually implemented either.
        // -------------------------------------------------------------------
        server.AddEventHandler(OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.HandleConfigurationRequestContext>()
            .UseInlineHandler(context =>
            {
                // Backchannel logout (OIDC Back-Channel Logout 1.0,
                // item 3.2 [L1]): advertised as supported ONLY when the
                // STS is configured to distribute logout_tokens to RPs
                // (BackchannelLogoutOptions.Enabled). When disabled,
                // publish `false` so OIDC clients natively skip the
                // flow instead of probing.
                context.Metadata["backchannel_logout_supported"] =
                    JsonValue.Create(options.BackchannelLogout.Enabled);
                context.Metadata["backchannel_logout_session_supported"] =
                    JsonValue.Create(options.BackchannelLogout.Enabled);

                // Frontchannel logout (OIDC Front-Channel Logout 1.0):
                // one-time iframe fan-out to registered RP logout URIs.
                context.Metadata["frontchannel_logout_supported"] =
                    JsonValue.Create(options.FrontchannelLogout.Enabled);
                context.Metadata["frontchannel_logout_session_supported"] =
                    JsonValue.Create(options.FrontchannelLogout.Enabled);

                // mTLS sender-constrained access tokens (RFC 8705, item
                // 3.4). Advertised ONLY when Mtls.Enabled — the host
                // must be configured for client certificates at the TLS
                // layer for this to be true (see MtlsOptions XML doc).
                // OpenIddict 7.6 publishes the RFC 8705 client
                // authentication methods, aliases and certificate-bound
                // token flag from the native mTLS configuration above.

                // Dynamic Client Registration (RFC 7591 §2 / OIDC
                // Discovery). OpenIddict ships no DCR, so it never
                // advertises the endpoint this STS implements. Without
                // this entry an MCP client reads the discovery
                // document, finds no registration_endpoint and gives up
                // on self-registration — the flow works only for
                // clients that already exist. Advertised strictly when
                // the endpoint is actually enabled.
                if (options.Mcp.Dcr.Enabled)
                {
                    context.Metadata["registration_endpoint"] =
                        JsonValue.Create(new Uri(
                            context.Issuer ?? new Uri("/", UriKind.Relative),
                            "connect/register").AbsoluteUri);
                }

                // OpenIddict attaches `iss` to every redirectable
                // authorization response (RFC 9207). Publish the
                // matching capability bit explicitly for FAPI clients.
                context.Metadata["authorization_response_iss_parameter_supported"] =
                    JsonValue.Create(true);

                // CIMD (draft-ietf-oauth-client-id-metadata-document):
                // advertise support only when the feature is on.
                context.Metadata["client_id_metadata_document_supported"] =
                    JsonValue.Create(
                        options.Mcp.ClientIdMetadataDocuments.Enabled);

                // Note: request_uri_parameter_supported and
                // require_pushed_authorization_requests are published
                // by OpenIddict itself based on the server options
                // (RequirePushedAuthorizationRequests above toggles the
                // latter). The PAR endpoint
                // (pushed_authorization_request_endpoint) is always
                // advertised once the endpoint URI is registered.

                // DPoP (RFC 9449, item 3.1). Advertised ONLY when
                // Dpop.Enabled: the STS validates DPoP proofs and
                // sender-constrains tokens. The signing-algorithms list
                // matches what DpopProofValidator accepts (EC P-256 and
                // RSA). OpenIddict 7.6 omits this entirely (no DPoP
                // support), so DiscoveryTests previously pinned its
                // absence — that assertion is updated alongside this.
                if (options.Dpop.Enabled)
                {
                    // dpop_signing_alg_values_supported is a JSON array
                    // of JWS alg names the AS accepts in DPoP proofs.
                    context.Metadata["dpop_signing_alg_values_supported"] =
                        System.Text.Json.JsonSerializer.SerializeToNode(
                            new[] { "ES256", "RS256" });
                }

                if (options.Jarm.Enabled)
                {
                    // JARM final section 4 defines this metadata value.
                    context.Metadata["authorization_signing_alg_values_supported"] =
                        System.Text.Json.JsonSerializer.SerializeToNode(
                            new[] { auxiliarySigningCredentials.Algorithm });

                    // When JWE encryption is configured, advertise the
                    // key-management and content-encryption algorithms
                    // (FAPI 2.0 Advancing Profile signed+encrypted mode).
                    if (options.Jarm.Encryption.Enabled)
                    {
                        context.Metadata["authorization_encryption_alg_values_supported"] =
                            System.Text.Json.JsonSerializer.SerializeToNode(
                                new[] { options.Jarm.Encryption.KeyManagementAlgorithm });
                        context.Metadata["authorization_encryption_enc_values_supported"] =
                            System.Text.Json.JsonSerializer.SerializeToNode(
                                new[] { options.Jarm.Encryption.ContentEncryptionAlgorithm });
                    }
                }

                // JAR (RFC 9101): advertise request object support and
                // the accepted signing algorithms when enabled.
                if (options.Jar.Enabled)
                {
                    context.Metadata["request_parameter_supported"] =
                        JsonValue.Create(true);
                    context.Metadata["request_object_signing_alg_values_supported"] =
                        System.Text.Json.JsonSerializer.SerializeToNode(
                            options.Jar.AllowedSigningAlgorithms
                                .OrderBy(a => a, StringComparer.Ordinal).ToArray());
                }

                return default;
            })
            .SetOrder(OpenIddictServerHandlers.Discovery.AttachEndpoints.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build());

        // ASP.NET Core host: let the AuthorizationController handle the
        // connect/* endpoints (passthrough) instead of OpenIddict writing
        // the responses directly.
        var aspNetCore = server.UseAspNetCore()
              .EnableAuthorizationEndpointPassthrough()
              .EnableEndSessionEndpointPassthrough()
              .EnableTokenEndpointPassthrough()
              .EnableUserInfoEndpointPassthrough()
              .EnableEndUserVerificationEndpointPassthrough()
              .SuppressJsonResponseIndentation();

        // In Development with HTTPS (same port as the legacy STS:
        // https://localhost:5001), no transport security override needed.
        // In pure-HTTP dev mode, disable the requirement:
        if (isDevelopmentEnvironment
            && Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Contains("https://") != true)
        {
            aspNetCore.DisableTransportSecurityRequirement();
        }
    }
}
