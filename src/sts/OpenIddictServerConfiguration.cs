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
        var applicationScopes = options.ClaimScopeMap
            .AllGatingScopeNames()
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
            Scopes.Phone,
            "identity.management",
            .. string.IsNullOrWhiteSpace(options.PersonalTokens.RequiredScope)
                ? Array.Empty<string>()
                : new[] { options.PersonalTokens.RequiredScope.Trim() },
            // Product scopes are deployment configuration, never built-ins of a
            // vendor-neutral STS (eval 2026-08-30, F-2). A scope that entitles
            // a claim is registered from the entitlement map itself, so
            // declaring the grant is enough; ApplicationScopes covers the rest.
            .. options.ApplicationScopes
                .Where(scope => !string.IsNullOrWhiteSpace(scope))
                .Select(scope => scope.Trim()),
            .. options.ScopeEntitlements.Grants.Keys
                .Where(scope => !string.IsNullOrWhiteSpace(scope))
                .Select(scope => scope.Trim()),
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
            Claims.Address,
            Claims.PhoneNumber,
            Claims.PhoneNumberVerified,
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

        // Optional protocol features contribute their flows, handlers and
        // server options; see Features/ProtocolFeatureCatalog.
        Features.ProtocolFeatureCatalog.ConfigureServer(
            server,
            new Features.ProtocolFeatureContext(options, auxiliarySigningCredentials));

        // private_key_jwt from any standard client library: OpenIddict only
        // accepts its own assertion media type. See
        // ClientAuthentication/StandardClientAssertionType.cs.
        server.AddEventHandler(
            ClientAuthentication.AcceptStandardClientAssertionType.Descriptor);
        server.AddEventHandler(
            ClientAuthentication.RestoreStandardClientAssertionTokenType.Descriptor);
        server.AddEventHandler(RecordIdentityUsage.Descriptor);
        server.AddEventHandler(RecordAuthorizationUsageFailure.Descriptor);
        server.AddEventHandler(RecordTokenUsageFailure.Descriptor);
        server.AddEventHandler(Security
            .AttachFormPostContentSecurityPolicy.Descriptor);
        server.AddEventHandler(Tokens.ApplyAccessTokenFormat.Descriptor);
        server.AddEventHandler(
            Tokens.PrepareSelfContainedAccessToken.Descriptor);
        // Issue #61: a replayed device_code (polling race, RFC 8628) must be
        // a plain invalid_grant. The built-in theft heuristic would otherwise
        // revoke every token of the authorization — including the reference
        // tokens just issued to the race's winner, turning their userinfo
        // 401. See Tokens/DeviceCodeReplayGuard.cs for the full rationale.
        server.AddEventHandler(Tokens.RejectRedeemedDeviceCodeReplay.Descriptor);
        // Humanize unrecoverable /connect/authorize errors (e.g. the ID2013
        // replay of a consumed PAR request_uri) for top-level browser
        // navigations; machine clients keep the raw payload. See
        // ErrorPages/BrowserAuthorizationErrorPage.cs.
        server.AddEventHandler(
            ErrorPages.BrowserAuthorizationErrorPage
                .RenderBrowserFriendlyAuthorizationError.Descriptor);

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

        // Unconditional: it decouples the stored claim name from the emitted
        // one, so it must hold for every deployment and every flow. Gating it
        // behind an option would mean the storage rename is safe on some hosts
        // and silently breaking on others.
        server.AddEventHandler(ProjectEntitlementClaimUnderBothNames.Descriptor);

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

        ConfigureServerCredentials(
            server,
            vaultOptions,
            certificateMaterial,
            auxiliarySigningCredentials,
            isDevelopmentEnvironment);

        ConfigureDiscoveryMetadata(server, options, auxiliarySigningCredentials);

        // ASP.NET Core host: let the AuthorizationController handle the
        // connect/* endpoints (passthrough) instead of OpenIddict writing
        // the responses directly.
        var aspNetCore = server.UseAspNetCore()
              .EnableStatusCodePagesIntegration()
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
