using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class DiscoveryTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public DiscoveryTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Discovery_document_advertises_supported_logout_without_claiming_sid_support()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();

        // Both provider-neutral dispatchers are active by default. The OP
        // cookie and ID Tokens carry a stable opaque sid for session-specific
        // RP logout.
        Assert.True(json.GetProperty("backchannel_logout_supported").GetBoolean());
        Assert.True(json.GetProperty("backchannel_logout_session_supported").GetBoolean());
        Assert.True(json.GetProperty("frontchannel_logout_supported").GetBoolean());
        Assert.True(json.GetProperty("frontchannel_logout_session_supported").GetBoolean());

        // OpenIddict's own base discovery handler (not Sufficit's customization)
        // always emits these two as honest `false` booleans — that's not a
        // capability claim, it's the framework being explicit that neither
        // feature is supported. Verified against the actual response before
        // asserting: OpenIddict 7.6's discovery document really does include
        // both, always with a `false` value, regardless of the custom
        // HandleConfigurationRequestContext handler in
        // ServiceCollectionExtensions.cs (which only adds the logout flags).
        Assert.False(json.GetProperty("claims_parameter_supported").GetBoolean());
        Assert.False(json.GetProperty("request_parameter_supported").GetBoolean());

        foreach (var honestlyAbsentKey in new[]
        {
            // DPoP and the check_session_iframe (session-management draft) are
            // not implemented and OpenIddict never emits them unprompted.
            "dpop_signing_alg_values_supported",
            "check_session_iframe",
            // Per-client registration metadata, not OP discovery metadata —
            // deliberately never surfaced here (see the comment above
            // AddEventHandler<HandleConfigurationRequestContext> in
            // src/sts/ServiceCollectionExtensions.cs).
            "backchannel_logout_url",
        })
        {
            Assert.False(
                json.TryGetProperty(honestlyAbsentKey, out _),
                $"Discovery document unexpectedly advertises '{honestlyAbsentKey}', which is not implemented.");
        }
    }

    [Fact]
    public async Task Authorization_code_requires_pkce_globally_and_advertises_only_s256()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();

        var clientId = $"pkce-global-{Guid.NewGuid():N}";
        const string redirectUri = "https://pkce.tests.local/callback";
        using (var scope = factory.Services.CreateScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = "pkce-global-secret",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                RedirectUris = { new Uri(redirectUri) },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                },
                // Deliberately no per-client PKCE requirement: the global
                // server policy must still reject the request.
            });
        }

        var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        using var authorization = await client.GetAsync(QueryHelpers.AddQueryString(
            "/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = clientId,
                ["redirect_uri"] = redirectUri,
            }));
        Assert.Equal(HttpStatusCode.BadRequest, authorization.StatusCode);
        var authorizationError = await authorization.Content.ReadAsStringAsync();
        Assert.Contains("error:invalid_request", authorizationError, StringComparison.Ordinal);

        var discovery = await client.GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration");
        var methods = discovery.GetProperty("code_challenge_methods_supported")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToArray();
        Assert.Equal("S256", Assert.Single(methods));
    }

    // ----------------------------------------------------------------------
    // Item 3.4 — mTLS sender-constrained tokens (RFC 8705).
    // Discovery must advertise tls_client_certificate_bound_access_tokens ONLY
    // when Sufficit:Identity:Mtls:Enabled is true (the host must be configured
    // for client certificates first — see MtlsOptions XML doc).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Discovery_does_not_advertise_mtls_when_disabled()
    {
        // Default config: Mtls.Enabled=false.
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.TryGetProperty("tls_client_certificate_bound_access_tokens", out var flag));
        Assert.False(flag.GetBoolean());
    }

    [Fact]
    public async Task Discovery_advertises_mtls_and_mtls_endpoint_aliases_when_enabled()
    {
        // Isolated factory with Mtls.Enabled=true: discovery must publish the
        // capability flag, native authentication method and aliased endpoint
        // paths so clients know where to target certificate authentication.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mtls:Enabled"] = "true",
            ["Sufficit:Identity:Mtls:DeploymentMode"] = "DirectTls",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        var client = factory.CreateClient();
        var response = await client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.GetProperty("tls_client_certificate_bound_access_tokens").GetBoolean());
        var authenticationMethods = json
            .GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToArray();
        Assert.Contains(
            "self_signed_tls_client_auth",
            authenticationMethods);
        Assert.DoesNotContain("tls_client_auth", authenticationMethods);

        // The MTLS token endpoint alias is the primary one clients use for
        // certificate-based client auth. Its presence proves the aliased paths
        // were registered. (Discovery surfaces aliases under mtls_endpoint_aliases.)
        Assert.True(json.TryGetProperty("mtls_endpoint_aliases", out var aliases));
        Assert.True(aliases.TryGetProperty("token_endpoint", out var mtlsTokenEndpoint));
        Assert.EndsWith("/connect/token/mtls", mtlsTokenEndpoint.GetString(), StringComparison.Ordinal);
    }
}
