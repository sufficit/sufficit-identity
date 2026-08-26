using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Configuration;
using Sufficit.Identity.STS.Integrations;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IntegrationOAuthProtocolTests
{
    [Fact]
    public void Google_workspace_grant_includes_calendar_without_manual_tokens()
    {
        var registry = Registry();

        var google = Assert.IsType<IntegrationOAuthProvider>(
            registry.Find("google-workspace"));

        Assert.True(google.Available);
        Assert.Contains(
            "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
            google.Scopes);
        Assert.Contains(
            "https://www.googleapis.com/auth/calendar.events",
            google.Scopes);
        Assert.Contains(
            "https://www.googleapis.com/auth/calendar.events.freebusy",
            google.Scopes);
    }

    [Fact]
    public void Gitlab_dynamic_registration_is_a_public_pkce_client()
    {
        var gitlab = Assert.IsType<IntegrationOAuthProvider>(
            Registry().Find("gitlab"));

        var registration = IntegrationOAuthProtocol.DynamicRegistration(
            gitlab,
            "https://identity.example.test/api/integrations/oauth/callback/gitlab");
        var serialized = JsonSerializer.Serialize(registration);
        var exchange = IntegrationOAuthProtocol.AuthorizationCodeFields(
            gitlab,
            "code-1",
            "https://identity.example.test/api/integrations/oauth/callback/gitlab",
            "dynamic-client",
            clientSecret: null,
            codeVerifier: "verifier-1");

        Assert.Equal("https://gitlab.com/api/v4/mcp", registration["resource"]);
        Assert.DoesNotContain("client_secret", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("token_endpoint_auth_method", serialized, StringComparison.Ordinal);
        Assert.Equal("dynamic-client", exchange["client_id"]);
        Assert.Equal("verifier-1", exchange["code_verifier"]);
        Assert.False(exchange.ContainsKey("client_secret"));
    }

    [Fact]
    public void Missing_new_scope_requires_a_fresh_provider_grant()
    {
        var required = new[] { "openid", "calendar.events" };

        Assert.False(IntegrationOAuthProtocol.HasRequiredScopes(
            required,
            "openid profile"));
        Assert.True(IntegrationOAuthProtocol.HasRequiredScopes(
            required,
            "profile,calendar.events openid"));
        Assert.False(IntegrationOAuthProtocol.HasRequiredScopes(required, null));
    }

    [Fact]
    public void Google_canonical_and_superset_scopes_satisfy_the_requested_grant()
    {
        var required = new[]
        {
            "openid",
            "profile",
            "email",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
            "https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/calendar.events.freebusy",
        };
        var granted = string.Join(' ',
            "openid",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/calendar");

        Assert.True(IntegrationOAuthProtocol.HasRequiredScopes(required, granted));
    }

    [Fact]
    public void Granted_scope_from_static_provider_token_response_is_persisted()
    {
        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = "access_token", Value = "access-1" },
            new AuthenticationToken { Name = "scope", Value = "stale.scope" },
        ]);
        using var payload = JsonDocument.Parse(
            """{"access_token":"access-1","scope":"openid calendar.events"}""");
        using var response = OAuthTokenResponse.Success(payload);

        IntegrationOAuthProtocol.StoreGrantedScope(properties, response);

        Assert.Equal(
            "openid calendar.events",
            properties.GetTokenValue("scope"));
        Assert.Equal("access-1", properties.GetTokenValue("access_token"));
        Assert.Single(properties.GetTokens(), token => token.Name == "scope");
    }

    [Fact]
    public void Confidential_clients_keep_their_secret_in_token_requests()
    {
        var github = Assert.IsType<IntegrationOAuthProvider>(Registry().Find("github"));

        var fields = IntegrationOAuthProtocol.RefreshFields(
            github,
            "refresh-1",
            "github-client",
            "github-secret");

        Assert.Equal("github-secret", fields["client_secret"]);
    }

    private static IntegrationOAuthProviderRegistry Registry()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:ExternalProviders:Google:Enabled"] = "true",
                ["Sufficit:Identity:ExternalProviders:Google:ClientId"] = "google-client",
                ["Sufficit:Identity:ExternalProviders:Google:ClientSecret"] = "google-secret",
                ["Sufficit:Identity:ExternalProviders:GitHub:Enabled"] = "true",
                ["Sufficit:Identity:ExternalProviders:GitHub:ClientId"] = "github-client",
                ["Sufficit:Identity:ExternalProviders:GitHub:ClientSecret"] = "github-secret",
            })
            .Build();
        return new IntegrationOAuthProviderRegistry(
            configuration,
            new TestSecretStore(configuration));
    }
}
