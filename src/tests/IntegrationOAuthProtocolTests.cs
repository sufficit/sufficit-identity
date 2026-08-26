using System.Text.Json;
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
