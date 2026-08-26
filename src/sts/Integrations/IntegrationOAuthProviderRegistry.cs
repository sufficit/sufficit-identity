using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Integrations;

/// <summary>
/// Server-owned OAuth applications that can authorize optional Genius MCP
/// integrations. Provider credentials never leave Identity; device clients
/// only receive short-lived user access tokens after proving identity.mcp.
/// </summary>
public sealed class IntegrationOAuthProviderRegistry
{
    private readonly IReadOnlyDictionary<string, IntegrationOAuthProvider> providers;

    public IntegrationOAuthProviderRegistry(
        IConfiguration configuration,
        ISecretStore secretStore)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(secretStore);

        var google = StaticProvider(
            configuration,
            secretStore,
            id: "google-workspace",
            displayName: "Google Workspace",
            scheme: "Google",
            configurationName: "Google",
            authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
            tokenEndpoint: "https://oauth2.googleapis.com/token",
            scopes:
            [
                "openid",
                "profile",
                "email",
                "https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/documents",
                "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
                "https://www.googleapis.com/auth/calendar.events",
                "https://www.googleapis.com/auth/calendar.events.freebusy",
            ]);
        var github = StaticProvider(
            configuration,
            secretStore,
            id: "github",
            displayName: "GitHub",
            scheme: "GitHub",
            configurationName: "GitHub",
            authorizationEndpoint: "https://github.com/login/oauth/authorize",
            tokenEndpoint: "https://github.com/login/oauth/access_token",
            scopes:
            [
                "repo",
                "read:org",
                "read:user",
                "user:email",
                "workflow",
            ]);
        var gitlab = new IntegrationOAuthProvider(
            "gitlab",
            "GitLab",
            Scheme: null,
            new Uri("https://gitlab.com/oauth/authorize"),
            new Uri("https://gitlab.com/oauth/token"),
            new Uri("https://gitlab.com/oauth/register"),
            ["api"],
            ClientId: null,
            ClientSecret: null,
            ProjectId: null,
            Available: true);

        providers = new[] { google, github, gitlab }
            .ToDictionary(value => value.Id, StringComparer.Ordinal);
    }

    public IReadOnlyCollection<IntegrationOAuthProvider> Providers =>
        providers.Values.ToArray();

    public IntegrationOAuthProvider? Find(string id) =>
        string.IsNullOrWhiteSpace(id)
            ? null
            : providers.GetValueOrDefault(id.Trim().ToLowerInvariant());

    private static IntegrationOAuthProvider StaticProvider(
        IConfiguration configuration,
        ISecretStore secretStore,
        string id,
        string displayName,
        string scheme,
        string configurationName,
        string authorizationEndpoint,
        string tokenEndpoint,
        IReadOnlyList<string> scopes)
    {
        var section = configuration.GetSection(
            $"Sufficit:Identity:ExternalProviders:{configurationName}");
        var logicalPrefix = configurationName.ToLowerInvariant();
        var clientId = ResolveSecret(
            secretStore,
            $"identity/external-providers/{logicalPrefix}/client-id");
        var clientSecret = ResolveSecret(
            secretStore,
            $"identity/external-providers/{logicalPrefix}/client-secret");
        return new IntegrationOAuthProvider(
            id,
            displayName,
            scheme,
            new Uri(authorizationEndpoint),
            new Uri(tokenEndpoint),
            RegistrationEndpoint: null,
            scopes,
            clientId,
            clientSecret,
            section["ProjectId"]?.Trim(),
            section.GetValue<bool>("Enabled")
                && !string.IsNullOrWhiteSpace(clientId)
                && !string.IsNullOrWhiteSpace(clientSecret));
    }

    private static string? ResolveSecret(ISecretStore store, string name) =>
        store.GetSecretAsync(name).GetAwaiter().GetResult();
}

public sealed record IntegrationOAuthProvider(
    string Id,
    string DisplayName,
    string? Scheme,
    Uri AuthorizationEndpoint,
    Uri TokenEndpoint,
    Uri? RegistrationEndpoint,
    IReadOnlyList<string> Scopes,
    string? ClientId,
    string? ClientSecret,
    string? ProjectId,
    bool Available,
    Uri? Resource = null);
