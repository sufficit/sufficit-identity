using Sufficit.Identity.Vault;
using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Explicit secret boundary for in-memory integration hosts. Production uses
/// EnvironmentSecretStore, while tests must opt in to every startup secret
/// they need instead of relying on appsettings fallback behavior.
/// </summary>
internal sealed class TestSecretStore : ISecretStore
{
    private readonly IConfiguration configuration;

    public TestSecretStore(IConfiguration configuration) =>
        this.configuration = configuration;

    public Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<string?>(name switch
        {
            "database/connection-string" =>
                configuration["ConnectionStrings:DefaultConnection"],
            "identity/dcr/initial-access-token" =>
                configuration["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"],
            "identity/external-providers/google/client-id" =>
                configuration["Sufficit:Identity:ExternalProviders:Google:ClientId"],
            "identity/external-providers/google/client-secret" =>
                configuration["Sufficit:Identity:ExternalProviders:Google:ClientSecret"],
            "identity/external-providers/github/client-id" =>
                configuration["Sufficit:Identity:ExternalProviders:GitHub:ClientId"],
            "identity/external-providers/github/client-secret" =>
                configuration["Sufficit:Identity:ExternalProviders:GitHub:ClientSecret"],
            "identity/external-providers/gitlab/client-id" =>
                configuration["Sufficit:Identity:ExternalProviders:GitLab:ClientId"],
            "identity/external-providers/gitlab/client-secret" =>
                configuration["Sufficit:Identity:ExternalProviders:GitLab:ClientSecret"],
            "identity/external-providers/facebook/client-id" =>
                configuration["Sufficit:Identity:ExternalProviders:Facebook:ClientId"],
            "identity/external-providers/facebook/client-secret" =>
                configuration["Sufficit:Identity:ExternalProviders:Facebook:ClientSecret"],
            _ => null,
        });
    }
}
