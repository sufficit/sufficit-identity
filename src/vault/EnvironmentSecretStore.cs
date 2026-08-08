using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Zero-dependency secret source used by default. Environment variables take
/// precedence over configuration so deployment secrets never need to be
/// copied into appsettings files. A logical name such as
/// <c>database/password</c> maps to
/// <c>SUFFICIT_SECRET_DATABASE_PASSWORD</c> (case-insensitive) and then falls
/// back to the configuration key itself.
/// </summary>
internal sealed class EnvironmentSecretStore(IConfiguration configuration)
    : ISecretStore
{
    private const string Prefix = "SUFFICIT_SECRET_";

    public Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        cancellationToken.ThrowIfCancellationRequested();

        var environmentName = Prefix + new string(name
            .Select(character => char.IsLetterOrDigit(character)
                ? char.ToUpperInvariant(character)
                : '_')
            .ToArray());

        var value = Environment.GetEnvironmentVariable(environmentName);
        if (value is null)
        {
            // Configuration providers are deliberately a compatibility
            // fallback (User Secrets, mounted JSON, etc.).
            value = configuration[name]
                ?? configuration[$"Secrets:{name}"];
        }

        return Task.FromResult(value);
    }
}
