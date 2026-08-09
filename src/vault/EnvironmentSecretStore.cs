using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Zero-dependency secret source used by default. Environment variables take
/// precedence over configuration so deployment secrets never need to be
/// copied into appsettings files. A logical name such as
/// <c>database/password</c> maps to
/// <c>SUFFICIT_SECRET_DATABASE_PASSWORD</c> (case-insensitive) and then falls
/// back to the mapped configuration key for known startup secrets.
/// </summary>
public sealed class EnvironmentSecretStore(
    IConfiguration? configuration = null,
    ILogger<EnvironmentSecretStore>? logger = null)
    : ISecretStore
{
    private const string Prefix = "SUFFICIT_SECRET_";

    private readonly IConfiguration? configuration = configuration;
    private readonly ILogger<EnvironmentSecretStore> logger =
        logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<EnvironmentSecretStore>.Instance;

    internal static string EnvironmentVariableName(string name) =>
        Prefix + new string(name
            .Select(character => char.IsLetterOrDigit(character)
                ? char.ToUpperInvariant(character)
                : '_')
            .ToArray());

    public Task<string?> GetSecretAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        cancellationToken.ThrowIfCancellationRequested();

        var environmentName = EnvironmentVariableName(name);

        var value = Environment.GetEnvironmentVariable(environmentName);
        if (value is null)
        {
            // Configuration providers are deliberately a compatibility
            // fallback (User Secrets, mounted JSON, etc.).
            value = configuration?[name]
                ?? configuration?[$"Secrets:{name}"];
            if (value is null)
            {
                var configurationKey =
                    SecretConfigurationExtensions.GetConfigurationKey(name);
                value = configurationKey is null
                    ? null
                    : configuration?[configurationKey];
            }
            if (!string.IsNullOrWhiteSpace(value))
            {
                logger.LogWarning(
                    "Legacy configuration secret fallback used for {SecretName}; migrate it to SUFFICIT_SECRET_*.",
                    name);
            }
        }

        return Task.FromResult(value);
    }
}
