using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Adds deployment-provided secret overrides before startup options are bound.
/// Configuration-time consumers therefore receive values from the same
/// <see cref="ISecretStore"/> boundary as runtime consumers. Values are never
/// logged or copied back into configuration files.
/// </summary>
public static class SecretConfigurationExtensions
{
    private static readonly (string LogicalName, string ConfigurationKey)[] Overrides =
    [
        ("database/connection-string", "ConnectionStrings:DefaultConnection"),
        ("identity/certificates/signing-password",
            "Sufficit:Identity:Certificates:SigningPassword"),
        ("identity/certificates/encryption-password",
            "Sufficit:Identity:Certificates:EncryptionPassword"),
        ("vault/kek-certificate-password",
            "Sufficit:Vault:CertificatePassword"),
        ("identity/human-verification/secret-key",
            "Sufficit:Identity:HumanVerification:SecretKey"),
        ("identity/dcr/initial-access-token",
            "Sufficit:Identity:Mcp:Dcr:InitialAccessToken"),
        ("identity/external-providers/google/client-id",
            "Sufficit:Identity:ExternalProviders:Google:ClientId"),
        ("identity/external-providers/google/client-secret",
            "Sufficit:Identity:ExternalProviders:Google:ClientSecret"),
        ("identity/external-providers/github/client-id",
            "Sufficit:Identity:ExternalProviders:GitHub:ClientId"),
        ("identity/external-providers/github/client-secret",
            "Sufficit:Identity:ExternalProviders:GitHub:ClientSecret"),
        ("identity/external-providers/gitlab/client-id",
            "Sufficit:Identity:ExternalProviders:GitLab:ClientId"),
        ("identity/external-providers/gitlab/client-secret",
            "Sufficit:Identity:ExternalProviders:GitLab:ClientSecret"),
        ("identity/external-providers/facebook/client-id",
            "Sufficit:Identity:ExternalProviders:Facebook:ClientId"),
        ("identity/external-providers/facebook/client-secret",
            "Sufficit:Identity:ExternalProviders:Facebook:ClientSecret"),
        ("identity/smtp/password", "Sufficit:Identity:Smtp:Password"),
        ("exchange/rabbitmq/password", "Sufficit:Exchange:RabbitMQ:Password"),
        ("distributed-cache/connection-string", "ConnectionStrings:Redis"),
    ];

    /// <summary>
    /// Appends non-empty <c>SUFFICIT_SECRET_*</c> values as the highest
    /// precedence configuration layer for known startup secrets.
    /// </summary>
    public static IConfigurationBuilder AddSufficitSecretOverrides(
        this IConfigurationBuilder configuration)
    {
        return configuration.AddSufficitSecretOverrides(
            new EnvironmentSecretStore());
    }

    /// <summary>
    /// Appends non-empty overrides resolved through the supplied secret store.
    /// This overload is used by the composition host so startup consumers share
    /// the same secret boundary as runtime consumers.
    /// </summary>
    public static IConfigurationBuilder AddSufficitSecretOverrides(
        this IConfigurationBuilder configuration,
        ISecretStore secretStore)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(secretStore);

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (logicalName, configurationKey) in Overrides)
        {
            var value = secretStore.GetSecretAsync(logicalName)
                .GetAwaiter()
                .GetResult();
            if (!string.IsNullOrWhiteSpace(value))
            {
                values[configurationKey] = value;
            }
        }

        return values.Count is 0
            ? configuration
            : configuration.AddInMemoryCollection(values);
    }

    /// <summary>
    /// Rejects plaintext startup secrets found in configuration providers.
    /// Call this before adding environment overrides so stale appsettings
    /// values cannot remain as an unnoticed compatibility fallback.
    /// </summary>
    public static void EnsureNoPlaintextSecrets(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        foreach (var (_, configurationKey) in Overrides)
        {
            if (!string.IsNullOrWhiteSpace(configuration[configurationKey]))
            {
                throw new InvalidOperationException(
                    $"Plaintext startup secret detected at '{configurationKey}'. " +
                    "Remove it from appsettings/User Secrets and configure the corresponding SUFFICIT_SECRET_* variable in vault-secrets.env.");
            }
        }
    }

    /// <summary>Returns the supported logical-to-configuration mappings.</summary>
    public static IReadOnlyList<(string LogicalName, string ConfigurationKey)>
        GetSufficitSecretOverrideMappings() => Overrides;

}
