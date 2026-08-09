using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Adds deployment-provided secret overrides before startup options are bound.
/// This keeps configuration-time consumers compatible while allowing operators
/// to remove secret values from machine-specific JSON files one setting at a
/// time. Values are never logged or copied back into configuration files.
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
        ("identity/external-providers/google/client-id",
            "Sufficit:Identity:ExternalProviders:Google:ClientId"),
        ("identity/external-providers/google/client-secret",
            "Sufficit:Identity:ExternalProviders:Google:ClientSecret"),
        ("identity/external-providers/github/client-id",
            "Sufficit:Identity:ExternalProviders:GitHub:ClientId"),
        ("identity/external-providers/github/client-secret",
            "Sufficit:Identity:ExternalProviders:GitHub:ClientSecret"),
        ("identity/external-providers/facebook/client-id",
            "Sufficit:Identity:ExternalProviders:Facebook:ClientId"),
        ("identity/external-providers/facebook/client-secret",
            "Sufficit:Identity:ExternalProviders:Facebook:ClientSecret"),
        ("identity/smtp/password", "Sufficit:Identity:Smtp:Password"),
        ("exchange/rabbitmq/password", "Sufficit:Exchange:RabbitMQ:Password"),
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

    /// <summary>Returns the supported logical-to-configuration mappings.</summary>
    public static IReadOnlyList<(string LogicalName, string ConfigurationKey)>
        GetSufficitSecretOverrideMappings() => Overrides;

    internal static string? GetConfigurationKey(string logicalName)
    {
        foreach (var (mappedName, configurationKey) in Overrides)
        {
            if (string.Equals(mappedName, logicalName, StringComparison.OrdinalIgnoreCase))
            {
                return configurationKey;
            }
        }

        return null;
    }
}
