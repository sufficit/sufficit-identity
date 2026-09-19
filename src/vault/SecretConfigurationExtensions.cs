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
        ISecretStore secretStore) =>
        configuration.AddSufficitSecretOverrides(secretStore, out _);

    /// <summary>
    /// Appends the overrides and reports where each known startup secret came
    /// from. The report carries logical names and sources, never a value.
    /// </summary>
    public static IConfigurationBuilder AddSufficitSecretOverrides(
        this IConfigurationBuilder configuration,
        ISecretStore secretStore,
        out SecretResolutionReport report)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(secretStore);

        // The sources already in the builder are the legacy fallback: whatever
        // answers here did not come through the secret store.
        var existing = configuration.Build();

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var resolutions = new List<SecretResolution>(Overrides.Length);
        foreach (var (logicalName, configurationKey) in Overrides)
        {
            var value = secretStore.GetSecretAsync(logicalName)
                .GetAwaiter()
                .GetResult();
            if (!string.IsNullOrWhiteSpace(value))
            {
                values[configurationKey] = value;
                resolutions.Add(new(
                    logicalName,
                    configurationKey,
                    SecretResolutionSource.SecretStore));
                continue;
            }

            resolutions.Add(new(
                logicalName,
                configurationKey,
                string.IsNullOrWhiteSpace(existing[configurationKey])
                    ? SecretResolutionSource.Absent
                    : SecretResolutionSource.Configuration));
        }

        report = new SecretResolutionReport(resolutions);
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

    /// <summary>
    /// Configuration keys that look like secrets by name, carry a value, and
    /// are not one of the mapped startup secrets.
    /// </summary>
    /// <remarks>
    /// <see cref="EnsureNoPlaintextSecrets"/> only knows the seventeen keys
    /// this file maps, so a secret nobody thought to map — a resource secret,
    /// an API key added for one integration — stays in an appsettings file
    /// unnoticed. This finds those by naming convention, which is imprecise on
    /// purpose: a deployment reviewing a false positive costs a minute, and a
    /// missed credential costs considerably more.
    ///
    /// Returns keys only. The caller reports names, never values.
    /// </remarks>
    /// <summary>
    /// Whether the key is a secret-boundary variable rather than a value that
    /// slipped past it.
    /// </summary>
    /// <remarks>
    /// Environment variables are part of <see cref="IConfiguration"/>, and
    /// <c>mapped</c> holds configuration keys — <c>ConnectionStrings:DefaultConnection</c>
    /// — not the <c>SUFFICIT_SECRET_*</c> names those values arrive under. Without
    /// this the scan reported every correctly placed secret and advised moving it
    /// to a SUFFICIT_SECRET_* variable, which is where it already was. Production
    /// logged ten such findings on 2026-09-19.
    /// </remarks>
    private static bool IsSecretBoundaryVariable(string key) =>
        key.Split(':')[^1].StartsWith(
            EnvironmentSecretStore.Prefix,
            StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<string> FindUnmappedSecretLikeKeys(
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var mapped = Overrides
            .Select(mapping => mapping.ConfigurationKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return [.. Walk(configuration)
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Value))
            .Where(entry => !mapped.Contains(entry.Key))
            .Where(entry => !IsSecretBoundaryVariable(entry.Key))
            .Where(entry => LooksLikeSecret(entry.Key, entry.Value!))
            .Select(entry => entry.Key)
            .Order(StringComparer.Ordinal)];

        static IEnumerable<KeyValuePair<string, string?>> Walk(
            IConfiguration section)
        {
            foreach (var child in section.GetChildren())
            {
                if (child.Value is not null)
                {
                    yield return new(child.Path, child.Value);
                }

                foreach (var descendant in Walk(child))
                {
                    yield return descendant;
                }
            }
        }
    }

    private static readonly string[] SecretSuffixes =
        ["password", "secret", "apikey", "accesstoken", "connectionstring"];

    /// <summary>
    /// Words that turn a secret-looking name into a setting: a key's
    /// <em>name</em>, <em>path</em> or <em>source</em> is not the key.
    /// </summary>
    private static readonly string[] NotSecretMarkers =
        ["name", "path", "source", "mode", "enabled", "lifetime", "days",
         "minutes", "seconds", "type", "provider", "url", "uri", "id",
         "length", "size", "count", "issuer", "audience"];

    /// <summary>
    /// Prefixes that make the key a question about a secret rather than the
    /// secret: <c>RequireInitialAccessToken</c> is a switch.
    /// </summary>
    private static readonly string[] NotSecretPrefixes =
        ["require", "use", "has", "is", "allow", "enable", "reject", "validate"];

    private static bool LooksLikeSecret(string key, string value)
    {
        // A connection string carries its credential inside the value, so the
        // key name proves nothing: ConnectionStrings:Reporting looks innocent
        // and may still hold "Password=...".
        if (value.Contains("password=", StringComparison.OrdinalIgnoreCase)
            || value.Contains("pwd=", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var leaf = key[(key.LastIndexOf(':') + 1)..];

        // This repository documents a real key by placing a commented twin
        // beside it, prefixed with an underscore. Those hold guidance, not
        // credentials, and every template would report a handful of them.
        if (leaf.StartsWith('_'))
        {
            return false;
        }

        // A boolean is never a credential, however it is named —
        // LegacyGrants:Password is a switch that enables ROPC.
        if (bool.TryParse(value, out _) || long.TryParse(value, out _))
        {
            return false;
        }

        leaf = leaf.ToLowerInvariant();
        if (NotSecretPrefixes.Any(prefix =>
                leaf.StartsWith(prefix, StringComparison.Ordinal))
            || NotSecretMarkers.Any(marker =>
                leaf.EndsWith(marker, StringComparison.Ordinal)))
        {
            return false;
        }

        return SecretSuffixes.Any(suffix =>
            leaf.EndsWith(suffix, StringComparison.Ordinal));
    }

    /// <summary>Returns the supported logical-to-configuration mappings.</summary>
    public static IReadOnlyList<(string LogicalName, string ConfigurationKey)>
        GetSufficitSecretOverrideMappings() => Overrides;

}
