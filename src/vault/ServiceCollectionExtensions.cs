using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography.X509Certificates;
using StackExchange.Redis;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Vault;

/// <summary>
/// DI extensions for the Sufficit Identity secret vault.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the vault services. A disabled vault resolves to
    /// <see cref="PassThroughKeyVault"/> only in Development. Other
    /// environments fail startup unless the real encrypted vault is enabled.
    /// </summary>
    public static IServiceCollection AddSufficitVault(
        this IServiceCollection services,
        IConfiguration configuration,
        ISecretStore? startupSecretStore = null)
    {
        services.AddLogging();
        var section = configuration.GetSection(VaultOptions.SectionName);
        var options = section.Get<VaultOptions>() ?? new VaultOptions();

        // Consumers use both VaultOptions directly (the vault implementation)
        // and IOptions<VaultOptions> (management validation). Keep both views
        // bound to the same configuration so an enabled vault cannot be
        // reported as disabled by a service resolving the options pattern.
        services.AddOptions<VaultOptions>().Bind(section);
        services.AddSingleton(options);
        services.AddSingleton(options.Snapshot);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IProductionPostureContributor,
                VaultProductionPostureContributor>());
        services.TryAddSingleton(configuration);
        var redisConnectionString = configuration.GetConnectionString("Redis");
        if (!string.IsNullOrWhiteSpace(redisConnectionString))
        {
            services.TryAddSingleton<IConnectionMultiplexer>(_ =>
            {
                var redisOptions = ConfigurationOptions.Parse(redisConnectionString);
                redisOptions.AbortOnConnectFail = false;
                return ConnectionMultiplexer.Connect(redisOptions);
            });
            services.TryAddSingleton<IVaultSnapshotInvalidationBus,
                RedisVaultSnapshotInvalidationBus>();
        }
        var resolvedSecretStore = startupSecretStore
            ?? new EnvironmentSecretStore();
        if (options.EnableSecretStore)
        {
            services.TryAddScoped<ISecretStore, VaultBackedSecretStore>();
        }
        else if (startupSecretStore is not null)
        {
            // Keep the exact startup boundary (EnvironmentSecretStore in
            // production, an explicit test store in integration hosts) for
            // runtime consumers that are not using the database-backed vault.
            services.TryAddSingleton<ISecretStore>(resolvedSecretStore);
        }
        else
        {
            services.TryAddSingleton<ISecretStore, EnvironmentSecretStore>();
        }
        services.TryAddScoped<IVaultNamedSecretStore, VaultBackedSecretStore>();
        services.TryAddScoped<Sufficit.Identity.Management.Vault.IUserVaultService,
            UserVaultPersonalSecretService>();

        var isDevelopment = string.Equals(
            configuration["ASPNETCORE_ENVIRONMENT"]
                ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            "Development",
            StringComparison.Ordinal);
        ValidateRuntimeMode(options, isDevelopment);
        ValidateKeyEncryptionKeyPolicy(
            options,
            configuration,
            isDevelopment,
            resolvedSecretStore);

        if (options.Enabled)
        {
            services.AddSingleton<IVaultKeyEncryptionKeySource>(sp =>
                CreateKeySource(sp, options, resolvedSecretStore));
            services.AddSingleton<IHostedService, VaultKekReadinessService>();
            services.AddSingleton<VaultCryptographyTelemetry>();
            services.AddSingleton(sp => new VaultSnapshotCache(
                sp.GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<Sufficit.Identity.Core.Data.AppDbContext>>(),
                sp.GetRequiredService<VaultSnapshotOptions>(),
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<VaultSnapshotCache>>(),
                sp.GetService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
                sp.GetService<IVaultSnapshotInvalidationBus>()));
            if (options.Snapshot.Enabled)
            {
                services.AddSingleton<IHostedService, VaultSnapshotRefreshService>();
                if (!string.IsNullOrWhiteSpace(redisConnectionString))
                {
                    services.AddSingleton<IHostedService,
                        VaultSnapshotInvalidationService>();
                }
            }
            services.AddSingleton<KeyVault>(sp => new KeyVault(
                sp.GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<Sufficit.Identity.Core.Data.AppDbContext>>(),
                sp.GetRequiredService<IVaultKeyEncryptionKeySource>(),
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<KeyVault>>(),
                options,
                sp.GetRequiredService<VaultCryptographyTelemetry>(),
                sp.GetService<TimeProvider>(),
                sp.GetService<VaultSnapshotCache>(),
                allowPlaintextReadCompatibility: isDevelopment
                    || options.PlaintextReadCompatibility.IsConfigured,
                plaintextReadCompatibilityExpiresAtUtc: isDevelopment
                    ? null
                    : options.PlaintextReadCompatibility.ExpiresAtUtc));
            services.AddSingleton<IKeyVault>(sp => sp.GetRequiredService<KeyVault>());
            if (options.ManageSigningKeys)
            {
                services.AddSingleton<IHostedService,
                    VaultSigningKeyLifecycleService>();
            }
        }
        else
        {
            services.AddSingleton<IKeyVault, PassThroughKeyVault>();
        }

        return services;
    }

    private static IVaultKeyEncryptionKeySource CreateKeySource(
        IServiceProvider services,
        VaultOptions options,
        ISecretStore secretStore) => options.KeySource.Trim().ToLowerInvariant() switch
        {
            "dataprotection" => new DataProtectionKeySource(
                services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
                options),
            "certificate" => new CertificateKeySource(
                options,
                secretStore),
            "external" => new ExternalKeySource(
                services.GetRequiredService<IVaultExternalKeyEncryptionProvider>(),
                options),
            _ => throw new InvalidOperationException(
                $"Unsupported Sufficit:Vault:KeySource '{options.KeySource}'."),
        };

    internal static void ValidateRuntimeMode(
        VaultOptions options,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.Enabled && !isDevelopment)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:Enabled=true is required outside Development; " +
                "the PassThroughKeyVault compatibility backend is development-only.");
        }
    }

    internal static void ValidateKeyEncryptionKeyPolicy(
        VaultOptions options,
        IConfiguration configuration,
        bool isDevelopment,
        ISecretStore? secretStore = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(configuration);
        var effectiveSecretStore = secretStore
            ?? new EnvironmentSecretStore();
        var source = options.KeySource.Trim().ToLowerInvariant();
        if (source is not ("dataprotection" or "certificate" or "external"))
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:KeySource must be 'dataprotection', 'certificate' or 'external'.");
        }

        if (!options.Enabled) return;

        if (options.AesGcmMessageBudgetPerKeyVersion is < 1 or > 4_294_967_296)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:AesGcmMessageBudgetPerKeyVersion must be between 1 and 4294967296.");
        }

        if (options.Snapshot.LocalLifetimeSeconds is < 1 or > 3_600)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:Snapshot:LocalLifetimeSeconds must be between 1 and 3600.");
        }

        if (options.Snapshot.DistributedLifetimeSeconds is < 1 or > 3_600)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:Snapshot:DistributedLifetimeSeconds must be between 1 and 3600.");
        }

        if (options.Snapshot.RefreshIntervalSeconds is < 1 or > 600)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:Snapshot:RefreshIntervalSeconds must be between 1 and 600.");
        }

        if (options.Snapshot.MaxEntries is < 1 or > 100_000)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:Snapshot:MaxEntries must be between 1 and 100000.");
        }

        var requiresDedicatedCertificate = !isDevelopment
            || source == "certificate"
            || !string.IsNullOrWhiteSpace(options.CertificatePath);
        if (requiresDedicatedCertificate)
        {
            if (string.IsNullOrWhiteSpace(options.CertificatePath))
            {
                throw new InvalidOperationException(
                    "Sufficit:Vault:CertificatePath is required outside Development to protect the Data Protection key ring with a certificate dedicated to the vault.");
            }

            var kekPath = Path.GetFullPath(options.CertificatePath);
            var signingPaths = new[]
                {
                    configuration["Sufficit:Identity:Certificates:SigningPath"]
                }
                .Concat(configuration
                    .GetSection("Sufficit:Identity:Certificates:SigningPaths")
                .Get<string[]>() ?? [])
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => Path.GetFullPath(path!))
                .ToArray();
            if (signingPaths.Any(path => string.Equals(
                    path,
                    kekPath,
                    StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    "The vault KEK certificate must be different from every token-signing certificate.");
            }

            using var kekCertificate = VaultKeyEncryptionCertificate.Load(
                options,
                effectiveSecretStore);
            var signingPassword = effectiveSecretStore.GetSecretAsync(
                    "identity/certificates/signing-password")
                .GetAwaiter()
                .GetResult();
            foreach (var signingPath in signingPaths)
            {
                using var signingCertificate =
                    X509CertificateLoader.LoadPkcs12FromFile(
                        signingPath,
                        signingPassword);
                if (string.Equals(
                        signingCertificate.Thumbprint,
                        kekCertificate.Thumbprint,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "The vault KEK certificate thumbprint must be different from every token-signing certificate.");
                }
            }
        }

        ValidateLegacyCertificateMigration(
            options.LegacyDataProtectionCertificateMigration,
            now: DateTimeOffset.UtcNow);

        ValidatePlaintextReadCompatibility(
            options.PlaintextReadCompatibility,
            now: DateTimeOffset.UtcNow);

        if (!isDevelopment
            && source == "external"
            && string.IsNullOrWhiteSpace(options.ExternalKeyIdentifier))
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:ExternalKeyIdentifier is required in production to pin the KMS/HSM KEK version.");
        }

        if (!SigningAlgorithms.Supported.Contains(
                options.SigningAlgorithm))
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:SigningAlgorithm must be one of: "
                + string.Join(", ", SigningAlgorithms.Supported) + ".");
        }

        if (options.SigningKeyOverlapSeconds < 1)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:SigningKeyOverlapSeconds must be positive.");
        }

        if (options.SigningKeyLockSeconds is < 5 or > 600)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:SigningKeyLockSeconds must be between 5 and 600.");
        }
    }

    internal static void ValidateLegacyCertificateMigration(
        VaultLegacyCertificateMigrationOptions migration,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(migration);
        if (!migration.IsConfigured) return;

        if (string.IsNullOrWhiteSpace(migration.Owner)
            || string.IsNullOrWhiteSpace(migration.Reason)
            || migration.ExpiresAtUtc is null)
        {
            throw new InvalidOperationException(
                "LegacyDataProtectionCertificateMigration requires Owner, Reason and ExpiresAtUtc together.");
        }

        if (migration.ExpiresAtUtc <= now)
        {
            throw new InvalidOperationException(
                "LegacyDataProtectionCertificateMigration has expired; remove the signing-certificate unwrap fallback.");
        }

        if (migration.ExpiresAtUtc > now.AddDays(180))
        {
            throw new InvalidOperationException(
                "LegacyDataProtectionCertificateMigration cannot exceed 180 days.");
        }
    }

    /// <summary>
    /// F-2 (eval 2026-08-14): the bounded acknowledgement window that permits
    /// the real vault to read legacy <c>pt1.</c> plaintext values outside
    /// Development. Same shape as the legacy certificate migration: Owner,
    /// Reason and a future ExpiresAtUtc, capped at 180 days. KeyVault enforces
    /// the deadline again at read time, so a process that outlives the window
    /// stops accepting the marker without a restart.
    /// </summary>
    internal static void ValidatePlaintextReadCompatibility(
        VaultPlaintextReadCompatibilityOptions compatibility,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(compatibility);
        if (!compatibility.IsConfigured) return;

        if (string.IsNullOrWhiteSpace(compatibility.Owner)
            || string.IsNullOrWhiteSpace(compatibility.Reason)
            || compatibility.ExpiresAtUtc is null)
        {
            throw new InvalidOperationException(
                "PlaintextReadCompatibility requires Owner, Reason and ExpiresAtUtc together.");
        }

        if (compatibility.ExpiresAtUtc <= now)
        {
            throw new InvalidOperationException(
                "PlaintextReadCompatibility has expired; remove the window and rewrite the " +
                "remaining pt1 rows with envelope encryption.");
        }

        if (compatibility.ExpiresAtUtc > now.AddDays(180))
        {
            throw new InvalidOperationException(
                "PlaintextReadCompatibility cannot exceed 180 days.");
        }
    }
}
