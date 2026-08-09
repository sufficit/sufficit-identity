using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
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
        IConfiguration configuration)
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
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IProductionPostureContributor,
                VaultProductionPostureContributor>());
        services.TryAddSingleton(configuration);
        if (options.EnableSecretStore)
        {
            services.TryAddScoped<ISecretStore, VaultBackedSecretStore>();
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
        ValidateKeyEncryptionKeyPolicy(options, configuration, isDevelopment);

        if (options.Enabled)
        {
            services.AddSingleton<IVaultKeyEncryptionKeySource>(sp =>
                CreateKeySource(sp, options));
            services.AddSingleton<IHostedService, VaultKekReadinessService>();
            services.AddSingleton<KeyVault>();
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
        VaultOptions options) => options.KeySource.Trim().ToLowerInvariant() switch
        {
            "dataprotection" => new DataProtectionKeySource(
                services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
                options),
            "certificate" => new CertificateKeySource(options),
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
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(configuration);
        var source = options.KeySource.Trim().ToLowerInvariant();
        if (source is not ("dataprotection" or "certificate" or "external"))
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:KeySource must be 'dataprotection', 'certificate' or 'external'.");
        }

        if (!options.Enabled) return;

        if (!isDevelopment && source == "dataprotection")
        {
            throw new InvalidOperationException(
                "The Data Protection vault KEK is development-only. Production must use a dedicated certificate or external KMS/HSM provider.");
        }

        if (source == "certificate")
        {
            if (string.IsNullOrWhiteSpace(options.CertificatePath))
            {
                throw new InvalidOperationException(
                    "Sufficit:Vault:CertificatePath is required for the certificate KEK source.");
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
                .Select(path => Path.GetFullPath(path!));
            if (signingPaths.Any(path => string.Equals(
                    path,
                    kekPath,
                    StringComparison.Ordinal)))
            {
                throw new InvalidOperationException(
                    "The vault KEK certificate must be different from every token-signing certificate.");
            }
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
}
