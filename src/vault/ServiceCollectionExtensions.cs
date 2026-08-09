using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
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

        if (!string.Equals(
                options.KeySource,
                "dataprotection",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:KeySource currently supports only 'dataprotection'.");
        }

        var isDevelopment = string.Equals(
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            "Development",
            StringComparison.Ordinal);
        ValidateRuntimeMode(options, isDevelopment);

        if (options.Enabled)
        {
            services.AddSingleton<DataProtectionKeySource>();
            services.AddSingleton<IVaultKeyEncryptionKeySource>(sp =>
                sp.GetRequiredService<DataProtectionKeySource>());
            services.AddSingleton<KeyVault>();
            services.AddSingleton<IKeyVault>(sp => sp.GetRequiredService<KeyVault>());
        }
        else
        {
            services.AddSingleton<IKeyVault, PassThroughKeyVault>();
        }

        return services;
    }

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
}
