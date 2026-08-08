using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Sufficit.Identity.Vault;

/// <summary>
/// DI extensions for the Sufficit Identity secret vault.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the vault services. When <c>Sufficit:Vault:Enabled</c> is
    /// false (default), <see cref="IKeyVault"/> resolves to
    /// <see cref="PassThroughKeyVault"/> (round-trip without crypto). When
    /// true, the real <see cref="KeyVault"/> with envelope encryption is used.
    /// </summary>
    public static IServiceCollection AddSufficitVault(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var section = configuration.GetSection(VaultOptions.SectionName);
        var options = section.Get<VaultOptions>() ?? new VaultOptions();

        // Consumers use both VaultOptions directly (the vault implementation)
        // and IOptions<VaultOptions> (management validation). Keep both views
        // bound to the same configuration so an enabled vault cannot be
        // reported as disabled by a service resolving the options pattern.
        services.AddOptions<VaultOptions>().Bind(section);
        services.AddSingleton(options);
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
        if (!options.Enabled && !isDevelopment)
        {
            if (options.RequireEncryptionInProduction)
            {
                throw new InvalidOperationException(
                    "Sufficit:Vault encryption is required in production, but Sufficit:Vault:Enabled is false.");
            }

            Console.Error.WriteLine(
                "[WARNING] Sufficit:Vault is using plaintext compatibility mode in production. Enable it, migrate pt1 values, then set RequireEncryptionInProduction=true.");
        }

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
}
