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
        var options = configuration
            .GetSection(VaultOptions.SectionName)
            .Get<VaultOptions>() ?? new VaultOptions();
        services.AddSingleton(options);

        if (options.Enabled)
        {
            services.AddSingleton<DataProtectionKeySource>();
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
