using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Sufficit.Identity.Vault.Client;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IVaultSecretsClient"/> against the identity
    /// management API. The returned <see cref="IHttpClientBuilder"/> is where
    /// the host attaches its authentication handler (client-credentials
    /// bearer token with the vault capabilities).
    /// </summary>
    public static IHttpClientBuilder AddSufficitVaultSecretsClient(
        this IServiceCollection services,
        Action<VaultSecretsClientOptions>? configure = null)
    {
        services.AddMemoryCache();
        services.AddOptions<VaultSecretsClientOptions>()
            .BindConfiguration(VaultSecretsClientOptions.SectionName);
        if (configure is not null) services.Configure(configure);
        services.PostConfigure<VaultSecretsClientOptions>(options =>
        {
            if (options.BaseAddress is null)
                throw new InvalidOperationException(
                    $"Configure {VaultSecretsClientOptions.SectionName}:BaseAddress "
                    + "with the identity management API address.");
        });

        services.TryAddSingleton<IVaultSecretsClient, VaultSecretsClient>();
        var builder = services.AddHttpClient(
            VaultSecretsClient.HttpClientName,
            static (provider, http) =>
            {
                var options = provider
                    .GetRequiredService<IOptions<VaultSecretsClientOptions>>()
                    .Value;
                http.BaseAddress = options.BaseAddress;
            });
        return builder;
    }
}
