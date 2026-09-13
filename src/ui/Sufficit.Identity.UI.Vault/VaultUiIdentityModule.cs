using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Hosting;
using Sufficit.Identity.UI.Abstractions.Hosting;

namespace Sufficit.Identity.UI.Vault;

/// <summary>
/// The embedded Vault UI (personal secrets and the capability-protected
/// operator Vault) as a composable module.
/// </summary>
public sealed class VaultUiIdentityModule : IIdentityModule
{
    public const string ModuleId = "vault-ui";

    public const string EnabledSetting = "Sufficit:Identity:UI:Vault:Enabled";

    public string Id => ModuleId;

    public bool IsEnabled(IConfiguration configuration) =>
        ReadHostingOptions(configuration).Vault.IsEmbedded
        && configuration.GetValue(EnabledSetting, defaultValue: true);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddSufficitIdentityVaultUI(configuration);

    public void ConfigurePipeline(IdentityPipelineBuilder pipeline) =>
        pipeline.MapEndpoints("vault-ui", app =>
        {
            // When the public UI is embedded, the Vault pages join its Blazor
            // endpoint as additional assemblies instead of mapping their own.
            var uiHostingOptions = ReadHostingOptions(
                app.Services.GetRequiredService<IConfiguration>());
            app.UseSufficitIdentityVaultUI(
                mapEndpoints: !uiHostingOptions.Public.IsEmbedded);
        });

    private static IdentityUiHostingOptions ReadHostingOptions(IConfiguration configuration) =>
        configuration
            .GetSection(IdentityUiHostingOptions.SectionName)
            .Get<IdentityUiHostingOptions>() ?? new IdentityUiHostingOptions();
}
