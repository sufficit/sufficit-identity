using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Hosting;
using Sufficit.Identity.UI.Abstractions.Hosting;

namespace Sufficit.Identity.UI.Management;

/// <summary>
/// The embedded management console as a composable module. It is enabled only
/// when the management API is enabled and the management surface is hosted
/// embedded.
/// </summary>
public sealed class ManagementUiIdentityModule : IIdentityModule
{
    public const string ModuleId = "management-ui";

    public const string ManagementEnabledSetting = "Sufficit:Identity:Management:Enabled";

    public string Id => ModuleId;

    public bool IsEnabled(IConfiguration configuration)
    {
        var uiHostingOptions = configuration
            .GetSection(IdentityUiHostingOptions.SectionName)
            .Get<IdentityUiHostingOptions>() ?? new IdentityUiHostingOptions();
        return configuration.GetValue<bool>(ManagementEnabledSetting)
            && uiHostingOptions.Management.IsEmbedded;
    }

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddSufficitIdentityManagementUI(configuration);

    public void ConfigurePipeline(IdentityPipelineBuilder pipeline) =>
        pipeline.MapEndpoints("management-ui", app => app.UseSufficitIdentityManagementUI());
}
