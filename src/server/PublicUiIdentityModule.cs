using Sufficit.Identity.Hosting;
using Sufficit.Identity.UI;
using Sufficit.Identity.UI.Abstractions.Hosting;

namespace Sufficit.Identity.Server;

/// <summary>
/// The embedded public UI (login, consent, device flow, manage area) as a
/// composable module. It lives in the host because it also installs the
/// browser adapters that render protocol errors and the device launcher with
/// UI components; those adapters need the STS, and the UI project must not.
/// </summary>
public sealed class PublicUiIdentityModule : IIdentityModule
{
    public const string ModuleId = "public-ui";

    public string Id => ModuleId;

    public bool IsEnabled(IConfiguration configuration) =>
        ReadHostingOptions(configuration).Public.IsEmbedded;

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddSufficitIdentityUI(configuration);
        services.AddSingleton<BrowserRateLimitErrors>();
    }

    public void ConfigurePipeline(IdentityPipelineBuilder pipeline)
    {
        // Only the embedded public UI can serve the recovery page and its
        // assets. Install before authentication: OpenIddict checks for the
        // status-page feature.
        pipeline.Use(
            IdentityPipelineStage.PreAuthentication,
            "browser-authorization-errors",
            app => app.UseBrowserAuthorizationErrors());
        pipeline.MapEndpoints("device-browser-launch", app => app.MapDeviceBrowserLaunch());

        // Surfaces that share the public Blazor endpoint (the Vault UI when
        // both are embedded) register their component assembly through DI.
        pipeline.MapEndpoints("public-ui", app => app.UseSufficitIdentityUI(
            app.Services.GetServices<PublicUiComponentAssembly>()
                .Select(contribution => contribution.Assembly)
                .Distinct()
                .ToArray()));
    }

    private static IdentityUiHostingOptions ReadHostingOptions(IConfiguration configuration) =>
        configuration
            .GetSection(IdentityUiHostingOptions.SectionName)
            .Get<IdentityUiHostingOptions>() ?? new IdentityUiHostingOptions();
}
