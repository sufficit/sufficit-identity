using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Hosting;

namespace Sufficit.Identity.Scim;

/// <summary>
/// SCIM 2.0 provisioning (RFC 7643/7644) as a composable module. Its
/// controllers join the host's controller endpoints, so it contributes no
/// pipeline steps of its own.
/// </summary>
public sealed class ScimIdentityModule : IIdentityModule
{
    public const string ModuleId = "scim";

    public const string EnabledSetting = "Sufficit:Identity:Scim:Enabled";

    public string Id => ModuleId;

    public bool IsEnabled(IConfiguration configuration) =>
        configuration.GetValue<bool>(EnabledSetting);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) =>
        services.AddSufficitIdentityScim(configuration);
}
