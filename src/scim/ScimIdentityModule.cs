using Microsoft.AspNetCore.Mvc.ApplicationParts;
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

    /// <summary>
    /// MVC discovers controllers in every referenced assembly, so a host that
    /// references SCIM maps its endpoints even with the module off. Disabled,
    /// SCIM registers no authorization policy and those endpoints would answer
    /// 500; without them they do not exist (404).
    /// </summary>
    public static void ExcludeControllers(ApplicationPartManager parts)
    {
        var scim = typeof(ScimIdentityModule).Assembly;
        foreach (var part in parts.ApplicationParts.OfType<AssemblyPart>()
            .Where(part => part.Assembly == scim).ToArray())
            parts.ApplicationParts.Remove(part);
    }
}
