using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Hosting;

namespace Sufficit.Identity.Management;

/// <summary>
/// The management REST API as a composable module.
/// </summary>
public sealed class ManagementIdentityModule : IIdentityModule
{
    public const string ModuleId = "management";

    public const string EnabledSetting = "Sufficit:Identity:Management:Enabled";

    public string Id => ModuleId;

    public bool IsEnabled(IConfiguration configuration) =>
        configuration.GetValue<bool>(EnabledSetting);

    public void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        // The module composes the generic scope/role resolver decorated by the
        // service principal resolver. Which roles receive full administrator
        // access is deployment configuration
        // (Sufficit:Identity:Management:Authorization:FullAdministratorRoles,
        // empty by default), never a role name hard-coded in a host.
        services.AddSufficitIdentityManagement(configuration);

        // Provisioning of confidential clients resolves secret references
        // through the vault. IKeyVault is registered by the STS module
        // (pass-through by default, real encryption when the vault is enabled).
        services.Replace(
            ServiceDescriptor.Singleton<
                Provisioning.IClientSecretResolver,
                Sufficit.Identity.Vault.VaultBackedClientSecretResolver>());
    }

    public void ConfigurePipeline(IdentityPipelineBuilder pipeline) =>
        pipeline.Use(
            IdentityPipelineStage.Endpoints,
            "management-endpoints",
            app => app.UseSufficitIdentityManagementEndpoints(
                app.ApplicationServices.GetRequiredService<IConfiguration>()));
}
