using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Management.Configuration;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementUiAuthorizationTests
{
    [Fact]
    public async Task Full_administrator_role_grants_access_when_configured()
    {
        await using var services = CreateServices();
        var authorization = services.GetRequiredService<IAuthorizationService>();

        // identity-administrator is configured as a FullAdministratorRole.
        Assert.True((await authorization.AuthorizeAsync(
            PrincipalWithRole("identity-administrator"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        // Unconfigured roles are NOT administrators by default (M2 fix).
        Assert.False((await authorization.AuthorizeAsync(
            PrincipalWithRole("administrator"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(
            PrincipalWithRole("manager"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(
            PrincipalWithRole("identity-administrator", "unassigned-operator"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
    }

    [Fact]
    public async Task Permission_claim_opens_only_its_provider_module()
    {
        await using var services = CreateServices();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        // M1 fix: capabilities come from "permission" claims, NOT "scope".
        var principal = PrincipalWithClaim(
            "permission",
            ManagementCapabilities.ClientsRead);

        Assert.True((await authorization.AuthorizeAsync(
            principal,
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(
            principal,
            resource: null,
            ManagementUiPolicies.ManageClients)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(
            principal,
            resource: null,
            ManagementUiPolicies.ManageBranding)).Succeeded);
    }

    [Fact]
    public void Management_ui_options_only_define_mount_path()
    {
        var options = new ManagementUiOptions();

        Assert.Equal("/management", options.GetPathBase());
        Assert.Equal("/management/", options.GetBaseHref());
        Assert.DoesNotContain(
            typeof(ManagementUiOptions).GetProperties(),
            property => property.Name.Contains(
                "Role",
                StringComparison.OrdinalIgnoreCase));
    }

    private static ServiceProvider CreateServices()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Management:RequireMfa"] = "false",
                ["Sufficit:Identity:Management:Authorization:FullAdministratorRoles:0"] = "identity-administrator",
                ["Sufficit:Identity:Management:Authorization:CapabilityClaimTypes:0"] = "permission",
                ["Sufficit:Identity:Management:Authorization:TenantAccess:SubjectTenants:operator-1:0"] = "global"
            })
            .Build();
        var collection = new ServiceCollection();
        collection.AddLogging();
        collection.AddOptions<ManagementOptions>()
            .Bind(configuration.GetSection("Sufficit:Identity:Management"));
        collection.AddScoped<IManagementEntitlementResolver,
            ScopeAndRoleManagementEntitlementResolver>();
        collection.AddScoped<IManagementTenantResolver,
            ConfigurationManagementTenantResolver>();
        collection.AddScoped<IProtectedPrincipalAccessPolicy,
            TestAllowProtectedPrincipalAccessPolicy>();
        collection.AddScoped<IManagementObjectAccessPolicy,
            ConfigurationManagementObjectAccessPolicy>();
        collection.AddScoped<IManagementAccessPolicyProvider,
            ConfigurationManagementAccessPolicyProvider>();
        collection.AddScoped<IManagementAuthorizationEvaluator,
            CapabilityManagementAuthorizationEvaluator>();
        collection.AddSufficitIdentityManagementUI(configuration);
        return collection.BuildServiceProvider();
    }

    private static ClaimsPrincipal PrincipalWithRole(
        string role,
        string subject = "operator-1") =>
        PrincipalWithClaim(ClaimTypes.Role, role, subject);

    private static ClaimsPrincipal PrincipalWithClaim(
        string type,
        string value,
        string subject = "operator-1") =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, subject),
                new Claim(type, value),
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
}
