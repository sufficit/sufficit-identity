using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Management.Configuration;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementUiAuthorizationTests
{
    [Fact]
    public async Task Generic_default_allows_only_provider_operator_role()
    {
        await using var services = CreateServices();
        var authorization = services.GetRequiredService<IAuthorizationService>();

        Assert.True((await authorization.AuthorizeAsync(
            PrincipalWithRole("identity-administrator"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(
            PrincipalWithRole("administrator"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(
            PrincipalWithRole("manager"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
    }

    [Fact]
    public async Task Exact_capability_claim_opens_only_its_provider_module()
    {
        await using var services = CreateServices();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var principal = PrincipalWithClaim(
            "scope",
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
            .AddInMemoryCollection()
            .Build();
        var collection = new ServiceCollection();
        collection.AddLogging();
        collection.AddSufficitIdentityManagementUI(configuration);
        return collection.BuildServiceProvider();
    }

    private static ClaimsPrincipal PrincipalWithRole(string role) =>
        PrincipalWithClaim(ClaimTypes.Role, role);

    private static ClaimsPrincipal PrincipalWithClaim(
        string type,
        string value) =>
        new(new ClaimsIdentity(
            [new Claim(type, value)],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
}
