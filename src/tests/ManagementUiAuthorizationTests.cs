using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Management.Configuration;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementUiAuthorizationTests
{
    [Fact]
    public async Task Default_roles_allow_both_operator_types_into_management()
    {
        await using var services = CreateServices();
        var authorization = services.GetRequiredService<IAuthorizationService>();

        Assert.True((await authorization.AuthorizeAsync(
            PrincipalWithRole("administrator"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(
            PrincipalWithRole("manager"),
            resource: null,
            ManagementUiPolicies.Access)).Succeeded);
    }

    [Fact]
    public async Task Manager_cannot_manage_clients_but_administrator_can()
    {
        await using var services = CreateServices();
        var authorization = services.GetRequiredService<IAuthorizationService>();

        Assert.False((await authorization.AuthorizeAsync(
            PrincipalWithRole("manager"),
            resource: null,
            ManagementUiPolicies.ManageClients)).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(
            PrincipalWithRole("administrator"),
            resource: null,
            ManagementUiPolicies.ManageClients)).Succeeded);
    }

    [Fact]
    public void Sufficit_defaults_make_administrator_a_management_superset()
    {
        var options = new ManagementUiOptions();

        Assert.Contains(
            "administrator",
            options.GetAccessRoles(["administrator"]));
        Assert.Contains(
            "manager",
            options.GetAccessRoles(["administrator"]));
        Assert.Equal("/management/", options.GetBaseHref());
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
        new(new ClaimsIdentity(
            [new Claim(ClaimTypes.Role, role)],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
}
