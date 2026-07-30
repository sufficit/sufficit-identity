using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Permissions;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Server.Management;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class UserPermissionManagementTests
{
    private const string FirstContext =
        "4082aef4-42d3-4b1b-a321-f405af935940";
    private const string SecondContext =
        "f96802a6-8d90-4143-a939-dd5258f3cfaa";

    [Fact]
    public async Task Role_endpoint_updates_stamp_and_writes_audit()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        string targetId;
        string? originalSecurityStamp;

        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = setup.ServiceProvider
                .GetRequiredService<RoleManager<ApplicationRole>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"role-target-{Guid.NewGuid():N}",
                TestDataSeeder.DefaultPassword);
            targetId = target.Id;
            originalSecurityStamp = target.SecurityStamp;
            if (await roleManager.FindByNameAsync("support") is null)
            {
                Assert.True((await roleManager.CreateAsync(
                    new ApplicationRole { Name = "support" })).Succeeded);
            }
        }

        var client = factory.CreateClient();
        using var response = await client.PutAsJsonAsync(
            $"/api/users/{targetId}/permissions/roles",
            new SetManagementUserRoleCommand(
                Role: "support",
                Assigned: true));
        var body = await response.Content
            .ReadFromJsonAsync<ManagementUserPermissions>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(body);
        Assert.Contains(
            body.Roles,
            role => role.Key == "support" && role.IsAssigned);

        await using var verification = factory.Services.CreateAsyncScope();
        var userManagerAfter = verification.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var persisted = await userManagerAfter.FindByIdAsync(targetId);
        Assert.NotNull(persisted);
        Assert.True(await userManagerAfter.IsInRoleAsync(
            persisted,
            "support"));
        Assert.NotEqual(originalSecurityStamp, persisted.SecurityStamp);

        var database = verification.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.True(await database.ManagementAuditEvents.AnyAsync(entry =>
            entry.Capability
                == ManagementCapabilities.UsersPermissionsManage
            && entry.ResourceId == $"{targetId}/roles/support"
            && entry.ReasonCode == "user_role_added"));
    }

    [Fact]
    public async Task Last_administrator_role_cannot_be_removed()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        string administratorId;

        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = setup.ServiceProvider
                .GetRequiredService<RoleManager<ApplicationRole>>();
            var administrator = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"last-admin-{Guid.NewGuid():N}",
                TestDataSeeder.DefaultPassword);
            await TestDataSeeder.AddToRoleAsync(
                roleManager,
                userManager,
                administrator,
                "administrator");
            administratorId = administrator.Id;
        }

        var client = factory.CreateClient();
        using var response = await client.PutAsJsonAsync(
            $"/api/users/{administratorId}/permissions/roles",
            new SetManagementUserRoleCommand(
                Role: "administrator",
                Assigned: false));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);

        await using var verification = factory.Services.CreateAsyncScope();
        var userManagerAfter = verification.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var persisted = await userManagerAfter.FindByIdAsync(administratorId);
        Assert.NotNull(persisted);
        Assert.True(await userManagerAfter.IsInRoleAsync(
            persisted,
            "administrator"));
    }

    [Fact]
    public async Task Manager_delegates_only_an_exact_permission_held_in_context()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var contextualFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IManagementEntitlementResolver>();
                services.AddScoped<
                    IManagementEntitlementResolver,
                    SufficitDirectiveManagementEntitlementResolver>();
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddScoped<
                    IManagementAuthorizationEvaluator,
                    RoleBasedManagementAuthorizationEvaluator>();
                services.RemoveAll<IManagementUserContextStore>();
                services.AddScoped<
                    IManagementUserContextStore,
                    SufficitDirectiveUserContextStore>();
                services.RemoveAll<IManagementContextualPermissionStore>();
                services.AddScoped<
                    IManagementContextualPermissionStore,
                    SufficitDirectiveUserPermissionStore>();
            }));
        _ = contextualFactory.CreateClient();

        await using var scope =
            contextualFactory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var operatorUser = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"manager-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            $"phonecalls:{FirstContext}");
        var catalogUser = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"catalog-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            $"clientadmin:{FirstContext}");
        var target = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"permission-target-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword);
        Assert.True((await userManager.AddClaimAsync(
            target,
            new Claim("management_context", FirstContext))).Succeeded);
        var originalSecurityStamp = target.SecurityStamp;
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, operatorUser.Id),
                new Claim(ClaimTypes.Role, "manager"),
                new Claim("directive", $"phonecalls:{FirstContext}")
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
        var requestContext = new ManagementRequestContext(
            principal,
            $"permission-test-{Guid.NewGuid():N}");
        var service = scope.ServiceProvider
            .GetRequiredService<IUserPermissionManagementService>();

        var denied = await Assert.ThrowsAsync<ManagementAccessException>(
            () => service.SetContextualPermissionAsync(
                target.Id,
                new SetManagementUserContextualPermissionCommand(
                    "clientadmin",
                    FirstContext,
                    Assigned: true),
                requestContext));
        Assert.Equal(
            "contextual_permission_not_delegable",
            denied.Decision.ReasonCode);

        var updated = await service.SetContextualPermissionAsync(
            target.Id,
            new SetManagementUserContextualPermissionCommand(
                "phonecalls",
                FirstContext,
                Assigned: true),
            requestContext);

        Assert.Contains(
            updated.ContextualPermissions,
            permission =>
                permission.Key == "phonecalls"
                && permission.IsAssigned);
        var persisted = await userManager.FindByIdAsync(target.Id);
        Assert.NotNull(persisted);
        var claims = await userManager.GetClaimsAsync(persisted);
        Assert.Contains(
            claims,
            claim =>
                claim.Type == "directive"
                && claim.Value == $"phonecalls:{FirstContext}");
        Assert.DoesNotContain(
            claims,
            claim =>
                claim.Type == "directive"
                && claim.Value == $"clientadmin:{FirstContext}");
        Assert.NotEqual(originalSecurityStamp, persisted.SecurityStamp);

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.True(await database.ManagementAuditEvents.AnyAsync(entry =>
            entry.ResourceId
                == $"{target.Id}/contextual/phonecalls"
            && entry.ContextId == FirstContext
            && entry.ReasonCode
                == "user_contextual_permission_added"));

        GC.KeepAlive(catalogUser);
    }

    [Fact]
    public async Task Sufficit_store_removes_one_value_from_array_claim()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"array-permissions-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            $"[\"clientadmin:{FirstContext}\",\"phonecalls:{SecondContext}\"]");
        var store = new SufficitDirectiveUserPermissionStore(
            scope.ServiceProvider.GetRequiredService<AppDbContext>(),
            userManager);

        await store.SetAsync(
            user.Id,
            "clientadmin",
            FirstContext,
            assigned: false);

        var persisted = await userManager.FindByIdAsync(user.Id);
        Assert.NotNull(persisted);
        var claims = await userManager.GetClaimsAsync(persisted);
        var directive = Assert.Single(
            claims,
            claim => claim.Type == "directive");
        Assert.DoesNotContain(
            $"clientadmin:{FirstContext}",
            directive.Value,
            StringComparison.Ordinal);
        Assert.Contains(
            $"phonecalls:{SecondContext}",
            directive.Value,
            StringComparison.Ordinal);
    }
}
