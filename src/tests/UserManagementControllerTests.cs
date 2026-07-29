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
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Server.Management;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class UserManagementControllerTests
{
    private const string FirstContext =
        "4082aef4-42d3-4b1b-a321-f405af935940";
    private const string SecondContext =
        "f96802a6-8d90-4143-a939-dd5258f3cfaa";

    [Fact]
    public async Task Global_list_and_detail_are_paged_redacted_and_audited()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var listed = await client.GetAsync(
            "/api/users?search=alice&page=1&pageSize=10");
        var page = await listed.Content.ReadFromJsonAsync<ManagementUserPage>();

        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.NotNull(page);
        var summary = Assert.Single(page.Items);
        Assert.Equal(TestDataSeeder.DefaultUsername, summary.UserName);

        using var detailResponse = await client.GetAsync(
            $"/api/users/{summary.Id}");
        var detailJson = await detailResponse.Content.ReadAsStringAsync();
        var detail = await detailResponse.Content
            .ReadFromJsonAsync<ManagementUserDetail>();

        Assert.Equal(HttpStatusCode.OK, detailResponse.StatusCode);
        Assert.NotNull(detail);
        Assert.DoesNotContain("passwordHash", detailJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("securityStamp", detailJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("concurrencyStamp", detailJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("claim", detailJson, StringComparison.OrdinalIgnoreCase);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var events = await database.ManagementAuditEvents
            .Where(entry =>
                entry.Capability == "identity.users.read"
                && entry.ResourceId == summary.Id)
            .ToArrayAsync();
        Assert.Contains(events, entry => entry.ReasonCode == "user_read");
    }

    [Fact]
    public async Task Sufficit_context_store_matches_exact_scalar_and_array_claims()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var scalar = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"scalar-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            $"phonecalls:{FirstContext}");
        var array = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"array-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            $"[\"clientadmin:{FirstContext}\",\"phonecalls:{SecondContext}\"]");
        var other = await TestDataSeeder.CreateUserAsync(
            userManager,
            $"other-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            $"phonecalls:{SecondContext}");
        var store = new SufficitDirectiveUserContextStore(
            scope.ServiceProvider.GetRequiredService<AppDbContext>());

        var firstUsers = await store.ListUserIdsAsync(FirstContext);
        var arrayContexts = await store.ListContextIdsAsync(array.Id);

        Assert.Contains(scalar.Id, firstUsers);
        Assert.Contains(array.Id, firstUsers);
        Assert.DoesNotContain(other.Id, firstUsers);
        Assert.Equal(
            new[] { FirstContext, SecondContext },
            arrayContexts.Order(StringComparer.Ordinal));
        Assert.True(await store.UserBelongsToAsync(scalar.Id, FirstContext));
        Assert.False(await store.UserBelongsToAsync(scalar.Id, SecondContext));
    }

    [Fact]
    public async Task Context_list_never_returns_users_outside_resolved_scope()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string visibleUserId;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var visible = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"visible-{Guid.NewGuid():N}",
                TestDataSeeder.DefaultPassword);
            _ = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"hidden-{Guid.NewGuid():N}",
                TestDataSeeder.DefaultPassword);
            visibleUserId = visible.Id;
        }

        using var scopedFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IManagementUserContextStore>();
                services.AddSingleton<IManagementUserContextStore>(
                    new FixedUserContextStore(visibleUserId, FirstContext));
            }));
        var client = scopedFactory.CreateClient();

        var page = await client.GetFromJsonAsync<ManagementUserPage>(
            $"/api/users?contextId={FirstContext}&pageSize=100");

        Assert.NotNull(page);
        var user = Assert.Single(page.Items);
        Assert.Equal(visibleUserId, user.Id);
        Assert.Equal(FirstContext, page.ContextId);
    }

    private sealed class FixedUserContextStore(
        string userId,
        string contextId) : IManagementUserContextStore
    {
        public Task<IReadOnlySet<string>> ListUserIdsAsync(
            string requestedContextId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlySet<string>>(
                string.Equals(
                    contextId,
                    requestedContextId,
                    StringComparison.OrdinalIgnoreCase)
                    ? new HashSet<string>([userId], StringComparer.Ordinal)
                    : new HashSet<string>(StringComparer.Ordinal));

        public Task<IReadOnlySet<string>> ListContextIdsAsync(
            string requestedUserId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlySet<string>>(
                string.Equals(userId, requestedUserId, StringComparison.Ordinal)
                    ? new HashSet<string>(
                        [contextId],
                        StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase));

        public Task<bool> UserBelongsToAsync(
            string requestedUserId,
            string requestedContextId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(
                string.Equals(
                    userId,
                    requestedUserId,
                    StringComparison.Ordinal)
                && string.Equals(
                    contextId,
                    requestedContextId,
                    StringComparison.OrdinalIgnoreCase));
    }
}
