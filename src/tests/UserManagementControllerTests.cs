using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
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
            scope.ServiceProvider.GetRequiredService<AppDbContext>(),
            userManager,
            scope.ServiceProvider.GetRequiredService<
                IOptions<ManagementOptions>>());

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
    public async Task Create_and_reset_use_neutral_context_membership_and_never_return_secrets()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var contextualFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IManagementUserContextStore>();
                services.AddScoped<
                    IManagementUserContextStore,
                    SufficitDirectiveUserContextStore>();
            }));
        var client = contextualFactory.CreateClient();
        var userName = $"created-{Guid.NewGuid():N}";
        const string initialPassword = "Initial!Passw0rd#42";
        const string replacementPassword = "Replacement!Passw0rd#84";

        using var createdResponse = await client.PostAsJsonAsync(
            "/api/users",
            new CreateManagementUserCommand(
                userName,
                $"{userName}@tests.local",
                initialPassword,
                FirstContext));
        var createdJson = await createdResponse.Content.ReadAsStringAsync();
        var created = await createdResponse.Content
            .ReadFromJsonAsync<ManagementUserDetail>();

        Assert.Equal(HttpStatusCode.OK, createdResponse.StatusCode);
        Assert.NotNull(created);
        Assert.Contains(FirstContext, created.ContextIds);
        Assert.True(created.Actions.CanResetPassword);
        Assert.DoesNotContain(
            initialPassword,
            createdJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "passwordHash",
            createdJson,
            StringComparison.OrdinalIgnoreCase);

        using var resetResponse = await client.PostAsJsonAsync(
            $"/api/users/{created.Id}/reset-password",
            new ResetManagementUserPasswordCommand(replacementPassword));
        var resetJson = await resetResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, resetResponse.StatusCode);
        Assert.DoesNotContain(
            replacementPassword,
            resetJson,
            StringComparison.Ordinal);

        await using var scope = contextualFactory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var persisted = await userManager.FindByIdAsync(created.Id);
        Assert.NotNull(persisted);
        Assert.True(await userManager.CheckPasswordAsync(
            persisted,
            replacementPassword));
        var claims = await userManager.GetClaimsAsync(persisted);
        Assert.Contains(
            claims,
            claim =>
                claim.Type == "management_context"
                && claim.Value == FirstContext);
        Assert.DoesNotContain(
            claims,
            claim => claim.Type == TestDataSeeder.DirectiveClaimType);

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == created.Id)
            .ToArrayAsync();
        Assert.Contains(
            audit,
            entry =>
                entry.Capability == ManagementCapabilities.UsersCreate
                && entry.ReasonCode == "user_created");
        Assert.Contains(
            audit,
            entry =>
                entry.Capability
                    == ManagementCapabilities.UsersResetPassword
                && entry.ReasonCode == "user_password_reset");
    }

    [Fact]
    public async Task Invalid_initial_password_is_rejected_without_persisting_user()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var contextualFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IManagementUserContextStore>();
                services.AddScoped<
                    IManagementUserContextStore,
                    SufficitDirectiveUserContextStore>();
            }));
        var client = contextualFactory.CreateClient();
        var userName = $"invalid-{Guid.NewGuid():N}";

        using var response = await client.PostAsJsonAsync(
            "/api/users",
            new CreateManagementUserCommand(
                userName,
                $"{userName}@tests.local",
                "weak",
                FirstContext));
        var problem = await response.Content
            .ReadFromJsonAsync<Dictionary<string, object>>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.NotNull(problem);
        Assert.Contains(
            "user_password_invalid",
            problem["reasonCode"].ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            "initialPassword",
            problem["field"].ToString(),
            StringComparison.Ordinal);

        await using var scope = contextualFactory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        Assert.Null(await userManager.FindByNameAsync(userName));
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.Contains(
            await database.ManagementAuditEvents.ToArrayAsync(),
            entry =>
                entry.Capability == ManagementCapabilities.UsersCreate
                && entry.OperationOutcome == "failed"
                && entry.ReasonCode == "user_password_invalid");
    }

    [Fact]
    public async Task Manager_must_control_every_target_context_to_reset_password()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var contextualFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IManagementUserContextStore>();
                services.AddScoped<
                    IManagementUserContextStore,
                    SufficitDirectiveUserContextStore>();
                services.RemoveAll<IManagementEntitlementResolver>();
                services.AddScoped<
                    IManagementEntitlementResolver,
                    SufficitDirectiveManagementEntitlementResolver>();
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddScoped<
                    IManagementAuthorizationEvaluator,
                    RoleBasedManagementAuthorizationEvaluator>();
            }));

        string targetId;
        const string originalPassword = "Original!Passw0rd#1";
        await using (var setup = contextualFactory.Services.CreateAsyncScope())
        {
            var setupUserManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                setupUserManager,
                $"multi-{Guid.NewGuid():N}",
                originalPassword,
                $"[\"phonecalls:{FirstContext}\","
                + $"\"phonecalls:{SecondContext}\"]");
            targetId = target.Id;
        }

        await using var scope = contextualFactory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var onlyFirstContext = RequestContext(
            "manager",
            new Claim("directive", $"phonecalls:{FirstContext}"));
        var bothContexts = RequestContext(
            "manager",
            new Claim(
                "directive",
                $"[\"phonecalls:{FirstContext}\","
                + $"\"phonecalls:{SecondContext}\"]"));

        var denied = await Assert.ThrowsAsync<ManagementAccessException>(
            () => service.ResetPasswordAsync(
                targetId,
                new ResetManagementUserPasswordCommand(
                    "Denied!Passw0rd#2"),
                onlyFirstContext));
        Assert.Equal(
            "user_context_scope_incomplete",
            denied.Decision.ReasonCode);

        var updated = await service.ResetPasswordAsync(
            targetId,
            new ResetManagementUserPasswordCommand(
                "Allowed!Passw0rd#3"),
            bothContexts);
        Assert.Equal(targetId, updated.Id);

        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var persisted = await userManager.FindByIdAsync(targetId);
        Assert.NotNull(persisted);
        Assert.False(await userManager.CheckPasswordAsync(
            persisted,
            originalPassword));
        Assert.True(await userManager.CheckPasswordAsync(
            persisted,
            "Allowed!Passw0rd#3"));
    }

    [Fact]
    public async Task Global_target_membership_requires_administrator_for_password_reset()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var contextualFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IManagementUserContextStore>();
                services.AddScoped<
                    IManagementUserContextStore,
                    SufficitDirectiveUserContextStore>();
                services.RemoveAll<IManagementEntitlementResolver>();
                services.AddScoped<
                    IManagementEntitlementResolver,
                    SufficitDirectiveManagementEntitlementResolver>();
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddScoped<
                    IManagementAuthorizationEvaluator,
                    RoleBasedManagementAuthorizationEvaluator>();
            }));

        string targetId;
        await using (var setup = contextualFactory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"global-{Guid.NewGuid():N}",
                "Original!Passw0rd#4",
                "phonecalls:00000000-0000-0000-0000-000000000000");
            targetId = target.Id;
        }

        await using var scope = contextualFactory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var denied = await Assert.ThrowsAsync<ManagementAccessException>(
            () => service.ResetPasswordAsync(
                targetId,
                new ResetManagementUserPasswordCommand(
                    "Denied!Passw0rd#5"),
                RequestContext(
                    "manager",
                    new Claim(
                        "directive",
                        $"phonecalls:{FirstContext}"))));
        Assert.Equal(
            "user_scope_requires_administrator",
            denied.Decision.ReasonCode);

        var result = await service.ResetPasswordAsync(
            targetId,
            new ResetManagementUserPasswordCommand(
                "Admin!Passw0rd#6"),
            RequestContext("administrator"));
        Assert.Equal(targetId, result.Id);
    }

    [Fact]
    public async Task Tenant_mfa_policy_applies_to_contextual_password_reset()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var contextualFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.Configure<ManagementOptions>(management =>
                    management.Authorization.Contexts[FirstContext] =
                        new ManagementContextAccessPolicyOptions
                        {
                            RequireMfa = true
                        });
                services.RemoveAll<IManagementUserContextStore>();
                services.AddScoped<
                    IManagementUserContextStore,
                    SufficitDirectiveUserContextStore>();
                services.RemoveAll<IManagementEntitlementResolver>();
                services.AddScoped<
                    IManagementEntitlementResolver,
                    SufficitDirectiveManagementEntitlementResolver>();
                services.RemoveAll<IManagementAuthorizationEvaluator>();
                services.AddScoped<
                    IManagementAuthorizationEvaluator,
                    RoleBasedManagementAuthorizationEvaluator>();
            }));

        string targetId;
        await using (var setup = contextualFactory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"mfa-{Guid.NewGuid():N}",
                "Original!Passw0rd#7",
                $"phonecalls:{FirstContext}");
            targetId = target.Id;
        }

        await using var scope = contextualFactory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var withoutMfa = await Assert.ThrowsAsync<ManagementAccessException>(
            () => service.ResetPasswordAsync(
                targetId,
                new ResetManagementUserPasswordCommand(
                    "Denied!Passw0rd#8"),
                RequestContext(
                    "manager",
                    new Claim(
                        "directive",
                        $"phonecalls:{FirstContext}"))));
        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            withoutMfa.Decision.Outcome);

        var updated = await service.ResetPasswordAsync(
            targetId,
            new ResetManagementUserPasswordCommand(
                "Allowed!Passw0rd#9"),
            RequestContext(
                "manager",
                new Claim(
                    "directive",
                    $"phonecalls:{FirstContext}"),
                new Claim("amr", "pwd mfa")));
        Assert.Equal(targetId, updated.Id);
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
        public Task<IReadOnlySet<string>> ListKnownContextIdsAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlySet<string>>(
                new HashSet<string>(
                    [contextId],
                    StringComparer.OrdinalIgnoreCase));

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

        public async Task<ManagementUserMembership> GetMembershipAsync(
            string requestedUserId,
            CancellationToken cancellationToken = default) =>
            new(
                await ListContextIdsAsync(
                    requestedUserId,
                    cancellationToken),
                RequiresAdministrator: false);

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

        public Task AddToContextAsync(
            string requestedUserId,
            string requestedContextId,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private static ManagementRequestContext RequestContext(
        string role,
        params Claim[] claims) =>
        new(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    [
                        new Claim(
                            ClaimTypes.NameIdentifier,
                            $"operator-{role}"),
                        new Claim(ClaimTypes.Role, role),
                        .. claims
                    ],
                    "test",
                    ClaimTypes.Name,
                    ClaimTypes.Role)),
            $"test-{Guid.NewGuid():N}");
}
