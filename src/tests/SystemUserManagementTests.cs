using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.SystemUsers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// System users through the management API: created without any sign-in
/// credential, enrolled with a one-time code the client redeems itself,
/// disabled with every credential revoked, all audited.
/// </summary>
public sealed class SystemUserManagementTests
{
    private const string AgentClientId = "mgmt-system-agent";

    [Fact]
    public async Task Operator_creates_enrolls_disables_and_the_audit_records_it()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await RegisterAgentClientAsync(factory);
        var operatorClient = factory.CreateClient();

        using var created = await operatorClient.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-github-engineer", displayName = "GitHub engineer" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var system = await created.Content.ReadFromJsonAsync<JsonElement>();
        var userId = system.GetProperty("userId").GetString()!;
        Assert.Equal("GitHub engineer", system.GetProperty("displayName").GetString());
        Assert.False(system.GetProperty("disabled").GetBoolean());

        using var duplicate = await operatorClient.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-github-engineer" });
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);

        using var unknownClient = await operatorClient.PostAsJsonAsync(
            $"/api/system-users/enrollments?userId={userId}", new { clientId = "no-such-client", label = "pod" });
        Assert.Equal(HttpStatusCode.BadRequest, unknownClient.StatusCode);

        using var issued = await operatorClient.PostAsJsonAsync(
            $"/api/system-users/enrollments?userId={userId}", new { clientId = AgentClientId, label = "pod github-engineer" });
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var issueBody = await issued.Content.ReadFromJsonAsync<JsonElement>();
        var code = issueBody.GetProperty("code").GetString()!;
        Assert.StartsWith("sys_enroll_", code, StringComparison.Ordinal);
        Assert.Equal(SystemUserEnrollmentProtocol.GrantType, issueBody.GetProperty("grantType").GetString());

        // The client redeems the code itself; the operator never sees the credential.
        var agent = factory.CreateClient();
        var (status, tokens) = await agent.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = SystemUserEnrollmentProtocol.GrantType,
            [SystemUserEnrollmentProtocol.CodeParameter] = code,
            ["client_id"] = AgentClientId,
        });
        Assert.True(status == HttpStatusCode.OK, tokens.ToString());
        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var listed = await operatorClient.GetFromJsonAsync<JsonElement>(
            $"/api/system-users/enrollments?userId={userId}");
        var enrollment = Assert.Single(listed.EnumerateArray());
        Assert.Equal(SystemUserEnrollmentStatus.Active, enrollment.GetProperty("status").GetString());
        Assert.DoesNotContain(code, listed.GetRawText(), StringComparison.Ordinal);
        var users = await operatorClient.GetFromJsonAsync<JsonElement>("/api/system-users");
        Assert.Equal(1, Assert.Single(users.EnumerateArray()).GetProperty("activeCredentials").GetInt32());

        // Disabling revokes the credential.
        using var disabled = await operatorClient.PatchAsync(
            $"/api/system-users/toggle?userId={userId}&enabled=false", null);
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        Assert.True((await disabled.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("disabled").GetBoolean());
        var (refreshStatus, _) = await agent.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refresh,
            ["client_id"] = AgentClientId,
        });
        Assert.Equal(HttpStatusCode.BadRequest, refreshStatus);

        // A disabled system user gets no new code; toggling without a value re-enables.
        using var whileDisabled = await operatorClient.PostAsJsonAsync(
            $"/api/system-users/enrollments?userId={userId}", new { clientId = AgentClientId, label = "pod" });
        Assert.Equal(HttpStatusCode.Conflict, whileDisabled.StatusCode);
        using var reenabled = await operatorClient.PatchAsync($"/api/system-users/toggle?userId={userId}", null);
        Assert.False((await reenabled.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("disabled").GetBoolean());

        // A pending code can be revoked before use.
        using var second = await operatorClient.PostAsJsonAsync(
            $"/api/system-users/enrollments?userId={userId}", new { clientId = AgentClientId, label = "pod 2" });
        var secondBody = await second.Content.ReadFromJsonAsync<JsonElement>();
        var secondId = secondBody.GetProperty("enrollment").GetProperty("id").GetString();
        using var revoked = await operatorClient.DeleteAsync(
            $"/api/system-users/enrollments?userId={userId}&id={secondId}");
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
        var (revokedRedeem, _) = await agent.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = SystemUserEnrollmentProtocol.GrantType,
            [SystemUserEnrollmentProtocol.CodeParameter] = secondBody.GetProperty("code").GetString()!,
            ["client_id"] = AgentClientId,
        });
        Assert.Equal(HttpStatusCode.BadRequest, revokedRedeem);

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var reasons = await database.ManagementAuditEvents.AsNoTracking()
            .Where(audit => audit.ResourceId == userId)
            .Select(audit => audit.ReasonCode)
            .ToListAsync();
        Assert.Contains("system_user_created", reasons);
        Assert.Equal(2, reasons.Count(reason => reason == "system_user_enrollment_issued"));
        Assert.Contains("system_user_disabled", reasons);
        Assert.Contains("system_user_enabled", reasons);
        Assert.Contains("system_user_enrollment_revoked", reasons);
        var marker = await database.SystemUsers.AsNoTracking().SingleAsync(x => x.UserId == userId);
        Assert.False(string.IsNullOrEmpty(marker.CreatedBy));
    }

    [Fact]
    public async Task Operator_can_create_a_system_user_with_a_chosen_id_once()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var operatorClient = factory.CreateClient();
        var id = Guid.CreateVersion7();

        using var created = await operatorClient.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-chosen-id", userId = id });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal(id.ToString("D"),
            (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("userId").GetString());

        // The same ID under another name is refused: an existing account is never adopted.
        using var taken = await operatorClient.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-other-name", userId = id });
        Assert.Equal(HttpStatusCode.Conflict, taken.StatusCode);

        using var empty = await operatorClient.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-empty-id", userId = Guid.Empty });
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);
    }

    [Fact]
    public async Task A_provisioner_with_only_the_system_users_capability_never_reaches_a_person()
    {
        using var root = new ManagementTestFactory();
        await ((IAsyncLifetime)root).InitializeAsync();
        await RegisterAgentClientAsync(root);
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddSingleton<IManagementAuthorizationEvaluator, OnlySystemUsersEvaluator>()));
        var provisioner = factory.CreateClient();

        string human;
        using (var scope = factory.Services.CreateScope())
        {
            var person = new ApplicationUser { UserName = "a-person" };
            Assert.True((await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().CreateAsync(person)).Succeeded);
            human = person.Id;
        }

        var agent = Guid.CreateVersion7();
        using var created = await provisioner.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-provisioned", userId = agent });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);

        // Entitlements: replaced as a set, contexts stored compact.
        using var entitled = await provisioner.PutAsJsonAsync($"/api/system-users/entitlements?userId={agent}",
            new { entitlements = new[] { "aiuser:01a05f00-0000-7000-8000-000000000001", "AIUSER:01a05f0000007000800000000000000a" } });
        Assert.Equal(HttpStatusCode.OK, entitled.StatusCode);
        Assert.Equal(["aiuser:01a05f00000070008000000000000001", "aiuser:01a05f0000007000800000000000000a"],
            await entitled.Content.ReadFromJsonAsync<string[]>());
        using var narrowed = await provisioner.PutAsJsonAsync($"/api/system-users/entitlements?userId={agent}",
            new { entitlements = new[] { "aiuser:01a05f00000070008000000000000001" } });
        Assert.Equal(["aiuser:01a05f00000070008000000000000001"], await narrowed.Content.ReadFromJsonAsync<string[]>());
        using var invalid = await provisioner.PutAsJsonAsync($"/api/system-users/entitlements?userId={agent}",
            new { entitlements = new[] { "not a key:x" } });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        using var issued = await provisioner.PostAsJsonAsync(
            $"/api/system-users/enrollments?userId={agent}", new { clientId = AgentClientId, label = "executor" });
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);

        // A person is out of reach: not a system user here, and the general users API refuses.
        using var onPerson = await provisioner.PutAsJsonAsync($"/api/system-users/entitlements?userId={human}",
            new { entitlements = new[] { "administrator" } });
        Assert.Equal(HttpStatusCode.NotFound, onPerson.StatusCode);
        using var codeForPerson = await provisioner.PostAsJsonAsync(
            $"/api/system-users/enrollments?userId={human}", new { clientId = AgentClientId, label = "x" });
        Assert.Equal(HttpStatusCode.NotFound, codeForPerson.StatusCode);
        using var users = await provisioner.GetAsync("/api/users");
        Assert.Equal(HttpStatusCode.Forbidden, users.StatusCode);
        using var adoptPerson = await provisioner.PostAsJsonAsync(
            "/api/system-users", new { userName = "agent-adopt", userId = Guid.Parse(human) });
        Assert.Equal(HttpStatusCode.Conflict, adoptPerson.StatusCode);
    }

    private sealed class OnlySystemUsersEvaluator : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            System.Security.Claims.ClaimsPrincipal principal, string capability, ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(capability == ManagementCapabilities.SystemUsersManage
                ? ManagementAuthorizationDecision.Allowed()
                : ManagementAuthorizationDecision.Denied("capability_missing", capability));
    }

    private static async Task RegisterAgentClientAsync(ManagementTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = AgentClientId,
            ClientType = ClientTypes.Public,
            DisplayName = "Headless agent",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.RefreshToken,
                Permissions.Prefixes.GrantType + SystemUserEnrollmentProtocol.GrantType,
            },
        });
    }
}
