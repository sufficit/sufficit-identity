using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
