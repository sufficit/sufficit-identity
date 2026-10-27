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
        // Its origin outlives the default audit retention.
        var origin = await database.ManagementAuditEvents.AsNoTracking()
            .SingleAsync(audit => audit.ResourceId == userId && audit.ReasonCode == "system_user_created");
        Assert.Equal(Sufficit.Identity.Core.Entities.ManagementAuditRetention.Never, origin.ExpiresAtUtc);
        Assert.Equal(origin.OperatorSubject, users.EnumerateArray().Single().GetProperty("createdBy").GetString());
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
            var person = new ApplicationUser { UserName = "a-person", Email = "a-person@example.test" };
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
            (await entitled.Content.ReadFromJsonAsync<string[]>())!);
        using var narrowed = await provisioner.PutAsJsonAsync($"/api/system-users/entitlements?userId={agent}",
            new { entitlements = new[] { "aiuser:01a05f00000070008000000000000001" } });
        Assert.Equal(["aiuser:01a05f00000070008000000000000001"], (await narrowed.Content.ReadFromJsonAsync<string[]>())!);
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

    [Fact]
    public async Task Canonical_and_legacy_routes_both_serve_system_users()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var operatorClient = factory.CreateClient();

        using var created = await operatorClient.PostAsJsonAsync(
            "/api/users/system", new { userName = "agent-canonical-route" });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var userId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("userId").GetString()!;

        // GET api/users/system is the system-users list, not a user named "system".
        foreach (var route in new[] { "/api/users/system", "/api/system-users" })
        {
            using var listed = await operatorClient.GetAsync(route);
            Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
            var body = await listed.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(JsonValueKind.Array, body.ValueKind);
            Assert.Equal(userId, Assert.Single(body.EnumerateArray()).GetProperty("userId").GetString());
        }

        // The users API itself still answers under api/users.
        using var person = await operatorClient.GetAsync($"/api/users/{userId}");
        Assert.Equal(HttpStatusCode.OK, person.StatusCode);

        // Entitlements live only on the legacy route.
        using var legacyEntitlements = await operatorClient.GetAsync($"/api/system-users/entitlements?userId={userId}");
        Assert.Equal(HttpStatusCode.OK, legacyEntitlements.StatusCode);
        using var canonicalEntitlements = await operatorClient.GetAsync($"/api/users/system/entitlements?userId={userId}");
        Assert.NotEqual(HttpStatusCode.OK, canonicalEntitlements.StatusCode);
    }

    [Fact]
    public async Task Users_system_capability_works_on_the_canonical_route()
    {
        using var root = new ManagementTestFactory();
        await ((IAsyncLifetime)root).InitializeAsync();
        await RegisterAgentClientAsync(root);
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddSingleton<IManagementAuthorizationEvaluator, OnlySystemUsersEvaluator>()));
        var provisioner = factory.CreateClient();

        var agent = Guid.CreateVersion7();
        using var created = await provisioner.PostAsJsonAsync(
            "/api/users/system", new { userName = "agent-canonical", userId = agent });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);

        using var issued = await provisioner.PostAsJsonAsync(
            $"/api/users/system/enrollments?userId={agent}", new { clientId = AgentClientId, label = "executor" });
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var enrollments = await provisioner.GetFromJsonAsync<JsonElement>($"/api/users/system/enrollments?userId={agent}");
        Assert.Single(enrollments.EnumerateArray());

        using var disabled = await provisioner.PatchAsync($"/api/users/system/toggle?userId={agent}&enabled=false", null);
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        var listed = await provisioner.GetFromJsonAsync<JsonElement>("/api/users/system");
        Assert.True(Assert.Single(listed.EnumerateArray()).GetProperty("disabled").GetBoolean());

        // Still nothing beyond system users.
        using var users = await provisioner.GetAsync("/api/users");
        Assert.Equal(HttpStatusCode.Forbidden, users.StatusCode);
    }

    [Fact]
    public async Task Claims_system_capability_manages_claims_of_system_users_and_never_of_a_person()
    {
        using var root = new ManagementTestFactory();
        await ((IAsyncLifetime)root).InitializeAsync();
        using var factory = root.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddSingleton<IManagementAuthorizationEvaluator, OnlySystemClaimsEvaluator>()));
        var provisioner = factory.CreateClient();

        string human, agent;
        int personClaimId;
        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var person = new ApplicationUser { UserName = "claims-person", Email = "claims-person@example.test" };
            Assert.True((await userManager.CreateAsync(person)).Succeeded);
            human = person.Id;
            Assert.True((await userManager.AddClaimAsync(person, new System.Security.Claims.Claim("entitlements", "seeded"))).Succeeded);
            var system = new ApplicationUser { UserName = "claims-agent" };
            Assert.True((await userManager.CreateAsync(system)).Succeeded);
            agent = system.Id;
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            personClaimId = (await database.UserClaims.SingleAsync(x => x.UserId == human && x.ClaimType == "entitlements")).Id;
        }

        // A system user's claims: create, read, delete.
        using var created = await provisioner.PostAsJsonAsync(
            "/api/claims", new { userId = agent, type = "entitlements", value = "aiuser" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var claimId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetInt32();
        var page = await provisioner.GetFromJsonAsync<JsonElement>($"/api/claims?userId={agent}");
        Assert.Equal(claimId, Assert.Single(page.GetProperty("items").EnumerateArray()).GetProperty("id").GetInt32());
        using var read = await provisioner.GetAsync($"/api/claims/{claimId}");
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);

        // The unfiltered listing never shows a person's claim.
        var all = await provisioner.GetFromJsonAsync<JsonElement>("/api/claims");
        Assert.DoesNotContain(all.GetProperty("items").EnumerateArray(), item => item.GetProperty("userId").GetString() == human);

        // Reserved claim types still apply.
        using var reserved = await provisioner.PostAsJsonAsync(
            "/api/claims", new { userId = agent, type = "permission", value = "identity.users.read" });
        Assert.Equal(HttpStatusCode.BadRequest, reserved.StatusCode);

        // A person is refused on every path, and the mutations are audited.
        using var onPerson = await provisioner.PostAsJsonAsync(
            "/api/claims", new { userId = human, type = "entitlements", value = "administrator" });
        Assert.Equal(HttpStatusCode.Forbidden, onPerson.StatusCode);
        using var deletePersonClaim = await provisioner.DeleteAsync($"/api/claims/{personClaimId}");
        Assert.Equal(HttpStatusCode.Forbidden, deletePersonClaim.StatusCode);
        using var updatePersonClaim = await provisioner.PutAsJsonAsync(
            $"/api/claims/{personClaimId}", new { type = "entitlements", value = "administrator" });
        Assert.Equal(HttpStatusCode.Forbidden, updatePersonClaim.StatusCode);
        using var readPersonClaim = await provisioner.GetAsync($"/api/claims/{personClaimId}");
        Assert.Equal(HttpStatusCode.Forbidden, readPersonClaim.StatusCode);
        using var listPersonClaims = await provisioner.GetAsync($"/api/claims?userId={human}");
        Assert.Equal(HttpStatusCode.Forbidden, listPersonClaims.StatusCode);

        using var deleted = await provisioner.DeleteAsync($"/api/claims/{claimId}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        using (var scope = factory.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            Assert.False(await database.UserClaims.AnyAsync(x => x.UserId == agent));
            Assert.True(await database.UserClaims.AnyAsync(x => x.Id == personClaimId && x.ClaimValue == "seeded"));
            var refusals = await database.ManagementAuditEvents.AsNoTracking()
                .Where(audit => audit.ReasonCode == "claim_owner_not_system_user")
                .Select(audit => audit.Capability)
                .ToListAsync();
            Assert.Contains(ManagementCapabilities.ClaimsCreate, refusals);
            Assert.Contains(ManagementCapabilities.ClaimsDelete, refusals);
            Assert.Contains(ManagementCapabilities.ClaimsUpdate, refusals);
            Assert.DoesNotContain(ManagementCapabilities.ClaimsRead, refusals);
        }
    }

    private sealed class OnlySystemClaimsEvaluator : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            System.Security.Claims.ClaimsPrincipal principal, string capability, ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(capability == ManagementCapabilities.ClaimsSystem
                ? ManagementAuthorizationDecision.Allowed()
                : ManagementAuthorizationDecision.Denied("capability_missing", capability));
    }

    private sealed class OnlySystemUsersEvaluator : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            System.Security.Claims.ClaimsPrincipal principal, string capability, ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(capability == ManagementCapabilities.UsersSystem
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
