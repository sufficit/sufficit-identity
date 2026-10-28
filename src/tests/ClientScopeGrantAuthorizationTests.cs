using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.STS.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Plan A2: one operator-aware scope-grant decision for every client entry
/// point. The reserved floor is never bypassable; a deployment-defined
/// privileged scope needs its capability, held by the operator.
/// </summary>
public sealed class ClientScopeGrantAuthorizationTests
{
    private const string PrivilegedScope = "reports.admin";
    private const string MappedScope = "ledger.write";

    private static ClientScopeGrantAuthorization Decision(
        ClientDefinitionRolloutMode mode = ClientDefinitionRolloutMode.Enforce) =>
        new(
            new ReservedScopePolicy(["identity.management", "scim"]),
            new ClientScopeGrantOptions
            {
                Mode = mode,
                PrivilegedScopes =
                [
                    new() { Scope = PrivilegedScope },
                    new() { Scope = MappedScope, Capability = ManagementCapabilities.SecretsManage },
                ],
            });

    private static ClientScopeGrantOperator Holding(params string[] capabilities) =>
        new("operator-1", capabilities.ToHashSet(StringComparer.Ordinal));

    private static ClientScopeGrantRequest Request(
        ClientScopeGrantOperator grantOperator,
        string[] scopes,
        string[]? current = null,
        ClientDefinitionSource source = ClientDefinitionSource.Management) =>
        new(source, grantOperator, "target-client",
            [Permissions.GrantTypes.ClientCredentials], scopes, current);

    [Fact]
    public void Reserved_floor_is_refused_in_observe_and_to_an_operator_holding_everything()
    {
        var decision = Decision(ClientDefinitionRolloutMode.Observe).Decide(
            Request(new("root", ManagementCapabilities.All), ["scp:identity.management"]));

        Assert.False(decision.IsAllowed);
        var denial = Assert.Single(decision.Denials);
        Assert.Equal("identity.management", denial.Scope);
        Assert.Equal(ClientScopeGrantReasonCodes.ScopeReserved, denial.ReasonCode);
        Assert.True(denial.Enforced);
    }

    [Fact]
    public void Privileged_scope_needs_the_default_grant_capability()
    {
        var refused = Decision().Decide(Request(
            Holding(ManagementCapabilities.ClientsCreate), [PrivilegedScope, "openid"]));
        Assert.False(refused.IsAllowed);
        var denial = Assert.Single(refused.Denials);
        Assert.Equal(ClientScopeGrantReasonCodes.CapabilityMissing, denial.ReasonCode);
        Assert.Equal(ManagementCapabilities.ScopesGrant, denial.RequiredCapability);
        Assert.Equal(["client_credentials"], refused.GrantTypes);

        var allowed = Decision().Decide(Request(
            Holding(ManagementCapabilities.ClientsCreate, ManagementCapabilities.ScopesGrant),
            [PrivilegedScope]));
        Assert.True(allowed.IsAllowed);
        Assert.Empty(allowed.Denials);
    }

    [Fact]
    public void Per_scope_capability_is_the_only_one_that_satisfies_it()
    {
        var refused = Decision().Decide(Request(
            Holding(ManagementCapabilities.ScopesGrant), [MappedScope]));
        Assert.Equal(
            ManagementCapabilities.SecretsManage,
            Assert.Single(refused.Denials).RequiredCapability);

        Assert.True(Decision().Decide(Request(
            Holding(ManagementCapabilities.SecretsManage), [MappedScope])).IsAllowed);
    }

    [Fact]
    public void Observe_records_the_denial_and_allows()
    {
        var decision = Decision(ClientDefinitionRolloutMode.Observe).Decide(
            Request(Holding(), [PrivilegedScope]));

        Assert.True(decision.IsAllowed);
        Assert.True(decision.HasObservedDenials);
        Assert.False(Assert.Single(decision.Denials).Enforced);
    }

    [Fact]
    public void Without_an_operator_nothing_privileged_can_be_granted()
    {
        var decision = Decision().Decide(Request(
            ClientScopeGrantOperator.None,
            [PrivilegedScope, "openid"],
            source: ClientDefinitionSource.DynamicRegistration));

        Assert.Equal(
            ClientScopeGrantReasonCodes.OperatorRequired,
            Assert.Single(decision.Denials).ReasonCode);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void Keeping_a_privileged_scope_is_not_an_expansion()
    {
        var kept = Decision().Decide(Request(
            Holding(ManagementCapabilities.ClientsUpdate),
            [PrivilegedScope, "openid"],
            current: ["scp:" + PrivilegedScope]));
        Assert.True(kept.IsAllowed);
        Assert.Empty(kept.Denials);

        var added = Decision().Decide(Request(
            Holding(ManagementCapabilities.ClientsUpdate),
            [PrivilegedScope, MappedScope],
            current: [PrivilegedScope]));
        Assert.Equal(MappedScope, Assert.Single(added.Denials).Scope);
    }

    [Fact]
    public void Options_refuse_a_capability_nobody_could_hold()
    {
        Assert.Throws<InvalidOperationException>(() => new ClientScopeGrantOptions
        {
            PrivilegedScopes = [new() { Scope = "x.y", Capability = "identity.anything.goes" }],
        }.ResolvePrivilegedScopes());
        Assert.Throws<InvalidOperationException>(() => new ClientScopeGrantOptions
        {
            PrivilegedScopes = [new() { Scope = "x.y" }, new() { Scope = "x.y" }],
        }.ResolvePrivilegedScopes());

        // A retired spelling is normalized like everywhere else.
        var resolved = new ClientScopeGrantOptions
        {
            PrivilegedScopes = [new() { Scope = "x.y", Capability = "identity.vault.secrets.manage" }],
        }.ResolvePrivilegedScopes();
        Assert.Equal(ManagementCapabilities.SecretsManage, resolved["x.y"]);
    }

    [Fact]
    public void Defaults_observe_and_declare_nothing_privileged()
    {
        var options = new ManagementOptions().ClientScopeGrants;
        Assert.Equal(ClientDefinitionRolloutMode.Observe, options.Mode);
        Assert.Empty(options.PrivilegedScopes);
        Assert.Contains(ManagementCapabilities.ScopesGrant, ManagementCapabilities.All);
    }

    [Fact]
    public void Posture_reports_observe_only_when_privileged_scopes_exist()
    {
        static IEnumerable<ProductionPostureFinding> Evaluate(
            ClientDefinitionRolloutMode mode, bool privileged) =>
            new ManagementProductionPostureContributor(Options.Create(new ManagementOptions
            {
                Enabled = true,
                ClientScopeGrants = new()
                {
                    Mode = mode,
                    PrivilegedScopes = privileged ? [new() { Scope = PrivilegedScope }] : [],
                },
            })).Evaluate();

        var finding = Assert.Single(
            Evaluate(ClientDefinitionRolloutMode.Observe, privileged: true),
            item => item.Id == "management-client-scope-grants-observe");
        Assert.Equal(ProductionPostureSeverity.Advisory, finding.Severity);
        Assert.DoesNotContain(
            Evaluate(ClientDefinitionRolloutMode.Observe, privileged: false),
            item => item.Id == "management-client-scope-grants-observe");
        Assert.DoesNotContain(
            Evaluate(ClientDefinitionRolloutMode.Enforce, privileged: true),
            item => item.Id == "management-client-scope-grants-observe");
    }

    // ---- Entry points ----

    private static Dictionary<string, string?> GrantConfiguration(string mode) => new()
    {
        ["Sufficit:Identity:Management:ClientScopeGrants:Mode"] = mode,
        ["Sufficit:Identity:Management:ClientScopeGrants:PrivilegedScopes:0:Scope"] = PrivilegedScope,
    };

    private static ManagementRequestContext Operator(params string[] capabilities) => new(
        new ClaimsPrincipal(new ClaimsIdentity(
            capabilities.Select(capability => new Claim("permission", capability))
                .Prepend(new Claim("sub", "scope-grant-operator")),
            "scope-grant-test")),
        $"scope-grant-{Guid.NewGuid():N}");

    private static CreateManagementClientCommand PublicClient(string clientId, params string[] scopes) =>
        new(clientId, null, "Scope grant fixture", null, false,
            [Permissions.GrantTypes.AuthorizationCode], scopes,
            ["https://client.example.invalid/callback"]);

    [Fact]
    public async Task Management_create_refuses_an_operator_without_the_capability_and_audits_it()
    {
        using var factory = new ManagementTestFactory(
            bypassAuthz: false, extraConfiguration: GrantConfiguration("Enforce"));
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
        var clientId = $"grant-refused-{Guid.NewGuid():N}";

        var refused = await Assert.ThrowsAsync<ManagementAccessException>(() =>
            clients.CreateAsync(
                PublicClient(clientId, "openid", PrivilegedScope),
                Operator(ManagementCapabilities.ClientsCreate)));
        Assert.Equal(ClientScopeGrantReasonCodes.CapabilityMissing, refused.Decision.ReasonCode);
        Assert.Equal(ManagementCapabilities.ScopesGrant, refused.Decision.RequiredCapability);
        Assert.Null(await scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>()
            .FindByClientIdAsync(clientId));

        var audit = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .ManagementAuditEvents.AsNoTracking()
            .SingleAsync(row => row.ResourceId == clientId);
        Assert.Equal("denied", audit.OperationOutcome);
        Assert.Equal(ManagementCapabilities.ScopesGrant, audit.Capability);
        Assert.Equal(ClientScopeGrantReasonCodes.CapabilityMissing, audit.ReasonCode);
        Assert.Equal("scope-grant-operator", audit.OperatorSubject);
        Assert.Null(audit.OperatorDisplayName);
        Assert.Contains(PrivilegedScope, audit.AfterJson);

        var created = await clients.CreateAsync(
            PublicClient(clientId, "openid", PrivilegedScope),
            Operator(ManagementCapabilities.ClientsCreate, ManagementCapabilities.ScopesGrant));
        Assert.Contains("scp:" + PrivilegedScope, created.Permissions);
    }

    [Fact]
    public async Task Management_update_refuses_only_the_expansion()
    {
        using var factory = new ManagementTestFactory(
            bypassAuthz: false, extraConfiguration: GrantConfiguration("Enforce"));
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
        var clientId = $"grant-update-{Guid.NewGuid():N}";

        var holding = await clients.CreateAsync(
            PublicClient(clientId, "openid", PrivilegedScope),
            Operator(ManagementCapabilities.ClientsCreate, ManagementCapabilities.ScopesGrant));
        var editor = Operator(ManagementCapabilities.ClientsUpdate);
        var kept = await clients.UpdateAsync(new UpdateManagementClientCommand(
            clientId, "Renamed", null, false,
            [Permissions.GrantTypes.AuthorizationCode], ["openid", PrivilegedScope],
            ["https://client.example.invalid/callback"],
            ExpectedVersion: holding.Version), editor);
        Assert.Equal("Renamed", kept.DisplayName);

        var without = await clients.UpdateAsync(new UpdateManagementClientCommand(
            clientId, "Narrowed", null, false,
            [Permissions.GrantTypes.AuthorizationCode], ["openid"],
            ["https://client.example.invalid/callback"],
            ExpectedVersion: kept.Version), editor);
        Assert.DoesNotContain("scp:" + PrivilegedScope, without.Permissions);

        var refused = await Assert.ThrowsAsync<ManagementAccessException>(() =>
            clients.UpdateAsync(new UpdateManagementClientCommand(
                clientId, "Widened", null, false,
                [Permissions.GrantTypes.AuthorizationCode], ["openid", PrivilegedScope],
                ["https://client.example.invalid/callback"],
                ExpectedVersion: without.Version), editor));
        Assert.Equal(ClientScopeGrantReasonCodes.CapabilityMissing, refused.Decision.ReasonCode);
    }

    [Fact]
    public async Task Management_observe_allows_and_records_would_deny()
    {
        using var factory = new ManagementTestFactory(
            bypassAuthz: false, extraConfiguration: GrantConfiguration("Observe"));
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var clients = scope.ServiceProvider.GetRequiredService<IClientManagementService>();
        var clientId = $"grant-observed-{Guid.NewGuid():N}";

        var created = await clients.CreateAsync(
            PublicClient(clientId, "openid", PrivilegedScope),
            Operator(ManagementCapabilities.ClientsCreate));
        Assert.Contains("scp:" + PrivilegedScope, created.Permissions);

        var audit = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .ManagementAuditEvents.AsNoTracking()
            .SingleAsync(row => row.ResourceId == clientId
                && row.ReasonCode == ClientScopeGrantReasonCodes.CapabilityMissing);
        Assert.Equal("observed", audit.OperationOutcome);
        Assert.Equal("allowed:scope_grant_observe", audit.AuthorizationOutcome);
    }

    [Fact]
    public async Task Management_http_refusal_carries_the_reason_and_the_missing_capability()
    {
        using var factory = new ManagementTestFactory(extraConfiguration: GrantConfiguration("Enforce"));
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.AddSingleton<IManagementEntitlementResolver>(
                new FixedEntitlements(ManagementCapabilities.ClientsCreate));
        }));
        using var http = host.CreateClient();

        using var response = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = $"grant-http-{Guid.NewGuid():N}",
            GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
            Scopes = ["openid", PrivilegedScope],
            RedirectUris = ["https://client.example.invalid/callback"],
        });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        // The test host skips authentication, so the caller names no
        // operator: the most restricted principal.
        Assert.Equal(
            ClientScopeGrantReasonCodes.OperatorRequired,
            body.GetProperty("reasonCode").GetString());
        Assert.Equal(
            ManagementCapabilities.ScopesGrant,
            body.GetProperty("requiredPermission").GetString());
    }

    private static IdentityProvisioningManifest Manifest(string clientId) => new()
    {
        ManifestId = "scope-grant-manifest",
        RolloutMode = ClientDefinitionRolloutMode.Enforce,
        Scopes = [new IdentityScopeManifest { Name = PrivilegedScope, Resources = ["reports-api"] }],
        Clients =
        [
            new IdentityClientManifest
            {
                ClientId = clientId,
                ClientType = ManifestClientTypes.Public,
                RequirePkce = true,
                GrantTypes = [ManifestGrantTypes.AuthorizationCode],
                ResponseTypes = [ManifestResponseTypes.Code],
                Scopes = ["openid", PrivilegedScope],
                RedirectUris = [new Uri("https://client.example.invalid/callback")],
            },
        ],
    };

    [Fact]
    public async Task Provisioning_refuses_an_operator_who_could_not_grant_the_scope_by_hand()
    {
        using var factory = new ManagementTestFactory(
            bypassAuthz: false, extraConfiguration: GrantConfiguration("Enforce"));
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var provisioning = scope.ServiceProvider.GetRequiredService<IProvisioningManagementService>();
        var clientId = $"manifest-grant-{Guid.NewGuid():N}";

        // A provisioning token holds the two provisioning capabilities only.
        var tokenOperator = Operator(
            ManagementCapabilities.ProvisioningPreview,
            ManagementCapabilities.ProvisioningApply);
        var preview = await Assert.ThrowsAsync<ManagementAccessException>(() =>
            provisioning.PreviewAsync(Manifest(clientId), tokenOperator));
        Assert.Equal(ClientScopeGrantReasonCodes.CapabilityMissing, preview.Decision.ReasonCode);
        await Assert.ThrowsAsync<ManagementAccessException>(() =>
            provisioning.ApplyAsync(Manifest(clientId), tokenOperator));
        Assert.Null(await scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>()
            .FindByClientIdAsync(clientId));
        Assert.True(await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .ManagementAuditEvents.AsNoTracking()
            .AnyAsync(row => row.ResourceId == clientId
                && row.OperationOutcome == "denied"
                && row.Capability == ManagementCapabilities.ScopesGrant));

        var plan = await provisioning.ApplyAsync(
            Manifest(clientId),
            Operator(
                ManagementCapabilities.ProvisioningApply,
                ManagementCapabilities.ScopesGrant));
        Assert.Contains(plan.Changes, change =>
            change.Identifier == clientId && change.Kind == IdentityManifestChangeKind.Create);

        // Re-applying the same manifest keeps the scope: not an expansion.
        await provisioning.ApplyAsync(Manifest(clientId), tokenOperator);
    }

    [Fact]
    public async Task Dynamic_registration_is_the_most_restricted_principal()
    {
        static Dictionary<string, string?> Configuration(string mode)
        {
            var configuration = GrantConfiguration(mode);
            configuration["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true";
            configuration["Sufficit:Identity:Mcp:Dcr:AllowedScopes:0"] = "openid";
            configuration["Sufficit:Identity:Mcp:Dcr:AllowedScopes:1"] = PrivilegedScope;
            return configuration;
        }

        foreach (var (mode, expected) in new[]
                 {
                     ("Enforce", HttpStatusCode.BadRequest),
                     ("Observe", HttpStatusCode.Created),
                 })
        {
            using var factory = new ManagementTestFactory(extraConfiguration: Configuration(mode));
            await ((IAsyncLifetime)factory).InitializeAsync();
            using var operatorClient = factory.CreateClient();
            using var issued = await operatorClient.PostAsJsonAsync(
                "/api/registration-tokens", new { label = "scope grant", lifetimeHours = 1 });
            var token = (await issued.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("initialAccessToken").GetString()!;

            using var registrant = factory.CreateClient();
            registrant.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
            using var response = await registrant.PostAsJsonAsync("/connect/register", new DcrRequest
            {
                GrantTypes = ["authorization_code"],
                Scopes = ["openid", PrivilegedScope],
                RedirectUris = [new Uri("https://client.example.invalid/callback")],
            });

            Assert.Equal(expected, response.StatusCode);
            if (expected == HttpStatusCode.BadRequest)
            {
                var body = await response.Content.ReadFromJsonAsync<JsonElement>();
                Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
                Assert.Equal(
                    ClientScopeGrantReasonCodes.OperatorRequired,
                    body.GetProperty("reason_code").GetString());
            }

            await using var scope = factory.Services.CreateAsyncScope();
            var audit = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
                .ManagementAuditEvents.AsNoTracking()
                .SingleAsync(row => row.ReasonCode == ClientScopeGrantReasonCodes.OperatorRequired);
            Assert.Equal(mode == "Enforce" ? "denied" : "observed", audit.OperationOutcome);
            Assert.Equal("source:dynamicregistration", audit.OperatorSubject);
        }
    }

    private sealed class FixedEntitlements(params string[] capabilities)
        : IManagementEntitlementResolver
    {
        public ValueTask<ManagementEntitlements> ResolveAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ManagementEntitlements(
                capabilities.ToHashSet(StringComparer.Ordinal)));
    }
}
