using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Vault;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Plan A2: the Management create/update contract names a vault secret
/// (<c>secretReference</c>); the plaintext <c>clientSecret</c> survives only as
/// an audited, expiring compatibility adapter.
/// </summary>
public sealed class ClientSecretReferenceTests
{
    private static async Task<HttpStatusCode> TokenAsync(
        HttpClient http, string clientId, string secret)
    {
        var (status, _) = await http.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        });
        return status;
    }

    [Fact]
    public async Task Plaintext_secret_is_accepted_with_a_pii_free_audit_warning_before_expiry()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        var clientId = $"plaintext-{Guid.NewGuid():N}";
        const string secret = "plaintext-compatibility-secret-value";

        using var response = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = secret,
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var rows = await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .ManagementAuditEvents.AsNoTracking()
            .Where(row => row.ResourceId == clientId)
            .ToArrayAsync();
        var warning = Assert.Single(rows, row =>
            row.ReasonCode == PlaintextClientSecretAdapter.DeprecatedReasonCode);
        Assert.Equal("warning", warning.OperationOutcome);
        Assert.Null(warning.OperatorDisplayName);
        Assert.All(rows, row => Assert.DoesNotContain(
            secret,
            JsonSerializer.Serialize(row),
            StringComparison.Ordinal));
    }

    [Fact]
    public async Task Plaintext_secret_is_refused_after_the_configured_expiry()
    {
        using var factory = new ManagementTestFactory(extraConfiguration: new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Management:ClientSecrets:PlaintextExpiresAtUtc"] = "2020-01-01T00:00:00Z",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        var clientId = $"plaintext-expired-{Guid.NewGuid():N}";

        using var response = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = "plaintext-compatibility-secret-value",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            PlaintextClientSecretAdapter.ExpiredReasonCode,
            body.GetProperty("reasonCode").GetString());
        await using var scope = factory.Services.CreateAsyncScope();
        Assert.Null(await scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>()
            .FindByClientIdAsync(clientId));
        Assert.True(await scope.ServiceProvider.GetRequiredService<AppDbContext>()
            .ManagementAuditEvents.AsNoTracking()
            .AnyAsync(row => row.ResourceId == clientId
                && row.ReasonCode == PlaintextClientSecretAdapter.ExpiredReasonCode));

        // secretReference is not plaintext on the wire and never meets the
        // adapter (here it fails later, for want of a vault).
        using var referenced = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            SecretReference = new() { Name = "clients/none/secret" },
        });
        Assert.NotEqual(HttpStatusCode.Created, referenced.StatusCode);
        Assert.NotEqual(
            PlaintextClientSecretAdapter.ExpiredReasonCode,
            (await referenced.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("reasonCode").GetString());
    }

    [Fact]
    public async Task Both_secret_sources_at_once_are_refused()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();

        using var response = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = $"ambiguous-{Guid.NewGuid():N}",
            ClientSecret = "plaintext-compatibility-secret-value",
            SecretReference = new() { Name = "clients/ambiguous/secret" },
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            PlaintextClientSecretAdapter.AmbiguousReasonCode,
            (await response.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("reasonCode").GetString());
    }

    [Fact]
    public async Task Secret_reference_creates_and_replaces_the_client_secret()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var vault = new FakeReferences(new()
        {
            ["global:clients/reporting/v1"] = "vault-resolved-secret-first-version",
            ["global:clients/reporting/v2"] = "vault-resolved-secret-second-version",
        });
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IManagementClientSecretReferenceResolver>(vault))));
        using var http = host.CreateClient();
        var clientId = $"referenced-{Guid.NewGuid():N}";

        using var created = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            SecretReference = new() { Name = "clients/reporting/v1" },
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var detail = (await created.Content.ReadFromJsonAsync<ManagementClientDetail>())!;
        Assert.Equal(ClientTypes.Confidential, detail.Type);
        Assert.Equal(HttpStatusCode.OK,
            await TokenAsync(http, clientId, "vault-resolved-secret-first-version"));

        using var updated = await http.PutAsJsonAsync($"/api/clients/{clientId}", new UpdateClientRequest
        {
            DisplayName = detail.DisplayName,
            ConsentType = detail.ConsentType,
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            ExpectedVersion = detail.Version,
            SecretReference = new() { Name = "clients/reporting/v2", ContextId = "global" },
        });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            await TokenAsync(http, clientId, "vault-resolved-secret-second-version"));
        Assert.NotEqual(HttpStatusCode.OK,
            await TokenAsync(http, clientId, "vault-resolved-secret-first-version"));

        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var application = (await applications.FindByClientIdAsync(clientId))!;
        var properties = await applications.GetPropertiesAsync(application);
        Assert.Equal(
            "global:clients/reporting/v2",
            properties["identity:management:secret-reference"].GetString());
        Assert.Equal(2, vault.Resolutions);
    }

    [Fact]
    public async Task Secret_reference_resolves_a_real_vault_named_secret()
    {
        using var factory = new ManagementTestFactory(enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IVaultNamedSecretStore>().PutAsync(
                "clients/vaulted/secret",
                "secret-held-only-by-the-vault-0123456789",
                "test-operator");
        }

        var clientId = $"vaulted-{Guid.NewGuid():N}";
        using var created = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            SecretReference = new() { Name = "clients/vaulted/secret" },
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            await TokenAsync(http, clientId, "secret-held-only-by-the-vault-0123456789"));

        using var missing = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = $"vaulted-missing-{Guid.NewGuid():N}",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            SecretReference = new() { Name = "clients/absent/secret" },
        });
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal(
            "client_secret_reference_not_found",
            (await missing.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("reasonCode").GetString());
    }

    [Theory]
    [InlineData("secret/rotate")]
    [InlineData("credentials")]
    public async Task Lifecycle_reference_is_resolved_without_returning_the_vault_value(string endpoint)
    {
        using var factory = new ManagementTestFactory(enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        const string original = "original-lifecycle-client-secret-0123456789";
        const string replacement = "vault-lifecycle-replacement-secret-0123456789";
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IVaultNamedSecretStore>().PutAsync(
                "clients/lifecycle/secret", replacement, "test-operator");
        }
        var clientId = $"lifecycle-ref-{Guid.NewGuid():N}";
        using var created = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = original,
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var detail = (await created.Content.ReadFromJsonAsync<ManagementClientDetail>())!;
        using var response = await http.PostAsJsonAsync($"/api/clients/{clientId}/{endpoint}", new
        {
            expectedVersion = detail.Version,
            expectedClientVersion = detail.Version,
            label = "vault-reference",
            generate = false,
            secretReference = new { name = "clients/lifecycle/secret" },
        });
        Assert.Equal(endpoint == "credentials" ? HttpStatusCode.Created : HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(replacement, json, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, await TokenAsync(http, clientId, replacement));
        Assert.Equal(endpoint == "credentials", await TokenAsync(http, clientId, original) == HttpStatusCode.OK);
        await using var auditScope = factory.Services.CreateAsyncScope();
        var rows = await auditScope.ServiceProvider.GetRequiredService<AppDbContext>()
            .ManagementAuditEvents.AsNoTracking().Where(row => row.ResourceId == clientId).ToArrayAsync();
        Assert.All(rows, row => Assert.DoesNotContain(replacement, JsonSerializer.Serialize(row), StringComparison.Ordinal));
        var current = (await http.GetFromJsonAsync<ManagementClientDetail>($"/api/clients/{clientId}"))!;
        foreach (var invalid in new[]
        {
            (Generate: true, Secret: (string?)null, Name: "clients/lifecycle/secret", Reason: "client_secret_source_ambiguous"),
            (Generate: false, Secret: (string?)original, Name: "clients/lifecycle/secret", Reason: "client_secret_source_ambiguous"),
            (Generate: false, Secret: (string?)null, Name: "clients/lifecycle/missing", Reason: "client_secret_reference_not_found"),
        })
        {
            using var rejected = await http.PostAsJsonAsync($"/api/clients/{clientId}/{endpoint}", new
            {
                expectedVersion = current.Version, expectedClientVersion = current.Version,
                label = "rejected-reference", generate = invalid.Generate, clientSecret = invalid.Secret,
                secretReference = new { name = invalid.Name },
            });
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.Equal(invalid.Reason, (await rejected.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reasonCode").GetString());
            Assert.Equal(HttpStatusCode.OK, await TokenAsync(http, clientId, replacement));
        }
        if (endpoint == "secret/rotate")
        {
            var manager = auditScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = (await manager.FindByClientIdAsync(clientId))!;
            Assert.Equal("global:clients/lifecycle/secret",
                (await manager.GetPropertiesAsync(application))["identity:management:secret-reference"].GetString());
        }
    }

    [Theory]
    [InlineData("secret/rotate")]
    [InlineData("credentials")]
    public async Task Lifecycle_plaintext_adapter_expires_but_generation_remains_available(string endpoint)
    {
        using var factory = new ManagementTestFactory(extraConfiguration: new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Management:ClientSecrets:PlaintextExpiresAtUtc"] = "2020-01-01T00:00:00Z",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var http = factory.CreateClient();
        var clientId = $"lifecycle-expired-{Guid.NewGuid():N}";
        using var created = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest { ClientId = clientId });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var detail = (await created.Content.ReadFromJsonAsync<ManagementClientDetail>())!;
        using var rejected = await http.PostAsJsonAsync($"/api/clients/{clientId}/{endpoint}", new
        {
            expectedVersion = detail.Version, expectedClientVersion = detail.Version,
            label = "expired-plaintext", generate = false, clientSecret = "expired-plaintext-secret-0123456789",
        });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal(PlaintextClientSecretAdapter.ExpiredReasonCode,
            (await rejected.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("reasonCode").GetString());
        using var generated = await http.PostAsJsonAsync($"/api/clients/{clientId}/{endpoint}", new
        {
            expectedVersion = detail.Version, expectedClientVersion = detail.Version,
            label = "generated-after-expiry", generate = true,
        });
        Assert.Equal(endpoint == "credentials" ? HttpStatusCode.Created : HttpStatusCode.OK, generated.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var audit = await scope.ServiceProvider.GetRequiredService<AppDbContext>().ManagementAuditEvents
            .SingleAsync(row => row.ResourceId == clientId && row.ReasonCode == PlaintextClientSecretAdapter.ExpiredReasonCode);
        Assert.Equal(ManagementCapabilities.ClientsUpdate, audit.Capability);
    }

    [Theory]
    [InlineData("secret/rotate")]
    [InlineData("credentials")]
    public async Task Lifecycle_reference_requires_vault_authority(string endpoint)
    {
        using var factory = new ManagementTestFactory(enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IManagementAuthorizationEvaluator>(new ClientOnlyAuthorization()))));
        using var http = host.CreateClient();
        var clientId = $"lifecycle-denied-{Guid.NewGuid():N}";
        using var created = await http.PostAsJsonAsync("/api/clients", new CreateClientRequest { ClientId = clientId });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var detail = (await created.Content.ReadFromJsonAsync<ManagementClientDetail>())!;
        using var rejected = await http.PostAsJsonAsync($"/api/clients/{clientId}/{endpoint}", new
        {
            expectedVersion = detail.Version, expectedClientVersion = detail.Version,
            label = "forbidden-reference", generate = false,
            secretReference = new { name = "clients/lifecycle/secret" },
        });
        Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        var unchanged = (await http.GetFromJsonAsync<ManagementClientDetail>($"/api/clients/{clientId}"))!;
        Assert.Equal(detail.Version, unchanged.Version);
        Assert.Equal(detail.Type, unchanged.Type);
    }

    private sealed class ClientOnlyAuthorization : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            System.Security.Claims.ClaimsPrincipal principal, string capability,
            ManagementResource resource, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(capability == ManagementCapabilities.SecretsResolve
                ? ManagementAuthorizationDecision.Denied("vault_resolution_denied")
                : ManagementAuthorizationDecision.Allowed());
    }

    private sealed class FakeReferences(Dictionary<string, string> values)
        : IManagementClientSecretReferenceResolver
    {
        public int Resolutions { get; private set; }

        public Task<string> ResolveAsync(
            ManagementClientSecretReference reference,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default)
        {
            Resolutions++;
            return values.TryGetValue(reference.ToString(), out var value)
                ? Task.FromResult(value)
                : throw new ManagementValidationException(
                    "client_secret_reference_not_found", "missing", "secretReference");
        }
    }
}
