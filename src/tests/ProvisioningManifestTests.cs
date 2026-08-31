using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed partial class ProvisioningManifestTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly SufficitIdentityTestFactory _factory;

    public ProvisioningManifestTests(SufficitIdentityTestFactory factory)
        => _factory = factory;

    [Fact]
    public void Public_example_is_secret_free_and_valid()
    {
        var json = File.ReadAllText(RepositoryFile(
            "docs",
            "migration",
            "examples",
            "identity-manifest.v1.json"));

        var manifest = JsonSerializer.Deserialize<IdentityProvisioningManifest>(
            json,
            JsonOptions);

        Assert.NotNull(manifest);
        Assert.Empty(IdentityProvisioningManifestValidator.Validate(manifest));
        Assert.DoesNotContain("clientSecret", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("client_secret", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Castrum_endpoints_manifest_is_secret_free_and_valid()
    {
        var json = File.ReadAllText(RepositoryFile(
            "docs",
            "runbooks",
            "manifests",
            "test-environment-endpoints.v1.json"));

        var manifest = JsonSerializer.Deserialize<IdentityProvisioningManifest>(
            json,
            JsonOptions);

        Assert.NotNull(manifest);
        Assert.Empty(IdentityProvisioningManifestValidator.Validate(manifest));
        var directives = Assert.Single(manifest.Scopes);
        Assert.Equal("directives", directives.Name);
        Assert.Contains("SufficitEndpointsIntrospection", directives.Resources);
        Assert.DoesNotContain("clientSecret", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("client_secret", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unknown_fields_are_rejected_instead_of_ignoring_embedded_credentials()
    {
        const string json =
            """
            {
              "schemaVersion": 1,
              "scopes": [],
              "clients": [],
              "clientSecret": "must-not-be-accepted"
            }
            """;

        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<IdentityProvisioningManifest>(json, JsonOptions));
    }

    [Fact]
    public void Enforce_requires_a_stable_manifest_identity()
    {
        var manifest = new IdentityProvisioningManifest
        {
            RolloutMode = ClientDefinitionRolloutMode.Enforce,
        };

        var errors = IdentityProvisioningManifestValidator.Validate(manifest);

        Assert.Contains(
            errors,
            error => error.Contains(
                "manifestId is required when rolloutMode is Enforce",
                StringComparison.Ordinal));
    }

    [Fact]
    public void Legacy_grants_and_non_loopback_http_redirects_are_rejected()
    {
        var manifest = new IdentityProvisioningManifest
        {
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = "legacy_web",
                    ClientType = ManifestClientTypes.Public,
                    GrantTypes = ["implicit"],
                    ResponseTypes = ["token"],
                    RedirectUris =
                    [
                        new Uri("http://client.example.invalid/callback"),
                        new Uri("javascript:alert('blocked')"),
                    ],
                },
            ],
        };

        var errors = IdentityProvisioningManifestValidator.Validate(manifest);

        Assert.Contains(errors, error => error.Contains(
            "unsupported target grant 'implicit'",
            StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains(
            "unsupported target response type 'token'",
            StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains(
            "must use HTTPS",
            StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains(
            "uses a forbidden redirect scheme",
            StringComparison.Ordinal));
    }

    [Fact]
    public async Task Provisioning_projects_pkce_for_confidential_authorization_code_only()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var interactiveId = $"manifest_confidential_code_{suffix}";
        var serviceId = $"manifest_confidential_service_{suffix}";
        var interactiveSecret = $"identity/clients/{interactiveId}/v1";
        var serviceSecret = $"identity/clients/{serviceId}/v1";
        var resolver = new TrackingSecretResolver(
            new Dictionary<string, string>
            {
                [interactiveSecret] = $"secret-interactive-{suffix}",
                [serviceSecret] = $"secret-service-{suffix}",
            });
        await using var scope = _factory.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = scope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            resolver);
        var manifest = new IdentityProvisioningManifest
        {
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = interactiveId,
                    ClientType = ManifestClientTypes.Confidential,
                    SecretReference = interactiveSecret,
                    RequirePkce = true,
                    GrantTypes = [ManifestGrantTypes.AuthorizationCode],
                    ResponseTypes = [ManifestResponseTypes.Code],
                    RedirectUris =
                    [
                        new Uri("https://client.example.invalid/callback"),
                    ],
                },
                new IdentityClientManifest
                {
                    ClientId = serviceId,
                    ClientType = ManifestClientTypes.Confidential,
                    SecretReference = serviceSecret,
                    GrantTypes = [ManifestGrantTypes.ClientCredentials],
                },
            ],
        };

        await provisioner.ApplyAsync(manifest);

        var interactive = await applications.FindByClientIdAsync(interactiveId);
        var service = await applications.FindByClientIdAsync(serviceId);
        Assert.NotNull(interactive);
        Assert.NotNull(service);
        Assert.Contains(
            OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
            await applications.GetRequirementsAsync(interactive!));
        Assert.DoesNotContain(
            OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
            await applications.GetRequirementsAsync(service!));
    }

    [Fact]
    public async Task Apply_is_idempotent_and_updates_only_declared_objects()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"manifest_scope_{suffix}";
        var clientId = $"manifest_web_{suffix}";

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var resolver = new TrackingSecretResolver();
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            resolver);

        var initial = PublicClientManifest(
            scopeName,
            clientId,
            displayName: "Initial web client",
            scopeDisplayName: "Initial API");

        var preview = await provisioner.PreviewAsync(initial);
        Assert.All(preview.Changes, change =>
            Assert.Equal(IdentityManifestChangeKind.Create, change.Kind));

        var applied = await provisioner.ApplyAsync(initial);
        Assert.All(applied.Changes, change =>
            Assert.Equal(IdentityManifestChangeKind.Create, change.Kind));

        var unchanged = await provisioner.PreviewAsync(initial);
        Assert.False(unchanged.HasChanges);
        Assert.All(unchanged.Changes, change =>
            Assert.Equal(IdentityManifestChangeKind.Unchanged, change.Kind));

        var application = await applications.FindByClientIdAsync(clientId)
            ?? throw new InvalidOperationException("Provisioned client missing.");
        var properties = await applications.GetPropertiesAsync(application);
        Assert.Equal(
            "provisioning",
            properties["identity:provisioning-manifest:owner"].GetString());
        Assert.Equal(
            $"client:{clientId}",
            properties["identity:provisioning-manifest:identity"].GetString());
        var logoutSettings = await applications.GetSettingsAsync(application);
        Assert.Equal(
            $"https://{clientId}.example.invalid/oidc/frontchannel-logout",
            logoutSettings["frontchannel_logout_uri"]);
        Assert.Equal(
            $"https://{clientId}.example.invalid/oidc/backchannel-logout",
            logoutSettings["backchannel_logout_uri"]);
        Assert.Equal("false", logoutSettings["frontchannel_logout_session_required"]);
        Assert.Equal("false", logoutSettings["backchannel_logout_session_required"]);

        var updated = PublicClientManifest(
            scopeName,
            clientId,
            displayName: "Updated web client",
            scopeDisplayName: "Updated API");

        var updatePreview = await provisioner.PreviewAsync(updated);
        Assert.All(updatePreview.Changes, change =>
            Assert.Equal(IdentityManifestChangeKind.Update, change.Kind));

        await provisioner.ApplyAsync(updated);
        Assert.False((await provisioner.PreviewAsync(updated)).HasChanges);
        Assert.Empty(resolver.Requests);

        // The additive manifest must not remove an existing object that was
        // not declared in this manifest.
        Assert.NotNull(await applications.FindByClientIdAsync(
            TestDataSeeder.ClientCredentialsClientId));
    }

    [Fact]
    public async Task Concurrent_previews_are_side_effect_free_and_idempotent()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"manifest_scope_{suffix}";
        var clientId = $"manifest_preview_{suffix}";

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            new TrackingSecretResolver());
        var manifest = PublicClientManifest(
            scopeName,
            clientId,
            "Concurrent preview",
            "API");

        var plans = await Task.WhenAll(
            Enumerable.Range(0, 8)
                .Select(_ => provisioner.PreviewAsync(manifest)));

        Assert.All(plans, plan =>
            Assert.All(plan.Changes, change =>
                Assert.Equal(IdentityManifestChangeKind.Create, change.Kind)));
        Assert.Null(await applications.FindByClientIdAsync(clientId));
        Assert.Null(await scopes.FindByNameAsync(scopeName));
    }

    [Fact]
    public async Task Manifest_persists_scope_entitlements_and_stays_idempotent()
    {
        // F-2 (eval 2026-08-30): the entitlement belongs to the scope record so
        // a replicated database carries it to every host, replacing the
        // per-server appsettings edit the configuration-only design required.
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"manifest_scope_{suffix}";
        var clientId = $"manifest_web_{suffix}";

        using var serviceScope = _factory.Services.CreateScope();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(
            serviceScope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>(),
            scopes,
            new TrackingSecretResolver());

        var manifest = PublicClientManifest(
            scopeName,
            clientId,
            displayName: "Entitlement web client",
            scopeDisplayName: "Entitlement API");
        manifest.Scopes[0].EntitlementClaims.Add(
            new IdentityScopeEntitlementManifest
            {
                Type = "directive",
                Value = "aiuser:11111111-1111-1111-1111-111111111111",
            });

        await provisioner.ApplyAsync(manifest);

        var scope = await scopes.FindByNameAsync(scopeName);
        Assert.NotNull(scope);
        var entitlements = ScopeEntitlements.Read(
            await scopes.GetPropertiesAsync(scope!));
        var entitlement = Assert.Single(entitlements);
        Assert.Equal("directive", entitlement.Type);
        Assert.Equal("aiuser:11111111-1111-1111-1111-111111111111", entitlement.Value);

        // Re-applying the same manifest must not report a pending change, or
        // every provisioning run would rewrite the scope forever.
        var unchanged = await provisioner.PreviewAsync(manifest);
        Assert.False(unchanged.HasChanges);

        // Removing the entitlement is a real change, and it must actually clear
        // the property rather than leave a stale grant behind.
        manifest.Scopes[0].EntitlementClaims.Clear();
        Assert.True((await provisioner.PreviewAsync(manifest)).HasChanges);
        await provisioner.ApplyAsync(manifest);

        var cleared = await scopes.FindByNameAsync(scopeName);
        Assert.Empty(ScopeEntitlements.Read(
            await scopes.GetPropertiesAsync(cleared!)));
    }

    private sealed class TrackingSecretResolver(
        IReadOnlyDictionary<string, string>? values = null) : IClientSecretResolver
    {
        private readonly IReadOnlyDictionary<string, string> _values =
            values ?? new Dictionary<string, string>();

        public List<string> Requests { get; } = [];

        public ValueTask<string> ResolveAsync(
            string reference,
            CancellationToken cancellationToken = default)
        {
            Requests.Add(reference);
            return _values.TryGetValue(reference, out var value)
                ? ValueTask.FromResult(value)
                : ValueTask.FromException<string>(
                    new InvalidOperationException(
                        $"No test secret registered for '{reference}'."));
        }
    }
}
