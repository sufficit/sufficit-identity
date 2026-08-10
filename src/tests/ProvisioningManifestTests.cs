using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class ProvisioningManifestTests
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
    public async Task Sensitive_redirect_transition_is_observed_without_mutation()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"transition_scope_{suffix}";
        var clientId = $"transition_observe_{suffix}";
        var initial = RedirectTransitionManifest(
            scopeName,
            clientId,
            new Uri("https://client.example.invalid/old"),
            ClientDefinitionRolloutMode.Enforce);

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            new TrackingSecretResolver());

        await provisioner.ApplyAsync(initial);

        var observed = RedirectTransitionManifest(
            scopeName,
            clientId,
            new Uri("https://client.example.invalid/new"),
            ClientDefinitionRolloutMode.Observe);
        var preview = await provisioner.PreviewAsync(observed);
        Assert.Contains(
            preview.Changes,
            change => change.Kind is IdentityManifestChangeKind.Observed);
        Assert.False(preview.HasChanges);

        await provisioner.ApplyAsync(observed);
        var application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);
        var redirectUris = await applications.GetRedirectUrisAsync(application);
        Assert.Contains(
            redirectUris,
            uri => uri.EndsWith("/old", StringComparison.Ordinal));
        Assert.DoesNotContain(
            redirectUris,
            uri => uri.EndsWith("/new", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Sensitive_redirect_transition_requires_authorization_in_enforce_mode()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"transition_scope_{suffix}";
        var clientId = $"transition_enforce_{suffix}";

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            new TrackingSecretResolver());
        await provisioner.ApplyAsync(RedirectTransitionManifest(
            scopeName,
            clientId,
            new Uri("https://client.example.invalid/old"),
            ClientDefinitionRolloutMode.Enforce));

        var denied = RedirectTransitionManifest(
            scopeName,
            clientId,
            new Uri("https://client.example.invalid/new"),
            ClientDefinitionRolloutMode.Enforce);
        var exception = await Assert.ThrowsAsync<IdentityProvisioningManifestException>(
            () => provisioner.ApplyAsync(
                denied,
                default,
                "operator-transition-test"));
        Assert.Contains(exception.Errors, error =>
            error.Contains("redirect_replacement_requires_authorization", StringComparison.Ordinal));

        var authorized = RedirectTransitionManifest(
            scopeName,
            clientId,
            new Uri("https://client.example.invalid/new"),
            ClientDefinitionRolloutMode.Enforce,
            authorizeSensitiveTransitions: true);
        var plan = await provisioner.ApplyAsync(
            authorized,
            default,
            "operator-transition-test");
        Assert.Contains(
            plan.Changes,
            change => change.Kind is IdentityManifestChangeKind.Update);
    }

    [Fact]
    public async Task Confidential_client_resolves_on_create_and_explicit_reference_rotation_only()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"manifest_scope_{suffix}";
        var clientId = $"manifest_worker_{suffix}";
        var firstReference = $"identity/clients/{clientId}/v1";
        var secondReference = $"identity/clients/{clientId}/v2";
        var firstSecret = $"first-{suffix}";
        var secondSecret = $"second-{suffix}";

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        var resolver = new TrackingSecretResolver(new Dictionary<string, string>
        {
            [firstReference] = firstSecret,
            [secondReference] = secondSecret,
        });
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            resolver);

        var initial = ConfidentialClientManifest(
            scopeName,
            clientId,
            firstReference);

        // Preview is guaranteed not to touch the secret store.
        Assert.True((await provisioner.PreviewAsync(initial)).HasChanges);
        Assert.Empty(resolver.Requests);

        await provisioner.ApplyAsync(initial);
        Assert.Equal([firstReference], resolver.Requests);

        var application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);
        Assert.True(await applications.ValidateClientSecretAsync(
            application,
            firstSecret));

        await provisioner.ApplyAsync(initial);
        Assert.Equal([firstReference], resolver.Requests);

        var rotated = ConfidentialClientManifest(
            scopeName,
            clientId,
            secondReference);

        await provisioner.ApplyAsync(rotated);
        Assert.Equal([firstReference, secondReference], resolver.Requests);

        application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);
        Assert.True(await applications.ValidateClientSecretAsync(
            application,
            secondSecret));
        Assert.False(await applications.ValidateClientSecretAsync(
            application,
            firstSecret));
        Assert.False((await provisioner.PreviewAsync(rotated)).HasChanges);
    }

    [Fact]
    public async Task Adopting_existing_confidential_client_preserves_its_secret()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"manifest_scope_{suffix}";
        var clientId = $"manifest_adopted_{suffix}";
        var existingSecret = $"existing-{suffix}";
        var secretReference = $"identity/clients/{clientId}/existing";

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();

        await scopes.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = scopeName,
            Resources = { scopeName },
        });
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = existingSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + scopeName,
            },
        });

        var resolver = new TrackingSecretResolver();
        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            resolver);
        var manifest = ConfidentialClientManifest(
            scopeName,
            clientId,
            secretReference,
            adoptExisting: true);

        var adoptionPlan = await provisioner.ApplyAsync(manifest);
        Assert.Contains(
            adoptionPlan.Changes,
            change => change.Kind is IdentityManifestChangeKind.Adopted);

        Assert.Empty(resolver.Requests);
        var application = await applications.FindByClientIdAsync(clientId);
        Assert.NotNull(application);
        Assert.True(await applications.ValidateClientSecretAsync(
            application,
            existingSecret));
        Assert.False((await provisioner.PreviewAsync(manifest)).HasChanges);
    }

    [Fact]
    public async Task Unmanaged_existing_client_requires_explicit_adoption()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"manifest_scope_{suffix}";
        var clientId = $"manifest_unmanaged_{suffix}";

        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        await scopes.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = scopeName,
            Resources = { scopeName },
        });
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
        });

        var provisioner = new OpenIddictManifestProvisioner(
            applications,
            scopes,
            new TrackingSecretResolver());
        var manifest = PublicClientManifest(
            scopeName,
            clientId,
            "Unmanaged client",
            "API");

        var exception = await Assert.ThrowsAsync<IdentityProvisioningManifestException>(
            () => provisioner.ApplyAsync(manifest));
        Assert.Contains(exception.Errors, error =>
            error.Contains("adoptExisting=true", StringComparison.Ordinal));
    }

    private static IdentityProvisioningManifest PublicClientManifest(
        string scopeName,
        string clientId,
        string displayName,
        string scopeDisplayName) =>
        new()
        {
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = scopeName,
                    DisplayName = scopeDisplayName,
                    Resources = [scopeName],
                },
            ],
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    DisplayName = displayName,
                    ClientType = ManifestClientTypes.Public,
                    ConsentType = ManifestConsentTypes.Explicit,
                    RequirePkce = true,
                    GrantTypes =
                    [
                        ManifestGrantTypes.AuthorizationCode,
                        ManifestGrantTypes.RefreshToken,
                    ],
                    ResponseTypes = [ManifestResponseTypes.Code],
                    Scopes = ["openid", "offline_access", scopeName],
                    RedirectUris =
                    [
                        new Uri($"https://{clientId}.example.invalid/signin-oidc"),
                    ],
                    PostLogoutRedirectUris =
                    [
                        new Uri(
                            $"https://{clientId}.example.invalid/signout-callback-oidc"),
                    ],
                    FrontchannelLogoutUri = new Uri(
                        $"https://{clientId}.example.invalid/oidc/frontchannel-logout"),
                    BackchannelLogoutUri = new Uri(
                        $"https://{clientId}.example.invalid/oidc/backchannel-logout"),
                },
            ],
        };

    private static IdentityProvisioningManifest RedirectTransitionManifest(
        string scopeName,
        string clientId,
        Uri redirectUri,
        ClientDefinitionRolloutMode rolloutMode,
        bool authorizeSensitiveTransitions = false) =>
        new()
        {
            ManifestId = $"transition:{clientId}",
            RolloutMode = rolloutMode,
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = scopeName,
                    Resources = [scopeName],
                },
            ],
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    ClientType = ManifestClientTypes.Public,
                    ConsentType = ManifestConsentTypes.Explicit,
                    RequirePkce = true,
                    AuthorizeSensitiveTransitions =
                        authorizeSensitiveTransitions,
                    GrantTypes = [ManifestGrantTypes.AuthorizationCode],
                    ResponseTypes = [ManifestResponseTypes.Code],
                    Scopes = [scopeName],
                    RedirectUris = [redirectUri],
                },
            ],
        };

    private static IdentityProvisioningManifest ConfidentialClientManifest(
        string scopeName,
        string clientId,
        string secretReference,
        bool adoptExisting = false) =>
        new()
        {
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = scopeName,
                    Resources = [scopeName],
                },
            ],
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    ClientType = ManifestClientTypes.Confidential,
                    ConsentType = ManifestConsentTypes.Implicit,
                    SecretReference = secretReference,
                    AdoptExisting = adoptExisting,
                    GrantTypes = [ManifestGrantTypes.ClientCredentials],
                    Scopes = [scopeName],
                },
            ],
        };

    private static string RepositoryFile(params string[] path)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new DirectoryNotFoundException(
                "Could not locate the Sufficit.Identity repository root.");
        }

        return Path.Combine([directory.FullName, .. path]);
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
