using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ProvisioningManifestTests
{
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
}
