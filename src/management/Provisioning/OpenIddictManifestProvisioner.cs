using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.Management.Provisioning;

[JsonConverter(typeof(JsonStringEnumConverter<IdentityManifestChangeKind>))]
public enum IdentityManifestChangeKind
{
    Create,
    Update,
    Unchanged,
}

public sealed record IdentityManifestChange(
    string ResourceType,
    string Identifier,
    IdentityManifestChangeKind Kind);

public sealed record IdentityProvisioningPlan(
    IReadOnlyList<IdentityManifestChange> Changes)
{
    public bool HasChanges => Changes.Any(change =>
        change.Kind is IdentityManifestChangeKind.Create or IdentityManifestChangeKind.Update);
}

/// <summary>
/// Computes and optionally applies an additive OpenIddict provisioning plan.
/// Objects omitted from the manifest are never deleted.
/// </summary>
public sealed class OpenIddictManifestProvisioner
{
    internal const string SchemaVersionProperty =
        "identity:provisioning-manifest:schema-version";
    internal const string SecretReferenceProperty =
        "identity:provisioning-manifest:secret-reference";

    private readonly IOpenIddictApplicationManager _applications;
    private readonly IOpenIddictScopeManager _scopes;
    private readonly IClientSecretResolver _secrets;

    public OpenIddictManifestProvisioner(
        IOpenIddictApplicationManager applications,
        IOpenIddictScopeManager scopes,
        IClientSecretResolver secrets)
    {
        _applications = applications;
        _scopes = scopes;
        _secrets = secrets;
    }

    public Task<IdentityProvisioningPlan> PreviewAsync(
        IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken = default) =>
        ProcessAsync(manifest, apply: false, cancellationToken);

    public Task<IdentityProvisioningPlan> ApplyAsync(
        IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken = default) =>
        ProcessAsync(manifest, apply: true, cancellationToken);

    private async Task<IdentityProvisioningPlan> ProcessAsync(
        IdentityProvisioningManifest manifest,
        bool apply,
        CancellationToken cancellationToken)
    {
        IdentityProvisioningManifestValidator.ValidateAndThrow(manifest);

        var changes = new List<IdentityManifestChange>(
            manifest.Scopes.Count + manifest.Clients.Count);

        foreach (var scope in manifest.Scopes.OrderBy(scope => scope.Name, StringComparer.Ordinal))
        {
            changes.Add(await ProcessScopeAsync(
                manifest.SchemaVersion,
                scope,
                apply,
                cancellationToken));
        }

        foreach (var client in manifest.Clients.OrderBy(
                     client => client.ClientId,
                     StringComparer.Ordinal))
        {
            changes.Add(await ProcessClientAsync(
                manifest.SchemaVersion,
                client,
                apply,
                cancellationToken));
        }

        return new IdentityProvisioningPlan(changes);
    }

    private async Task<IdentityManifestChange> ProcessScopeAsync(
        int schemaVersion,
        IdentityScopeManifest manifest,
        bool apply,
        CancellationToken cancellationToken)
    {
        var desired = CreateScopeDescriptor(schemaVersion, manifest);
        var scope = await _scopes.FindByNameAsync(manifest.Name, cancellationToken);

        if (scope is null)
        {
            if (apply)
            {
                await _scopes.CreateAsync(desired, cancellationToken);
            }

            return new IdentityManifestChange(
                "scope",
                manifest.Name,
                IdentityManifestChangeKind.Create);
        }

        var current = new OpenIddictScopeDescriptor();
        await _scopes.PopulateAsync(current, scope, cancellationToken);

        if (ScopeEquals(current, desired))
        {
            return new IdentityManifestChange(
                "scope",
                manifest.Name,
                IdentityManifestChangeKind.Unchanged);
        }

        if (apply)
        {
            ApplyManagedScopeValues(current, desired);
            await _scopes.UpdateAsync(scope, current, cancellationToken);
        }

        return new IdentityManifestChange(
            "scope",
            manifest.Name,
            IdentityManifestChangeKind.Update);
    }

    private async Task<IdentityManifestChange> ProcessClientAsync(
        int schemaVersion,
        IdentityClientManifest manifest,
        bool apply,
        CancellationToken cancellationToken)
    {
        var desired = CreateApplicationDescriptor(schemaVersion, manifest);
        var application = await _applications.FindByClientIdAsync(
            manifest.ClientId,
            cancellationToken);

        if (application is null)
        {
            if (apply)
            {
                if (manifest.ClientType == ManifestClientTypes.Confidential)
                {
                    desired.ClientSecret = await ResolveSecretAsync(
                        manifest.SecretReference!,
                        cancellationToken);
                }

                await _applications.CreateAsync(desired, cancellationToken);
            }

            return new IdentityManifestChange(
                "client",
                manifest.ClientId,
                IdentityManifestChangeKind.Create);
        }

        var current = new OpenIddictApplicationDescriptor();
        await _applications.PopulateAsync(current, application, cancellationToken);

        if (ApplicationEquals(current, desired))
        {
            return new IdentityManifestChange(
                "client",
                manifest.ClientId,
                IdentityManifestChangeKind.Unchanged);
        }

        if (apply)
        {
            var currentReference = GetStringProperty(
                current.Properties,
                SecretReferenceProperty);
            var desiredReference = GetStringProperty(
                desired.Properties,
                SecretReferenceProperty);

            ApplyManagedApplicationValues(current, desired);

            if (manifest.ClientType == ManifestClientTypes.Public)
            {
                current.ClientSecret = null;
            }
            else if (string.IsNullOrEmpty(current.ClientSecret) ||
                     (!string.IsNullOrEmpty(currentReference) &&
                      !string.Equals(
                          currentReference,
                          desiredReference,
                          StringComparison.Ordinal)))
            {
                // A missing secret needs initial material. A changed reference
                // explicitly requests a rotation. When adopting an existing
                // confidential client that has a secret but no marker, preserve
                // its current secret and only stamp the reference.
                current.ClientSecret = await ResolveSecretAsync(
                    manifest.SecretReference!,
                    cancellationToken);
            }

            await _applications.UpdateAsync(application, current, cancellationToken);
        }

        return new IdentityManifestChange(
            "client",
            manifest.ClientId,
            IdentityManifestChangeKind.Update);
    }

    private async ValueTask<string> ResolveSecretAsync(
        string reference,
        CancellationToken cancellationToken)
    {
        var secret = await _secrets.ResolveAsync(reference, cancellationToken);
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new ClientSecretResolutionException();
        }

        return secret;
    }

    private static OpenIddictScopeDescriptor CreateScopeDescriptor(
        int schemaVersion,
        IdentityScopeManifest manifest)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = manifest.Name,
            DisplayName = manifest.DisplayName,
            Description = manifest.Description,
        };

        descriptor.Resources.UnionWith(manifest.Resources);
        SetManifestProperties(descriptor.Properties, schemaVersion, secretReference: null);
        return descriptor;
    }

    private static OpenIddictApplicationDescriptor CreateApplicationDescriptor(
        int schemaVersion,
        IdentityClientManifest manifest)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = manifest.ClientId,
            ClientType = manifest.ClientType switch
            {
                ManifestClientTypes.Public => OpenIddictConstants.ClientTypes.Public,
                ManifestClientTypes.Confidential => OpenIddictConstants.ClientTypes.Confidential,
                _ => throw new UnreachableException(),
            },
            ConsentType = manifest.ConsentType switch
            {
                ManifestConsentTypes.Explicit => OpenIddictConstants.ConsentTypes.Explicit,
                ManifestConsentTypes.External => OpenIddictConstants.ConsentTypes.External,
                ManifestConsentTypes.Implicit => OpenIddictConstants.ConsentTypes.Implicit,
                ManifestConsentTypes.Systematic => OpenIddictConstants.ConsentTypes.Systematic,
                _ => throw new UnreachableException(),
            },
            DisplayName = manifest.DisplayName,
        };

        foreach (var grant in manifest.GrantTypes)
        {
            descriptor.Permissions.Add(grant switch
            {
                ManifestGrantTypes.AuthorizationCode =>
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                ManifestGrantTypes.ClientCredentials =>
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                ManifestGrantTypes.DeviceCode =>
                    OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
                ManifestGrantTypes.RefreshToken =>
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                ManifestGrantTypes.TokenExchange =>
                    OpenIddictConstants.Permissions.GrantTypes.TokenExchange,
                _ => throw new UnreachableException(),
            });
        }

        if (manifest.GrantTypes.Contains(
                ManifestGrantTypes.AuthorizationCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.EndSession);
        }

        if (manifest.GrantTypes.Contains(
                ManifestGrantTypes.ClientCredentials,
                StringComparer.Ordinal) ||
            manifest.GrantTypes.Contains(
                ManifestGrantTypes.RefreshToken,
                StringComparer.Ordinal) ||
            manifest.GrantTypes.Contains(
                ManifestGrantTypes.TokenExchange,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        }

        if (manifest.GrantTypes.Contains(
                ManifestGrantTypes.DeviceCode,
                StringComparer.Ordinal))
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        }

        foreach (var responseType in manifest.ResponseTypes)
        {
            descriptor.Permissions.Add(responseType switch
            {
                ManifestResponseTypes.Code =>
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                _ => throw new UnreachableException(),
            });
        }

        foreach (var scope in manifest.Scopes)
        {
            descriptor.Permissions.Add(
                OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        descriptor.RedirectUris.UnionWith(manifest.RedirectUris);
        descriptor.PostLogoutRedirectUris.UnionWith(manifest.PostLogoutRedirectUris);

        if (manifest.RequirePkce)
        {
            descriptor.Requirements.Add(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        SetManifestProperties(
            descriptor.Properties,
            schemaVersion,
            manifest.SecretReference);

        return descriptor;
    }

    private static void ApplyManagedScopeValues(
        OpenIddictScopeDescriptor target,
        OpenIddictScopeDescriptor source)
    {
        target.Name = source.Name;
        target.DisplayName = source.DisplayName;
        target.Description = source.Description;
        target.Resources.Clear();
        target.Resources.UnionWith(source.Resources);
        CopyManifestProperties(target.Properties, source.Properties);
    }

    private static void ApplyManagedApplicationValues(
        OpenIddictApplicationDescriptor target,
        OpenIddictApplicationDescriptor source)
    {
        target.ClientId = source.ClientId;
        target.ClientType = source.ClientType;
        target.ConsentType = source.ConsentType;
        target.DisplayName = source.DisplayName;

        target.Permissions.Clear();
        target.Permissions.UnionWith(source.Permissions);
        target.RedirectUris.Clear();
        target.RedirectUris.UnionWith(source.RedirectUris);
        target.PostLogoutRedirectUris.Clear();
        target.PostLogoutRedirectUris.UnionWith(source.PostLogoutRedirectUris);
        target.Requirements.Clear();
        target.Requirements.UnionWith(source.Requirements);

        CopyManifestProperties(target.Properties, source.Properties);
    }

    private static bool ScopeEquals(
        OpenIddictScopeDescriptor current,
        OpenIddictScopeDescriptor desired) =>
        string.Equals(current.Name, desired.Name, StringComparison.Ordinal) &&
        string.Equals(current.DisplayName, desired.DisplayName, StringComparison.Ordinal) &&
        string.Equals(current.Description, desired.Description, StringComparison.Ordinal) &&
        current.Resources.SetEquals(desired.Resources) &&
        ManifestPropertiesEqual(current.Properties, desired.Properties);

    private static bool ApplicationEquals(
        OpenIddictApplicationDescriptor current,
        OpenIddictApplicationDescriptor desired) =>
        string.Equals(current.ClientId, desired.ClientId, StringComparison.Ordinal) &&
        string.Equals(current.ClientType, desired.ClientType, StringComparison.Ordinal) &&
        string.Equals(current.ConsentType, desired.ConsentType, StringComparison.Ordinal) &&
        string.Equals(current.DisplayName, desired.DisplayName, StringComparison.Ordinal) &&
        current.Permissions.SetEquals(desired.Permissions) &&
        current.RedirectUris.Select(uri => uri.OriginalString).ToHashSet(StringComparer.Ordinal)
            .SetEquals(desired.RedirectUris.Select(uri => uri.OriginalString)) &&
        current.PostLogoutRedirectUris.Select(uri => uri.OriginalString)
            .ToHashSet(StringComparer.Ordinal)
            .SetEquals(desired.PostLogoutRedirectUris.Select(uri => uri.OriginalString)) &&
        current.Requirements.SetEquals(desired.Requirements) &&
        ManifestPropertiesEqual(current.Properties, desired.Properties);

    private static bool ManifestPropertiesEqual(
        IDictionary<string, JsonElement> current,
        IDictionary<string, JsonElement> desired) =>
        GetInt32Property(current, SchemaVersionProperty) ==
        GetInt32Property(desired, SchemaVersionProperty) &&
        string.Equals(
            GetStringProperty(current, SecretReferenceProperty),
            GetStringProperty(desired, SecretReferenceProperty),
            StringComparison.Ordinal);

    private static void SetManifestProperties(
        IDictionary<string, JsonElement> properties,
        int schemaVersion,
        string? secretReference)
    {
        properties[SchemaVersionProperty] = JsonSerializer.SerializeToElement(schemaVersion);

        if (string.IsNullOrEmpty(secretReference))
        {
            properties.Remove(SecretReferenceProperty);
        }
        else
        {
            properties[SecretReferenceProperty] =
                JsonSerializer.SerializeToElement(secretReference);
        }
    }

    private static void CopyManifestProperties(
        IDictionary<string, JsonElement> target,
        IDictionary<string, JsonElement> source)
    {
        target[SchemaVersionProperty] = source[SchemaVersionProperty];

        if (source.TryGetValue(SecretReferenceProperty, out var secretReference))
        {
            target[SecretReferenceProperty] = secretReference;
        }
        else
        {
            target.Remove(SecretReferenceProperty);
        }
    }

    private static int? GetInt32Property(
        IDictionary<string, JsonElement> properties,
        string name) =>
        properties.TryGetValue(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt32(out var result)
            ? result
            : null;

    private static string? GetStringProperty(
        IDictionary<string, JsonElement> properties,
        string name) =>
        properties.TryGetValue(name, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
