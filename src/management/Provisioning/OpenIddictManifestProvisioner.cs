using System.Diagnostics;
using System.Text.Json;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Provisioning;

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
    internal const string OwnerProperty =
        "identity:provisioning-manifest:owner";
    internal const string ManifestIdentityProperty =
        "identity:provisioning-manifest:identity";
    private const string ProvisioningOwner = "provisioning";

    private readonly IOpenIddictApplicationManager _applications;
    private readonly IOpenIddictScopeManager _scopes;
    private readonly IClientSecretResolver _secrets;
    private readonly IReservedScopePolicy _reservedScopePolicy;
    private readonly IClientDefinitionValidator _clientDefinitionValidator;

    public OpenIddictManifestProvisioner(
        IOpenIddictApplicationManager applications,
        IOpenIddictScopeManager scopes,
        IClientSecretResolver secrets,
        IReservedScopePolicy? reservedScopePolicy = null,
        IClientDefinitionValidator? clientDefinitionValidator = null)
    {
        _applications = applications;
        _scopes = scopes;
        _secrets = secrets;
        _reservedScopePolicy = reservedScopePolicy ?? new ReservedScopePolicy(
            ["identity.management", "scim"]);
        _clientDefinitionValidator = clientDefinitionValidator
            ?? new ClientDefinitionValidator(_reservedScopePolicy);
    }

    public Task<IdentityProvisioningPlan> PreviewAsync(
        IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken = default,
        string? actorSubject = null) =>
        ProcessAsync(manifest, apply: false, cancellationToken, actorSubject);

    public Task<IdentityProvisioningPlan> ApplyAsync(
        IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken = default,
        string? actorSubject = null) =>
        ProcessAsync(manifest, apply: true, cancellationToken, actorSubject);

    /// <summary>
    /// Builds a non-mutating inventory of manifest ownership and drift. It
    /// deliberately never resolves client secrets, so operators can run it
    /// before approving an adoption or enabling Enforce mode.
    /// </summary>
    public async Task<IdentityProvisioningInventory> InventoryAsync(
        IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken = default)
    {
        IdentityProvisioningManifestValidator.ValidateAndThrow(
            manifest,
            _reservedScopePolicy,
            _clientDefinitionValidator);

        var declaredIds = manifest.Clients
            .Select(client => client.ClientId)
            .ToHashSet(StringComparer.Ordinal);
        var entries = new List<IdentityManifestInventoryEntry>();

        foreach (var client in manifest.Clients.OrderBy(
                     client => client.ClientId,
                     StringComparer.Ordinal))
        {
            var manifestIdentity = GetManifestIdentity(
                manifest.ManifestId,
                "client:" + client.ClientId);
            var application = await _applications.FindByClientIdAsync(
                client.ClientId,
                cancellationToken);

            if (application is null)
            {
                entries.Add(new IdentityManifestInventoryEntry(
                    client.ClientId,
                    IdentityManifestInventoryStatus.DeclaredMissing,
                    manifestIdentity));
                continue;
            }

            var current = new OpenIddictApplicationDescriptor();
            await _applications.PopulateAsync(
                current,
                application,
                cancellationToken);

            var currentOwner = GetStringProperty(
                current.Properties,
                OwnerProperty);
            var currentIdentity = GetStringProperty(
                current.Properties,
                ManifestIdentityProperty);
            var schemaVersion = GetInt32Property(
                current.Properties,
                SchemaVersionProperty);
            var managedByThisManifest =
                string.Equals(currentOwner, ProvisioningOwner, StringComparison.Ordinal)
                && string.Equals(
                    currentIdentity,
                    manifestIdentity,
                    StringComparison.Ordinal);

            var status = !string.Equals(
                    currentOwner,
                    ProvisioningOwner,
                    StringComparison.Ordinal)
                ? IdentityManifestInventoryStatus.DeclaredUnmanaged
                : !managedByThisManifest
                    ? IdentityManifestInventoryStatus.DeclaredOwnedByAnotherManifest
                    : ApplicationEquals(
                        current,
                        CreateApplicationDescriptor(
                            manifest.SchemaVersion,
                            client,
                            manifestIdentity))
                        ? IdentityManifestInventoryStatus.DeclaredCurrent
                        : IdentityManifestInventoryStatus.DeclaredDrifted;

            entries.Add(new IdentityManifestInventoryEntry(
                client.ClientId,
                status,
                currentIdentity,
                schemaVersion));
        }

        await foreach (var application in _applications.ListAsync(
                           cancellationToken: cancellationToken))
        {
            var clientId = (string?)await _applications.GetClientIdAsync(
                application,
                cancellationToken);
            if (string.IsNullOrWhiteSpace(clientId) ||
                declaredIds.Contains(clientId))
            {
                continue;
            }

            var current = new OpenIddictApplicationDescriptor();
            await _applications.PopulateAsync(
                current,
                application,
                cancellationToken);
            var owner = GetStringProperty(current.Properties, OwnerProperty);
            entries.Add(new IdentityManifestInventoryEntry(
                clientId,
                string.Equals(owner, ProvisioningOwner, StringComparison.Ordinal)
                    ? IdentityManifestInventoryStatus.ManagedButUndeclared
                    : IdentityManifestInventoryStatus.UnmanagedAndUndeclared,
                GetStringProperty(current.Properties, ManifestIdentityProperty),
                GetInt32Property(current.Properties, SchemaVersionProperty)));
        }

        return new IdentityProvisioningInventory(
            entries
                .OrderBy(entry => entry.ClientId, StringComparer.Ordinal)
                .ToArray(),
            manifest.ManifestId,
            DateTimeOffset.UtcNow);
    }

    private async Task<IdentityProvisioningPlan> ProcessAsync(
        IdentityProvisioningManifest manifest,
        bool apply,
        CancellationToken cancellationToken,
        string? actorSubject)
    {
        IdentityProvisioningManifestValidator.ValidateAndThrow(
            manifest,
            _reservedScopePolicy,
            _clientDefinitionValidator);

        var changes = new List<IdentityManifestChange>(
            manifest.Scopes.Count + manifest.Clients.Count);

        foreach (var scope in manifest.Scopes.OrderBy(scope => scope.Name, StringComparer.Ordinal))
        {
            changes.Add(await ProcessScopeAsync(
                manifest.ManifestId,
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
                manifest.ManifestId,
                manifest.SchemaVersion,
                client,
                apply,
                cancellationToken,
                actorSubject,
                manifest.RolloutMode));
        }

        return new IdentityProvisioningPlan(changes);
    }

    private async Task<IdentityManifestChange> ProcessScopeAsync(
        string? manifestId,
        int schemaVersion,
        IdentityScopeManifest manifest,
        bool apply,
        CancellationToken cancellationToken)
    {
        var desired = CreateScopeDescriptor(
            schemaVersion,
            manifest,
            GetManifestIdentity(manifestId, "scope:" + manifest.Name));
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
        string? manifestId,
        int schemaVersion,
        IdentityClientManifest manifest,
        bool apply,
        CancellationToken cancellationToken,
        string? actorSubject,
        ClientDefinitionRolloutMode rolloutMode)
    {
        var manifestIdentity = GetManifestIdentity(
            manifestId,
            "client:" + manifest.ClientId);
        var desired = CreateApplicationDescriptor(
            schemaVersion,
            manifest,
            manifestIdentity);
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

        var currentOwner = GetStringProperty(
            current.Properties,
            OwnerProperty);
        var currentIdentity = GetStringProperty(
            current.Properties,
            ManifestIdentityProperty);
        var managedByThisManifest =
            string.Equals(currentOwner, ProvisioningOwner, StringComparison.Ordinal)
            && string.Equals(
                currentIdentity,
                manifestIdentity,
                StringComparison.Ordinal);
        if (!managedByThisManifest && !manifest.AdoptExisting)
        {
            throw new IdentityProvisioningManifestException([
                $"clients[{manifest.ClientId}] is not owned by this manifest. " +
                "Set adoptExisting=true to authorize an explicit audited adoption."]);
        }

        var adopted = !managedByThisManifest;

        var transitionValidation = _clientDefinitionValidator.Validate(
            new ClientDefinitionRequest(
                ClientDefinitionSource.Provisioning,
                manifest.ClientId,
                manifest.ClientType,
                manifest.GrantTypes,
                manifest.Scopes,
                manifest.RedirectUris,
                manifest.RequirePkce,
                manifest.ClientType == ManifestClientTypes.Confidential,
                RolloutMode: rolloutMode,
                ActorSubject: actorSubject,
                Current: Snapshot(current),
                AuthorizeSensitiveTransitions:
                    manifest.AuthorizeSensitiveTransitions));
        if (!transitionValidation.IsValid)
        {
            throw new IdentityProvisioningManifestException(
                transitionValidation.Issues.Select(issue =>
                    $"clients[{manifest.ClientId}].{issue.Code} " +
                    $"({issue.Field}): {issue.Message}")
                    .ToArray());
        }

        if (transitionValidation.HasObservedIssues)
        {
            return new IdentityManifestChange(
                "client",
                manifest.ClientId,
                IdentityManifestChangeKind.Observed);
        }

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
            adopted
                ? IdentityManifestChangeKind.Adopted
                : IdentityManifestChangeKind.Update);
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
        IdentityScopeManifest manifest,
        string manifestIdentity)
    {
        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = manifest.Name,
            DisplayName = manifest.DisplayName,
            Description = manifest.Description,
        };

        descriptor.Resources.UnionWith(manifest.Resources);
        SetManifestProperties(
            descriptor.Properties,
            schemaVersion,
            secretReference: null,
            manifestIdentity);
        return descriptor;
    }

    private OpenIddictApplicationDescriptor CreateApplicationDescriptor(
        int schemaVersion,
        IdentityClientManifest manifest,
        string manifestIdentity)
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
        SetNativeReturnUris(descriptor.Properties, manifest.NativeReturnUris);
        SetLogoutSettings(descriptor.Settings, manifest);

        if (_clientDefinitionValidator.RequiresProofKeyForCodeExchange(
                manifest.GrantTypes))
        {
            descriptor.Requirements.Add(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        SetManifestProperties(
            descriptor.Properties,
            schemaVersion,
            manifest.SecretReference,
            manifestIdentity);

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

        CopyManagedLogoutSettings(target.Settings, source.Settings);

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
        ManagedLogoutSettingsEqual(current.Settings, desired.Settings) &&
        ManifestPropertiesEqual(current.Properties, desired.Properties);

    private static ClientDefinitionSnapshot Snapshot(
        OpenIddictApplicationDescriptor descriptor) =>
        new(
            descriptor.ClientType ?? "",
            !string.IsNullOrEmpty(descriptor.ClientSecret),
            descriptor.Permissions.ToHashSet(StringComparer.Ordinal),
            descriptor.Permissions
                .Where(permission => permission.StartsWith(
                    OpenIddictConstants.Permissions.Prefixes.Scope,
                    StringComparison.Ordinal))
                .Select(permission => permission[
                    OpenIddictConstants.Permissions.Prefixes.Scope.Length..])
                .ToHashSet(StringComparer.Ordinal),
            descriptor.RedirectUris
                .Select(uri => uri.OriginalString)
                .ToHashSet(StringComparer.Ordinal));

    private static readonly string[] ManagedLogoutSettingKeys =
    [
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
        "backchannel_logout_uri",
        "backchannel_logout_session_required",
    ];

    private static void SetLogoutSettings(
        IDictionary<string, string> settings,
        IdentityClientManifest manifest)
    {
        if (manifest.FrontchannelLogoutUri is not null)
        {
            settings["frontchannel_logout_uri"] =
                manifest.FrontchannelLogoutUri.AbsoluteUri;
            settings["frontchannel_logout_session_required"] =
                manifest.FrontchannelLogoutSessionRequired ? "true" : "false";
        }

        if (manifest.BackchannelLogoutUri is not null)
        {
            settings["backchannel_logout_uri"] =
                manifest.BackchannelLogoutUri.AbsoluteUri;
            settings["backchannel_logout_session_required"] =
                manifest.BackchannelLogoutSessionRequired ? "true" : "false";
        }
    }

    private static void CopyManagedLogoutSettings(
        IDictionary<string, string> target,
        IDictionary<string, string> source)
    {
        foreach (var key in ManagedLogoutSettingKeys)
        {
            if (source.TryGetValue(key, out var value))
            {
                target[key] = value;
            }
            else
            {
                target.Remove(key);
            }
        }
    }

    private static bool ManagedLogoutSettingsEqual(
        IDictionary<string, string> current,
        IDictionary<string, string> desired) =>
        ManagedLogoutSettingKeys.All(key =>
            current.TryGetValue(key, out var currentValue) ==
            desired.TryGetValue(key, out var desiredValue) &&
            string.Equals(currentValue, desiredValue, StringComparison.Ordinal));

    private static bool ManifestPropertiesEqual(
        IDictionary<string, JsonElement> current,
        IDictionary<string, JsonElement> desired) =>
        GetInt32Property(current, SchemaVersionProperty) ==
        GetInt32Property(desired, SchemaVersionProperty) &&
        string.Equals(
            GetStringProperty(current, OwnerProperty),
            GetStringProperty(desired, OwnerProperty),
            StringComparison.Ordinal) &&
        string.Equals(
            GetStringProperty(current, ManifestIdentityProperty),
            GetStringProperty(desired, ManifestIdentityProperty),
            StringComparison.Ordinal) &&
        string.Equals(
            GetStringProperty(current, SecretReferenceProperty),
            GetStringProperty(desired, SecretReferenceProperty),
            StringComparison.Ordinal) &&
        NativeReturnUrisEqual(current, desired);

    private static void SetManifestProperties(
        IDictionary<string, JsonElement> properties,
        int schemaVersion,
        string? secretReference,
        string manifestIdentity)
    {
        properties[SchemaVersionProperty] = JsonSerializer.SerializeToElement(schemaVersion);
        properties[OwnerProperty] = JsonSerializer.SerializeToElement(ProvisioningOwner);
        properties[ManifestIdentityProperty] =
            JsonSerializer.SerializeToElement(manifestIdentity);

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

        target[OwnerProperty] = source[OwnerProperty];
        target[ManifestIdentityProperty] = source[ManifestIdentityProperty];

        if (source.TryGetValue(SecretReferenceProperty, out var secretReference))
        {
            target[SecretReferenceProperty] = secretReference;
        }
        else
        {
            target.Remove(SecretReferenceProperty);
        }

        if (source.TryGetValue(NativeReturnUriPolicy.PropertyKey, out var returnUris))
        {
            target[NativeReturnUriPolicy.PropertyKey] = returnUris;
        }
        else
        {
            target.Remove(NativeReturnUriPolicy.PropertyKey);
        }
    }

    /// <summary>
    /// Writes the manifest's native callbacks into the client property bag,
    /// removing the key when the manifest declares none.
    /// </summary>
    private static void SetNativeReturnUris(
        IDictionary<string, JsonElement> properties,
        IReadOnlyList<string> values)
    {
        var normalized = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (normalized.Length == 0)
        {
            properties.Remove(NativeReturnUriPolicy.PropertyKey);
            return;
        }

        properties[NativeReturnUriPolicy.PropertyKey] =
            JsonSerializer.SerializeToElement(normalized);
    }

    private static bool NativeReturnUrisEqual(
        IDictionary<string, JsonElement> current,
        IDictionary<string, JsonElement> desired) =>
        ReadNativeReturnUris(current).SequenceEqual(
            ReadNativeReturnUris(desired),
            StringComparer.Ordinal);

    private static IReadOnlyList<string> ReadNativeReturnUris(
        IDictionary<string, JsonElement> properties) =>
        properties.TryGetValue(NativeReturnUriPolicy.PropertyKey, out var value)
        && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
                .Where(element => element.ValueKind == JsonValueKind.String)
                .Select(element => element.GetString()!)
                .ToArray()
            : [];

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

    private static string GetManifestIdentity(
        string? manifestId,
        string fallback) =>
        string.IsNullOrWhiteSpace(manifestId)
            ? fallback
            : manifestId.Trim();
}
