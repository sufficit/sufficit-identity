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
public sealed partial class OpenIddictManifestProvisioner
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

    private static readonly string[] ManagedLogoutSettingKeys =
    [
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
        "backchannel_logout_uri",
        "backchannel_logout_session_required",
    ];

}
