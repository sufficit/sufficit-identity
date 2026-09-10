using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Scopes;

internal sealed partial class ScopeManagementService
{
    public async Task<ManagementAudienceInventory> ListAudiencesAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await guard.DemandAsync(context, ManagementCapabilities.ScopesRead,
            new ManagementResource(ManagementResourceTypes.ScopeCollection), cancellationToken);
        var usage = await ListClientUsageAsync(cancellationToken);
        var definitions = new List<ManagementScopeDetail>();
        await foreach (var scope in scopes.ListAsync(cancellationToken: cancellationToken))
        {
            var id = await scopes.GetIdAsync(scope, cancellationToken);
            var name = await scopes.GetNameAsync(scope, cancellationToken);
            if (id is null || name is null) continue;
            var properties = await scopes.GetPropertiesAsync(scope, cancellationToken);
            definitions.Add(new ManagementScopeDetail(id, name,
                await scopes.GetDisplayNameAsync(scope, cancellationToken),
                await scopes.GetDescriptionAsync(scope, cancellationToken),
                (await scopes.GetResourcesAsync(scope, cancellationToken)).Order(StringComparer.Ordinal).ToArray(),
                usage.TryGetValue(name, out var clients) ? clients.Order(StringComparer.Ordinal).ToArray() : [],
                properties.ContainsKey(OpenIddictManifestProvisioner.SchemaVersionProperty)));
        }

        var ordered = definitions.OrderBy(scope => scope.Name, StringComparer.Ordinal).ToArray();
        var audiences = ordered.SelectMany(scope => scope.Resources.Select(name => (name, scope)))
            .GroupBy(binding => binding.name, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new ManagementAudienceSummary(group.Key,
                group.Select(binding => binding.scope).ToArray(),
                group.SelectMany(binding => binding.scope.ClientIds)
                    .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray()))
            .ToArray();
        return new ManagementAudienceInventory(audiences, ordered);
    }

    public async Task<ManagementScopeDetail> UpdateAudienceBindingAsync(
        string scopeId,
        UpdateAudienceBindingCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeId);
        ArgumentNullException.ThrowIfNull(command);
        await guard.DemandAsync(context, ManagementCapabilities.ScopesUpdate,
            new ManagementResource(ManagementResourceTypes.Scope, scopeId), cancellationToken,
            auditDenial: true);
        var scope = await scopes.FindByIdAsync(scopeId, cancellationToken)
            ?? throw new ManagementNotFoundException("scope_not_found", "O scope não foi encontrado.");
        await DemandManuallyManagedAsync(scope, cancellationToken);
        var name = await scopes.GetNameAsync(scope, cancellationToken);
        if (command.Assigned && (ProtocolScopes.Contains(name ?? string.Empty)
            || name is "entitlements" or "directives"
            || ReservedApiScopes.Contains(name, StringComparer.Ordinal)
            || RetiredIdentityScopes.Contains(name)))
        {
            throw new ManagementValidationException("audience_scope_not_editable",
                "Use um scope de acesso à API. Scopes de claims ou reservados não recebem novas audiências por esta tela.", "scopeId");
        }

        var audience = ValidateResources([command.Audience]).Single();
        if (audience.Any(char.IsWhiteSpace))
            throw new ManagementValidationException("scope_resource_invalid",
                "O identificador da audiência não pode conter espaços.", "audience");
        var expected = ValidateResources(command.ExpectedResources);
        var current = await scopes.GetResourcesAsync(scope, cancellationToken);
        if (!expected.SetEquals(current))
            throw new ManagementConflictException("audience_bindings_changed",
                "Os vínculos deste scope mudaram. Atualize a lista e revise a operação.");

        var resources = current.ToHashSet(StringComparer.Ordinal);
        if (command.Assigned) resources.Add(audience);
        else resources.Remove(audience);
        // Reuse the canonical scoped write, its transaction, optimistic entity
        // concurrency, manifest guard and audit. Never replace names or metadata.
        return await UpdateAsync(scopeId, new UpdateManagementScopeCommand(
            await scopes.GetDisplayNameAsync(scope, cancellationToken),
            await scopes.GetDescriptionAsync(scope, cancellationToken),
            resources.Order(StringComparer.Ordinal).ToArray()), context, cancellationToken);
    }
}
