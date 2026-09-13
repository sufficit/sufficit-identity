using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OAuthScopes = OpenIddict.Abstractions.OpenIddictConstants.Scopes;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Scopes;

internal sealed partial class ScopeManagementService(
    IOpenIddictScopeManager scopes,
    IOpenIddictApplicationManager applications,
    AppDbContext database,
    Microsoft.Extensions.Options.IOptions<ManagementOptions> managementOptions,
    ILogger<ScopeManagementService> logger,
    ManagementOperationGuard guard) : IScopeManagementService
{
    private string[] ReservedApiScopes => managementOptions.Value.ReservedApiScopes;

    private const int DisplayNameMaxLength = 200;
    private const int DescriptionMaxLength = 1000;
    private const int ResourceMaxLength = 512;
    private const int ResourceCountLimit = 100;

    private static readonly HashSet<string> ProtocolScopes =
        new(StringComparer.Ordinal)
        {
            OAuthScopes.OpenId,
            OAuthScopes.OfflineAccess,
            OAuthScopes.Profile,
            OAuthScopes.Email,
            OAuthScopes.Phone,
            OAuthScopes.Address,
            OAuthScopes.Roles
        };

    public async Task<IReadOnlyList<ManagementScopeSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = new ManagementResource(
            ManagementResourceTypes.ScopeCollection);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ScopesRead,
            resource,
            cancellationToken);
        var usage = await ListClientUsageAsync(cancellationToken);
        var result = new List<ManagementScopeSummary>();

        await foreach (var scope in scopes.ListAsync(
            cancellationToken: cancellationToken))
        {
            var id = (string?)await scopes.GetIdAsync(
                scope,
                cancellationToken);
            var name = (string?)await scopes.GetNameAsync(
                scope,
                cancellationToken);
            if (id is null || name is null)
            {
                continue;
            }

            var resources = await scopes.GetResourcesAsync(
                scope,
                cancellationToken);
            var properties = await scopes.GetPropertiesAsync(
                scope,
                cancellationToken);
            result.Add(new ManagementScopeSummary(
                id,
                name,
                (string?)await scopes.GetDisplayNameAsync(
                    scope,
                    cancellationToken),
                (string?)await scopes.GetDescriptionAsync(
                    scope,
                    cancellationToken),
                resources.Length,
                usage.TryGetValue(name, out var clients)
                    ? clients.Count
                    : 0,
                properties.ContainsKey(
                    OpenIddictManifestProvisioner.SchemaVersionProperty)));
        }

        // L3 fix (eval): no audit row on read paths.

        return result
            .OrderBy(scope => scope.DisplayName ?? scope.Name,
                StringComparer.OrdinalIgnoreCase)
            .ThenBy(scope => scope.Name, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<ManagementScopeDetail> GetAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var resource = new ManagementResource(
            ManagementResourceTypes.Scope,
            id);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ScopesRead,
            resource,
            cancellationToken);
        var scope = await scopes.FindByIdAsync(id, cancellationToken);
        if (scope is null)
        {
            throw new ManagementNotFoundException(
                "scope_not_found",
                "The scope was not found.");
        }

        var detail = await ToDetailAsync(scope, cancellationToken);
        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ScopesRead,
                resource,
                decision,
                "succeeded",
                "scope_read"));
        await database.SaveChangesAsync(cancellationToken);
        return detail;
    }

    public async Task<ManagementScopeDetail> CreateAsync(
        CreateManagementScopeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var name = ValidateName(command.Name);
        var resource = new ManagementResource(
            ManagementResourceTypes.Scope,
            name);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ScopesCreate,
            resource,
            cancellationToken,
            auditDenial: true);
        if (await scopes.FindByNameAsync(name, cancellationToken) is not null)
        {
            throw new ManagementConflictException(
                "scope_already_exists",
                "A scope with this name already exists.");
        }

        var descriptor = new OpenIddictScopeDescriptor
        {
            Name = name,
            DisplayName = ValidateOptional(
                command.DisplayName,
                DisplayNameMaxLength,
                "scope_display_name_too_long",
                "displayName"),
            Description = ValidateOptional(
                command.Description,
                DescriptionMaxLength,
                "scope_description_too_long",
                "description")
        };
        descriptor.Resources.UnionWith(
            ValidateResources(command.Resources));

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var scope = await scopes.CreateAsync(
                descriptor,
                cancellationToken);
            var detail = await ToDetailAsync(scope, cancellationToken);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ScopesCreate,
                    new ManagementResource(
                        ManagementResourceTypes.Scope,
                        detail.Id),
                    decision,
                    "succeeded",
                    "scope_created"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return detail;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
            when (exception is not ManagementConflictException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to create OAuth scope {ScopeName}. CorrelationId={CorrelationId}",
                name,
                context.CorrelationId);
            throw new ManagementConflictException(
                "scope_create_failed",
                "The scope could not be created.");
        }
    }

    public async Task<ManagementScopeDetail> UpdateAsync(
        string id,
        UpdateManagementScopeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var resource = new ManagementResource(
            ManagementResourceTypes.Scope,
            id);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ScopesUpdate,
            resource,
            cancellationToken,
            auditDenial: true);
        var scope = await scopes.FindByIdAsync(id, cancellationToken);
        if (scope is null)
        {
            throw new ManagementNotFoundException(
                "scope_not_found",
                "The scope was not found.");
        }
        await DemandManuallyManagedAsync(scope, cancellationToken);

        var descriptor = new OpenIddictScopeDescriptor();
        await scopes.PopulateAsync(
            descriptor,
            scope,
            cancellationToken);
        descriptor.DisplayName = ValidateOptional(
            command.DisplayName,
            DisplayNameMaxLength,
            "scope_display_name_too_long",
            "displayName");
        descriptor.Description = ValidateOptional(
            command.Description,
            DescriptionMaxLength,
            "scope_description_too_long",
            "description");
        descriptor.Resources.Clear();
        descriptor.Resources.UnionWith(
            ValidateResources(command.Resources));

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            await scopes.UpdateAsync(
                scope,
                descriptor,
                cancellationToken);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ScopesUpdate,
                    resource,
                    decision,
                    "succeeded",
                    "scope_updated"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return await ToDetailAsync(scope, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to update OAuth scope {ScopeId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            throw new ManagementConflictException(
                "scope_update_failed",
                "The scope could not be updated.");
        }
    }

    public async Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var resource = new ManagementResource(
            ManagementResourceTypes.Scope,
            id);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ScopesDelete,
            resource,
            cancellationToken,
            auditDenial: true);
        var scope = await scopes.FindByIdAsync(id, cancellationToken);
        if (scope is null)
        {
            throw new ManagementNotFoundException(
                "scope_not_found",
                "The scope was not found.");
        }
        await DemandManuallyManagedAsync(scope, cancellationToken);

        var name = (string?)await scopes.GetNameAsync(
            scope,
            cancellationToken)
            ?? throw new ManagementConflictException(
                "scope_name_missing",
                "The scope does not have a valid name.");
        var usage = await ListClientUsageAsync(cancellationToken);
        if (usage.TryGetValue(name, out var clients) && clients.Count > 0)
        {
            throw new ManagementConflictException(
                "scope_in_use",
                $"Remove the scope from clients before deleting it ({clients.Count} client(s) still use it).");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            await scopes.DeleteAsync(scope, cancellationToken);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ScopesDelete,
                    resource,
                    decision,
                    "succeeded",
                    "scope_deleted"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to delete OAuth scope {ScopeId}. CorrelationId={CorrelationId}",
                id,
                context.CorrelationId);
            throw new ManagementConflictException(
                "scope_delete_failed",
                "The scope could not be deleted.");
        }
    }

    private async Task<ManagementScopeDetail> ToDetailAsync(
        object scope,
        CancellationToken cancellationToken)
    {
        var id = (string?)await scopes.GetIdAsync(scope, cancellationToken)
            ?? throw new InvalidOperationException(
                "The OpenIddict scope has no identifier.");
        var name = (string?)await scopes.GetNameAsync(scope, cancellationToken)
            ?? throw new InvalidOperationException(
                "The OpenIddict scope has no name.");
        var usage = await ListClientUsageAsync(cancellationToken);
        var resources = await scopes.GetResourcesAsync(
            scope,
            cancellationToken);
        var properties = await scopes.GetPropertiesAsync(
            scope,
            cancellationToken);

        return new ManagementScopeDetail(
            id,
            name,
            (string?)await scopes.GetDisplayNameAsync(
                scope,
                cancellationToken),
            (string?)await scopes.GetDescriptionAsync(
                scope,
                cancellationToken),
            resources.Order(StringComparer.Ordinal).ToArray(),
            usage.TryGetValue(name, out var clients)
                ? clients.Order(StringComparer.Ordinal).ToArray()
                : [],
            properties.ContainsKey(
                OpenIddictManifestProvisioner.SchemaVersionProperty));
    }

    private async Task DemandManuallyManagedAsync(
        object scope,
        CancellationToken cancellationToken)
    {
        var properties = await scopes.GetPropertiesAsync(
            scope,
            cancellationToken);
        if (properties.ContainsKey(
                OpenIddictManifestProvisioner.SchemaVersionProperty))
        {
            throw new ManagementConflictException(
                "scope_manifest_managed",
                "This scope is managed by the declarative manifest. Change the manifest and apply provisioning.");
        }
    }

    private async Task<Dictionary<string, HashSet<string>>>
        ListClientUsageAsync(CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, HashSet<string>>(
            StringComparer.Ordinal);
        await foreach (var application in applications.ListAsync(
            cancellationToken: cancellationToken))
        {
            var clientId = (string?)await applications.GetClientIdAsync(
                application,
                cancellationToken);
            if (clientId is null)
            {
                continue;
            }

            var permissions = await applications.GetPermissionsAsync(
                application,
                cancellationToken);
            foreach (var permission in permissions)
            {
                if (!permission.StartsWith(
                        Permissions.Prefixes.Scope,
                        StringComparison.Ordinal))
                {
                    continue;
                }

                var scopeName = permission[
                    Permissions.Prefixes.Scope.Length..];
                if (!result.TryGetValue(scopeName, out var clients))
                {
                    clients = new HashSet<string>(StringComparer.Ordinal);
                    result.Add(scopeName, clients);
                }
                clients.Add(clientId);
            }
        }

        return result;
    }


    private string ValidateName(string? value)
    {
        var name = value?.Trim();
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ManagementValidationException(
                "scope_name_required",
                "Provide the scope name.",
                "name");
        }
        if (name.Length > IdentityDatabaseSchema.OpenIddictScopeNameLength)
        {
            throw new ManagementValidationException(
                "scope_name_too_long",
                $"Use at most {IdentityDatabaseSchema.OpenIddictScopeNameLength} characters.",
                "name");
        }
        if (name.Any(character =>
                character < '\u0021'
                || character > '\u007e'
                || character is '"' or '\\'))
        {
            throw new ManagementValidationException(
                "scope_name_invalid",
                "Use an OAuth scope token without spaces, quotes, or backslashes.",
                "name");
        }
        if (ProtocolScopes.Contains(name))
        {
            throw new ManagementValidationException(
                "scope_name_reserved",
                "This scope is defined by the protocol and must not be registered as a custom scope.",
                "name");
        }
        if (RetiredIdentityScopes.Contains(name))
        {
            throw new ManagementValidationException(
                "scope_retired",
                "This scope has been retired and cannot be created again.",
                "name");
        }
        // H2/M3 fix (eval): API-protection scopes (management, SCIM, custom
        // privileged APIs) must never be created via the runtime CRUD path —
        // doing so would let an operator mint e.g. identity.management
        // as a custom scope and bind it to a client they control, escalating
        // past the transport policy. Declare reserved scopes via
        // bootstrap/provisioning instead.
        if (ReservedApiScopes.Contains(name, StringComparer.Ordinal))
        {
            throw new ManagementValidationException(
                "scope_name_reserved",
                "This scope protects an administrative surface and cannot be created through the management API. Declare it via bootstrap/provisioning.",
                "name");
        }

        return name;
    }

    private static string? ValidateOptional(
        string? value,
        int maxLength,
        string reasonCode,
        string field)
    {
        var normalized = string.IsNullOrWhiteSpace(value)
            ? null
            : value.Trim();
        if (normalized?.Length > maxLength)
        {
            throw new ManagementValidationException(
                reasonCode,
                $"Use at most {maxLength} characters.",
                field);
        }

        return normalized;
    }

    private static IReadOnlySet<string> ValidateResources(
        IReadOnlyList<string>? values)
    {
        if (values is null)
        {
            throw new ManagementValidationException(
                "scope_resources_required",
                "The resources list is required, even when empty.",
                "resources");
        }
        if (values.Count > ResourceCountLimit)
        {
            throw new ManagementValidationException(
                "scope_resources_limit",
                $"Use at most {ResourceCountLimit} resources.",
                "resources");
        }

        var resources = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            var resource = value?.Trim();
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ManagementValidationException(
                    "scope_resource_invalid",
                    "Resources cannot be empty.",
                    "resources");
            }
            if (resource.Length > ResourceMaxLength
                || resource.Any(char.IsControl))
            {
                throw new ManagementValidationException(
                    "scope_resource_invalid",
                    $"Each resource must be up to {ResourceMaxLength} characters and cannot contain control characters.",
                    "resources");
            }
            if (!resources.Add(resource))
            {
                throw new ManagementValidationException(
                    "scope_resource_duplicate",
                    $"The resource '{resource}' is duplicated.",
                    "resources");
            }
        }

        return resources;
    }
}
