#if !APPLICATION_CONTRACTS
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
using static OpenIddict.Abstractions.OpenIddictConstants;
using OAuthScopes = OpenIddict.Abstractions.OpenIddictConstants.Scopes;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Scopes;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical application boundary for custom OAuth scope definitions stored by
/// OpenIddict. Protocol scopes remain built-in and are not duplicated here.
/// </summary>
public interface IScopeManagementService
{
    Task<IReadOnlyList<ManagementScopeSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> GetAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> CreateAsync(
        CreateManagementScopeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> UpdateAsync(
        string id,
        UpdateManagementScopeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementScopeSummary(
    string Id,
    string Name,
    string? DisplayName,
    string? Description,
    int ResourceCount,
    int ClientCount,
    bool IsManifestManaged);

public sealed record ManagementScopeDetail(
    string Id,
    string Name,
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources,
    IReadOnlyList<string> ClientIds,
    bool IsManifestManaged);

public sealed record CreateManagementScopeCommand(
    string Name,
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources);

public sealed record UpdateManagementScopeCommand(
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources);

#else

internal sealed class ScopeManagementService(
    IOpenIddictScopeManager scopes,
    IOpenIddictApplicationManager applications,
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    Microsoft.Extensions.Options.IOptions<ManagementOptions> managementOptions,
    ILogger<ScopeManagementService> logger) : IScopeManagementService
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
        var decision = await DemandAsync(
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

        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ScopesRead,
                resource,
                decision,
                "succeeded",
                "scopes_listed"));
        await database.SaveChangesAsync(cancellationToken);

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
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ScopesRead,
            resource,
            cancellationToken);
        var scope = await scopes.FindByIdAsync(id, cancellationToken);
        if (scope is null)
        {
            throw new ManagementNotFoundException(
                "scope_not_found",
                "O scope não foi encontrado.");
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
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ScopesCreate,
            resource,
            cancellationToken);
        if (await scopes.FindByNameAsync(name, cancellationToken) is not null)
        {
            throw new ManagementConflictException(
                "scope_already_exists",
                "Já existe um scope com esse nome.");
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
                "Não foi possível criar o scope.");
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
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ScopesUpdate,
            resource,
            cancellationToken);
        var scope = await scopes.FindByIdAsync(id, cancellationToken);
        if (scope is null)
        {
            throw new ManagementNotFoundException(
                "scope_not_found",
                "O scope não foi encontrado.");
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
                "Não foi possível atualizar o scope.");
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
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ScopesDelete,
            resource,
            cancellationToken);
        var scope = await scopes.FindByIdAsync(id, cancellationToken);
        if (scope is null)
        {
            throw new ManagementNotFoundException(
                "scope_not_found",
                "O scope não foi encontrado.");
        }
        await DemandManuallyManagedAsync(scope, cancellationToken);

        var name = (string?)await scopes.GetNameAsync(
            scope,
            cancellationToken)
            ?? throw new ManagementConflictException(
                "scope_name_missing",
                "O scope não possui um nome válido.");
        var usage = await ListClientUsageAsync(cancellationToken);
        if (usage.TryGetValue(name, out var clients) && clients.Count > 0)
        {
            throw new ManagementConflictException(
                "scope_in_use",
                $"Remova o scope dos clientes antes de excluí-lo ({clients.Count} cliente(s) ainda o utilizam).");
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
                "Não foi possível excluir o scope.");
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
                "Este scope é gerenciado pelo manifesto declarativo. Altere o manifesto e aplique o provisionamento.");
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

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            resource,
            cancellationToken);
        if (!decision.IsAllowed)
        {
            throw new ManagementAccessException(decision);
        }

        return decision;
    }

    private string ValidateName(string? value)
    {
        var name = value?.Trim();
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ManagementValidationException(
                "scope_name_required",
                "Informe o nome do scope.",
                "name");
        }
        if (name.Length > IdentityDatabaseSchema.OpenIddictScopeNameLength)
        {
            throw new ManagementValidationException(
                "scope_name_too_long",
                $"Use no máximo {IdentityDatabaseSchema.OpenIddictScopeNameLength} caracteres.",
                "name");
        }
        if (name.Any(character =>
                character < '\u0021'
                || character > '\u007e'
                || character is '"' or '\\'))
        {
            throw new ManagementValidationException(
                "scope_name_invalid",
                "Use um scope-token OAuth sem espaços, aspas ou barra invertida.",
                "name");
        }
        if (ProtocolScopes.Contains(name))
        {
            throw new ManagementValidationException(
                "scope_name_reserved",
                "Esse scope é definido pelo protocolo e não deve ser cadastrado como scope customizado.",
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
                "Esse scope protege uma superfície administrativa e não pode ser criado pela API de gerenciamento. Declare-o via bootstrap/provisioning.",
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
                $"Use no máximo {maxLength} caracteres.",
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
                "A lista de resources é obrigatória, mesmo quando vazia.",
                "resources");
        }
        if (values.Count > ResourceCountLimit)
        {
            throw new ManagementValidationException(
                "scope_resources_limit",
                $"Use no máximo {ResourceCountLimit} resources.",
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
                    "Resources não podem ser vazios.",
                    "resources");
            }
            if (resource.Length > ResourceMaxLength
                || resource.Any(char.IsControl))
            {
                throw new ManagementValidationException(
                    "scope_resource_invalid",
                    $"Cada resource deve ter até {ResourceMaxLength} caracteres e não pode conter caracteres de controle.",
                    "resources");
            }
            if (!resources.Add(resource))
            {
                throw new ManagementValidationException(
                    "scope_resource_duplicate",
                    $"O resource '{resource}' está duplicado.",
                    "resources");
            }
        }

        return resources;
    }
}
#endif
