using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;

namespace Sufficit.Identity.Management.Permissions;

/// <summary>
/// Canonical application boundary for user role and contextual permission
/// delegation. Embedded UI and HTTP adapters execute these same use cases.
/// </summary>
public interface IUserPermissionManagementService
{
    Task<ManagementUserPermissions> GetAsync(
        string userId,
        string? contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserPermissions> SetRoleAsync(
        string userId,
        SetManagementUserRoleCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserPermissions> SetContextualPermissionAsync(
        string userId,
        SetManagementUserContextualPermissionCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record SetManagementUserRoleCommand(
    string Role,
    bool Assigned);

public sealed record SetManagementUserContextualPermissionCommand(
    string Key,
    string ContextId,
    bool Assigned);

public sealed record ManagementPermissionOption(
    string Key,
    string Label,
    string? Description,
    bool IsAssigned,
    bool CanChange,
    string ReasonCode);

public sealed record ManagementUserPermissionActions(
    bool CanManageRoles,
    bool RolesRequireMfa,
    string RolesReasonCode,
    bool CanManageContextualPermissions,
    bool ContextualPermissionsRequireMfa,
    string ContextualPermissionsReasonCode);

public sealed record ManagementUserPermissions(
    string UserId,
    string? UserName,
    string? Email,
    string? ContextId,
    IReadOnlyList<ManagementPermissionOption> Roles,
    IReadOnlyList<ManagementPermissionOption> ContextualPermissions,
    ManagementUserPermissionActions Actions);

public sealed record ManagementContextualPermissionDescriptor(
    string Key,
    string Label,
    string? Description = null);

/// <summary>
/// Replaceable host adapter for contextual grants. The generic management
/// layer does not know a claim type, wire format or wildcard convention.
/// </summary>
public interface IManagementContextualPermissionStore
{
    Task<IReadOnlyList<ManagementContextualPermissionDescriptor>>
        ListKnownAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlySet<string>> ListAssignedKeysAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlySet<string>> ListDelegableKeysAsync(
        string operatorUserId,
        string contextId,
        CancellationToken cancellationToken = default);

    Task SetAsync(
        string userId,
        string key,
        string contextId,
        bool assigned,
        CancellationToken cancellationToken = default);
}

internal sealed class EmptyManagementContextualPermissionStore
    : IManagementContextualPermissionStore
{
    public Task<IReadOnlyList<ManagementContextualPermissionDescriptor>>
        ListKnownAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<ManagementContextualPermissionDescriptor>>(
            []);

    public Task<IReadOnlySet<string>> ListAssignedKeysAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlySet<string>>(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    public Task<IReadOnlySet<string>> ListDelegableKeysAsync(
        string operatorUserId,
        string contextId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlySet<string>>(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    public Task SetAsync(
        string userId,
        string key,
        string contextId,
        bool assigned,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException(
            "No contextual permission store is configured.");
}

internal sealed class UserPermissionManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IManagementAuthorizationEvaluator authorization,
    IManagementEntitlementResolver entitlements,
    IManagementUserContextStore userContexts,
    IManagementContextualPermissionStore contextualPermissions,
    IManagementUserSessionRevoker sessionRevoker,
    IOptions<ManagementOptions> options,
    ILogger<UserPermissionManagementService> logger)
    : IUserPermissionManagementService
{
    public async Task<ManagementUserPermissions> GetAsync(
        string userId,
        string? contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var normalizedContextId = NormalizeOptionalContext(contextId);
        var resource = PermissionResource(userId, normalizedContextId);
        var roleDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersPermissionsManage,
            PermissionResource(userId, null),
            cancellationToken);
        var contextualDecision = normalizedContextId is null
            ? ManagementAuthorizationDecision.Denied("context_required")
            : await authorization.EvaluateAsync(
                context.Operator,
                ManagementCapabilities.UsersPermissionsManage,
                resource,
                cancellationToken);
        var readDecision = normalizedContextId is null
            ? roleDecision
            : contextualDecision;

        if (!readDecision.IsAllowed)
        {
            await WriteAuditAsync(
                context,
                resource,
                readDecision,
                "denied",
                readDecision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(readDecision);
        }

        var user = await database.Users
            .AsNoTracking()
            .Where(candidate => candidate.Id == userId)
            .Select(candidate => new
            {
                candidate.Id,
                candidate.UserName,
                candidate.Email
            })
            .FirstOrDefaultAsync(cancellationToken);
        if (user is null)
        {
            await WriteAuditAsync(
                context,
                resource,
                readDecision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        if (normalizedContextId is not null
            && !await userContexts.UserBelongsToAsync(
                userId,
                normalizedContextId,
                cancellationToken))
        {
            await WriteAuditAsync(
                context,
                resource,
                readDecision,
                "not-found",
                "user_not_found_in_context",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado no contexto solicitado.");
        }

        var isSelf = IsSelf(userId, context);
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var roleOptions = await RoleOptionsAsync(
            userId,
            canChange: roleDecision.IsAllowed && !isSelf,
            isSelf ? "user_self_permission_change_not_allowed" : roleDecision.ReasonCode,
            cancellationToken);

        var contextualOptions =
            Array.Empty<ManagementPermissionOption>();
        if (normalizedContextId is not null)
        {
            contextualOptions = await ContextualOptionsAsync(
                userId,
                context.OperatorSubject,
                normalizedContextId,
                grants.HasGlobalAdministratorAccess,
                contextualDecision,
                isSelf,
                cancellationToken);
        }

        var contextualCanChange = contextualOptions.Any(option => option.CanChange);
        var result = new ManagementUserPermissions(
            user.Id,
            user.UserName,
            user.Email,
            normalizedContextId,
            roleOptions,
            contextualOptions,
            new ManagementUserPermissionActions(
                CanManageRoles: roleDecision.IsAllowed && !isSelf,
                RolesRequireMfa:
                    roleDecision.Outcome
                    is ManagementAuthorizationOutcome.StepUpRequired,
                RolesReasonCode: isSelf
                    ? "user_self_permission_change_not_allowed"
                    : roleDecision.ReasonCode,
                CanManageContextualPermissions: contextualCanChange,
                ContextualPermissionsRequireMfa:
                    contextualDecision.Outcome
                    is ManagementAuthorizationOutcome.StepUpRequired,
                ContextualPermissionsReasonCode: isSelf
                    ? "user_self_permission_change_not_allowed"
                    : contextualDecision.ReasonCode));

        await WriteAuditAsync(
            context,
            resource,
            readDecision,
            "succeeded",
            "user_permissions_read",
            cancellationToken);
        return result;
    }

    public async Task<ManagementUserPermissions> SetRoleAsync(
        string userId,
        SetManagementUserRoleCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(command);

        var roleName = NormalizeRole(command.Role);
        var resource = new ManagementResource(
            ManagementResourceTypes.UserPermission,
            $"{userId}/roles/{roleName}");
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersPermissionsManage,
            resource,
            cancellationToken);
        if (IsSelf(userId, context))
        {
            decision = ManagementAuthorizationDecision.Denied(
                "user_self_permission_change_not_allowed");
        }

        if (!decision.IsAllowed)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var role = await database.Roles
            .AsNoTracking()
            .Where(candidate =>
                candidate.NormalizedName == roleName.ToUpperInvariant()
                || candidate.Name == roleName)
            .Select(candidate => new
            {
                candidate.Id,
                candidate.Name,
                candidate.NormalizedName
            })
            .FirstOrDefaultAsync(cancellationToken);
        if (role?.Name is null)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "validation-failed",
                "user_role_unknown",
                cancellationToken);
            throw new ManagementValidationException(
                "user_role_unknown",
                "O papel informado não existe.",
                "role");
        }

        var user = await userManager.FindByIdAsync(userId);
        if (user is null)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        var isAssigned = await userManager.IsInRoleAsync(user, role.Name);
        if (isAssigned == command.Assigned)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "unchanged",
                "user_role_unchanged",
                cancellationToken);
            return await GetAsync(
                userId,
                contextId: null,
                context,
                cancellationToken);
        }

        if (!command.Assigned
            && IsAdministratorRole(role.Name, role.NormalizedName)
            && await database.UserRoles
                .AsNoTracking()
                .CountAsync(
                    userRole => userRole.RoleId == role.Id,
                    cancellationToken) <= 1)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "conflict",
                "last_administrator_required",
                cancellationToken);
            throw new ManagementConflictException(
                "last_administrator_required",
                "O último administrador não pode perder esse papel.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            EnsureIdentitySucceeded(
                command.Assigned
                    ? await userManager.AddToRoleAsync(user, role.Name)
                    : await userManager.RemoveFromRoleAsync(user, role.Name));
            EnsureIdentitySucceeded(
                await userManager.UpdateSecurityStampAsync(user));
            var revocation = await sessionRevoker.RevokeAsync(
                user.Id,
                cancellationToken);
            LogRevocation(user.Id, context, revocation);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersPermissionsManage,
                    resource,
                    decision,
                    "succeeded",
                    command.Assigned
                        ? "user_role_added"
                        : "user_role_removed"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to change a management user role. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "failed",
                "user_role_change_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_role_change_failed",
                "Não foi possível alterar o papel do usuário.");
        }

        return await GetAsync(
            userId,
            contextId: null,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserPermissions>
        SetContextualPermissionAsync(
            string userId,
            SetManagementUserContextualPermissionCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(command);

        var contextId = NormalizeRequiredContext(command.ContextId);
        var key = NormalizePermissionKey(command.Key);
        var resource = new ManagementResource(
            ManagementResourceTypes.UserPermission,
            $"{userId}/contextual/{key}",
            contextId);
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersPermissionsManage,
            resource,
            cancellationToken);
        if (IsSelf(userId, context))
        {
            decision = ManagementAuthorizationDecision.Denied(
                "user_self_permission_change_not_allowed");
        }

        if (!decision.IsAllowed)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var user = await userManager.FindByIdAsync(userId);
        if (user is null
            || !await userContexts.UserBelongsToAsync(
                userId,
                contextId,
                cancellationToken))
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "not-found",
                "user_not_found_in_context",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado no contexto solicitado.");
        }

        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var known = await contextualPermissions.ListKnownAsync(
            cancellationToken);
        var knownKeys = known
            .Select(permission => permission.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var delegableKeys = grants.HasGlobalAdministratorAccess
            ? knownKeys
            : await contextualPermissions.ListDelegableKeysAsync(
                context.OperatorSubject,
                contextId,
                cancellationToken);
        var assignedKeys = await contextualPermissions.ListAssignedKeysAsync(
            userId,
            contextId,
            cancellationToken);

        if (!knownKeys.Contains(key) && !assignedKeys.Contains(key))
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "validation-failed",
                "contextual_permission_unknown",
                cancellationToken);
            throw new ManagementValidationException(
                "contextual_permission_unknown",
                "A permissão contextual informada não existe.",
                "key");
        }

        if (!delegableKeys.Contains(key))
        {
            var delegationDecision = ManagementAuthorizationDecision.Denied(
                "contextual_permission_not_delegable");
            await WriteAuditAsync(
                context,
                resource,
                delegationDecision,
                "denied",
                delegationDecision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(delegationDecision);
        }

        if (assignedKeys.Contains(key) == command.Assigned)
        {
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "unchanged",
                "contextual_permission_unchanged",
                cancellationToken);
            return await GetAsync(
                userId,
                contextId,
                context,
                cancellationToken);
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            await contextualPermissions.SetAsync(
                userId,
                key,
                contextId,
                command.Assigned,
                cancellationToken);
            EnsureIdentitySucceeded(
                await userManager.UpdateSecurityStampAsync(user));
            var revocation = await sessionRevoker.RevokeAsync(
                user.Id,
                cancellationToken);
            LogRevocation(user.Id, context, revocation);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersPermissionsManage,
                    resource,
                    decision,
                    "succeeded",
                    command.Assigned
                        ? "user_contextual_permission_added"
                        : "user_contextual_permission_removed"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to change a contextual management permission. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await WriteAuditAsync(
                context,
                resource,
                decision,
                "failed",
                "contextual_permission_change_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "contextual_permission_change_failed",
                "Não foi possível alterar a permissão contextual.");
        }

        return await GetAsync(
            userId,
            contextId,
            context,
            cancellationToken);
    }

    private async Task<IReadOnlyList<ManagementPermissionOption>>
        RoleOptionsAsync(
            string userId,
            bool canChange,
            string reasonCode,
            CancellationToken cancellationToken)
    {
        var roles = await database.Roles
            .AsNoTracking()
            .Where(role => role.Name != null)
            .Select(role => new { role.Id, Name = role.Name! })
            .OrderBy(role => role.Name)
            .ToArrayAsync(cancellationToken);
        var assignedIds = await database.UserRoles
            .AsNoTracking()
            .Where(userRole => userRole.UserId == userId)
            .Select(userRole => userRole.RoleId)
            .ToHashSetAsync(cancellationToken);

        return roles
            .Select(role => new ManagementPermissionOption(
                role.Name,
                role.Name,
                "Papel global da conta",
                assignedIds.Contains(role.Id),
                canChange,
                canChange ? "allowed" : reasonCode))
            .ToArray();
    }

    private async Task<ManagementPermissionOption[]>
        ContextualOptionsAsync(
            string userId,
            string operatorUserId,
            string contextId,
            bool hasGlobalAdministratorAccess,
            ManagementAuthorizationDecision contextualDecision,
            bool isSelf,
            CancellationToken cancellationToken)
    {
        var known = await contextualPermissions.ListKnownAsync(
            cancellationToken);
        var assigned = await contextualPermissions.ListAssignedKeysAsync(
            userId,
            contextId,
            cancellationToken);
        var delegable = hasGlobalAdministratorAccess
            ? known
                .Select(permission => permission.Key)
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
            : await contextualPermissions.ListDelegableKeysAsync(
                operatorUserId,
                contextId,
                cancellationToken);
        var descriptors = known.ToDictionary(
            permission => permission.Key,
            StringComparer.OrdinalIgnoreCase);
        var visibleKeys = assigned
            .Concat(delegable)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return visibleKeys
            .Select(key =>
            {
                var descriptor = descriptors.GetValueOrDefault(key)
                    ?? new ManagementContextualPermissionDescriptor(
                        key,
                        key,
                        "Diretiva contextual existente");
                var canChange = !isSelf
                    && contextualDecision.IsAllowed
                    && delegable.Contains(key);
                var reasonCode = isSelf
                    ? "user_self_permission_change_not_allowed"
                    : !contextualDecision.IsAllowed
                        ? contextualDecision.ReasonCode
                        : !delegable.Contains(key)
                            ? "contextual_permission_not_delegable"
                            : "allowed";

                return new ManagementPermissionOption(
                    descriptor.Key,
                    descriptor.Label,
                    descriptor.Description,
                    assigned.Contains(key),
                    canChange,
                    reasonCode);
            })
            .ToArray();
    }

    private bool IsAdministratorRole(
        string roleName,
        string? normalizedRoleName)
    {
        var administratorRoles =
            RoleAndClaimManagementEntitlementResolver.NormalizeRoles(
                options.Value.Authorization.AdministratorRoles,
                "administrator");
        return administratorRoles.Any(configured =>
            string.Equals(
                configured,
                roleName,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                configured,
                normalizedRoleName,
                StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSelf(
        string userId,
        ManagementRequestContext context) =>
        string.Equals(
            userId,
            context.OperatorSubject,
            StringComparison.Ordinal);

    private static ManagementResource PermissionResource(
        string userId,
        string? contextId) =>
        new(
            ManagementResourceTypes.UserPermission,
            userId,
            contextId);

    private static string NormalizeRole(string role)
    {
        var normalized = role?.Trim();
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.Length > 256)
        {
            throw new ManagementValidationException(
                "user_role_invalid",
                "Informe um papel válido.",
                "role");
        }

        return normalized;
    }

    private static string NormalizePermissionKey(string key)
    {
        var normalized = key?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized.Length > 100
            || normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character)
                && character is not '.' and not '-' and not '_'))
        {
            throw new ManagementValidationException(
                "contextual_permission_invalid",
                "Informe uma permissão contextual válida.",
                "key");
        }

        return normalized;
    }

    private static string? NormalizeOptionalContext(string? contextId)
    {
        if (contextId is null)
        {
            return null;
        }

        return NormalizeRequiredContext(contextId);
    }

    private static string NormalizeRequiredContext(string contextId)
    {
        var normalized =
            RoleAndClaimManagementEntitlementResolver.NormalizeContextId(
                contextId);
        if (normalized is null)
        {
            throw new ManagementValidationException(
                "user_context_invalid",
                "Informe um contexto não vazio.",
                "contextId");
        }

        return normalized;
    }

    private static void EnsureIdentitySucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                string.Join(
                    ' ',
                    result.Errors.Select(error => error.Code)));
        }
    }

    private void LogRevocation(
        string userId,
        ManagementRequestContext context,
        ManagementUserSessionRevocation revocation) =>
        logger.LogInformation(
            "Revoked {TokenCount} tokens and {AuthorizationCount} authorizations after permission change for user {UserId}. CorrelationId={CorrelationId}",
            revocation.RevokedTokens,
            revocation.RevokedAuthorizations,
            userId,
            context.CorrelationId);

    private async Task WriteAuditAsync(
        ManagementRequestContext context,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersPermissionsManage,
                    resource,
                    decision,
                    operationOutcome,
                    reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist user-permission audit event. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }
    }
}
