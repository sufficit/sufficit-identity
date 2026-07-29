using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

/// <summary>
/// Canonical application boundary for contextual user discovery.
/// Mutating user operations are intentionally excluded until their
/// multi-context security semantics are explicit.
/// </summary>
public interface IUserManagementService
{
    Task<ManagementUserAccess> GetAccessAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserPage> SearchAsync(
        ManagementUserSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> GetAsync(
        string id,
        string? contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public interface IManagementUserContextStore
{
    Task<IReadOnlySet<string>> ListUserIdsAsync(
        string contextId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlySet<string>> ListContextIdsAsync(
        string userId,
        CancellationToken cancellationToken = default);

    Task<bool> UserBelongsToAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementUserAccess(
    bool HasGlobalAccess,
    IReadOnlyList<string> ContextIds);

public sealed record ManagementUserSearch(
    string? Search = null,
    string? ContextId = null,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementUserPage(
    IReadOnlyList<ManagementUserSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? ContextId);

public sealed record ManagementUserSummary(
    string Id,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    bool TwoFactorEnabled,
    bool IsLockedOut,
    IReadOnlyList<string> Roles);

public sealed record ManagementUserDetail(
    string Id,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    string? PhoneNumber,
    bool PhoneNumberConfirmed,
    bool TwoFactorEnabled,
    bool LockoutEnabled,
    DateTimeOffset? LockoutEnd,
    int AccessFailedCount,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> ContextIds,
    DateTime UpdatedAt);

internal sealed class EmptyManagementUserContextStore
    : IManagementUserContextStore
{
    public Task<IReadOnlySet<string>> ListUserIdsAsync(
        string contextId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlySet<string>>(
            new HashSet<string>(StringComparer.Ordinal));

    public Task<IReadOnlySet<string>> ListContextIdsAsync(
        string userId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlySet<string>>(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    public Task<bool> UserBelongsToAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(false);
}

internal sealed class UserManagementService(
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    IManagementEntitlementResolver entitlements,
    IManagementUserContextStore userContexts,
    ILogger<UserManagementService> logger) : IUserManagementService
{
    public async Task<ManagementUserAccess> GetAccessAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        if (!grants.HasGlobalAdministratorAccess
            && grants.ManagedContextIds.Count is 0)
        {
            throw new ManagementAccessException(
                ManagementAuthorizationDecision.Denied(
                    "capability_not_granted"));
        }

        return new ManagementUserAccess(
            grants.HasGlobalAdministratorAccess,
            grants.ManagedContextIds
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray());
    }

    public async Task<ManagementUserPage> SearchAsync(
        ManagementUserSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 1, 100);
        var contextId = NormalizeContextId(query.ContextId);
        var resource = new ManagementResource(
            ManagementResourceTypes.UserCollection,
            ContextId: contextId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

        var users = database.Users.AsNoTracking();
        if (contextId is not null)
        {
            var visibleUserIds = await userContexts.ListUserIdsAsync(
                contextId,
                cancellationToken);
            users = users.Where(user => visibleUserIds.Contains(user.Id));
        }

        var search = query.Search?.Trim();
        if (!string.IsNullOrWhiteSpace(search))
        {
            users = users.Where(user =>
                user.UserName != null && user.UserName.Contains(search)
                || user.Email != null && user.Email.Contains(search));
        }

        var totalCount = await users.CountAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var pageRows = await users
            .OrderBy(user => user.UserName ?? user.Email ?? user.Id)
            .ThenBy(user => user.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                IsLockedOut = user.LockoutEnd != null
                    && user.LockoutEnd > now
            })
            .ToArrayAsync(cancellationToken);
        var roles = await RolesByUserAsync(
            pageRows.Select(user => user.Id).ToArray(),
            cancellationToken);

        var items = pageRows
            .Select(user => new ManagementUserSummary(
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                user.IsLockedOut,
                roles.GetValueOrDefault(user.Id, [])))
            .ToArray();

        await WriteAuditAsync(
            context,
            resource,
            decision,
            "succeeded",
            "users_listed",
            cancellationToken);

        return new ManagementUserPage(
            items,
            page,
            pageSize,
            totalCount,
            contextId);
    }

    public async Task<ManagementUserDetail> GetAsync(
        string id,
        string? contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var normalizedContextId = NormalizeContextId(contextId);
        var resource = new ManagementResource(
            ManagementResourceTypes.User,
            id,
            normalizedContextId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

        if (normalizedContextId is not null
            && !await userContexts.UserBelongsToAsync(
                id,
                normalizedContextId,
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
                "The user was not found in the requested context.");
        }

        var user = await database.Users
            .AsNoTracking()
            .Where(user => user.Id == id)
            .Select(user => new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.PhoneNumber,
                user.PhoneNumberConfirmed,
                user.TwoFactorEnabled,
                user.LockoutEnabled,
                user.LockoutEnd,
                user.AccessFailedCount,
                user.Timestamp
            })
            .FirstOrDefaultAsync(cancellationToken);
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
                "The user was not found.");
        }

        var roles = await RolesByUserAsync([user.Id], cancellationToken);
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var visibleContexts = grants.HasGlobalAdministratorAccess
            ? await userContexts.ListContextIdsAsync(
                user.Id,
                cancellationToken)
            : new HashSet<string>(
                normalizedContextId is null ? [] : [normalizedContextId],
                StringComparer.OrdinalIgnoreCase);

        await WriteAuditAsync(
            context,
            resource,
            decision,
            "succeeded",
            "user_read",
            cancellationToken);

        return new ManagementUserDetail(
            user.Id,
            user.UserName,
            user.Email,
            user.EmailConfirmed,
            user.PhoneNumber,
            user.PhoneNumberConfirmed,
            user.TwoFactorEnabled,
            user.LockoutEnabled,
            user.LockoutEnd,
            user.AccessFailedCount,
            roles.GetValueOrDefault(user.Id, []),
            visibleContexts.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            user.Timestamp);
    }

    private async Task<Dictionary<string, IReadOnlyList<string>>>
        RolesByUserAsync(
            string[] userIds,
            CancellationToken cancellationToken)
    {
        if (userIds.Length is 0)
        {
            return new Dictionary<string, IReadOnlyList<string>>(
                StringComparer.Ordinal);
        }

        var rows = await (
            from userRole in database.UserRoles.AsNoTracking()
            join role in database.Roles.AsNoTracking()
                on userRole.RoleId equals role.Id
            where userIds.Contains(userRole.UserId)
            select new { userRole.UserId, role.Name })
            .ToArrayAsync(cancellationToken);

        return rows
            .GroupBy(row => row.UserId, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyList<string>)group
                    .Select(row => row.Name)
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Select(name => name!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                StringComparer.Ordinal);
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
        if (decision.IsAllowed)
        {
            return decision;
        }

        await WriteAuditAsync(
            context,
            resource,
            decision,
            "denied",
            decision.ReasonCode,
            cancellationToken);
        throw new ManagementAccessException(decision);
    }

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
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.UsersRead,
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
                "Unable to persist user-management audit event. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }
    }

    private static string? NormalizeContextId(string? value)
    {
        var normalized =
            RoleAndClaimManagementEntitlementResolver.NormalizeContextId(
                value);
        if (value is not null && normalized is null)
        {
            throw new ManagementValidationException(
                "user_context_invalid",
                "A non-empty context identifier is required.",
                "contextId");
        }

        return normalized;
    }
}
