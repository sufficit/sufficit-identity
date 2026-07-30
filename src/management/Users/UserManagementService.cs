using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

/// <summary>
/// Canonical application boundary for contextual user administration.
/// Both embedded UI and HTTP adapters execute these same use cases.
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

    Task<ManagementUserDetail> CreateAsync(
        CreateManagementUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> ResetPasswordAsync(
        string id,
        ResetManagementUserPasswordCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> SetLockoutAsync(
        string id,
        SetManagementUserLockoutCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public interface IManagementUserContextStore
{
    Task<IReadOnlySet<string>> ListKnownContextIdsAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlySet<string>> ListUserIdsAsync(
        string contextId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlySet<string>> ListContextIdsAsync(
        string userId,
        CancellationToken cancellationToken = default);

    Task<ManagementUserMembership> GetMembershipAsync(
        string userId,
        CancellationToken cancellationToken = default);

    Task<bool> UserBelongsToAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default);

    Task AddToContextAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementUserAccess(
    bool HasGlobalAccess,
    IReadOnlyList<string> ContextIds,
    bool CanCreate = false);

public sealed record CreateManagementUserCommand(
    string UserName,
    string Email,
    string InitialPassword,
    string ContextId);

public sealed record ResetManagementUserPasswordCommand(
    string NewPassword);

public sealed record SetManagementUserLockoutCommand(
    bool Locked);

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

public sealed record ManagementUserMembership(
    IReadOnlySet<string> ContextIds,
    bool RequiresAdministrator);

public sealed record ManagementUserActions(
    bool CanResetPassword,
    bool ResetPasswordRequiresMfa,
    string ResetPasswordReasonCode,
    bool CanSetLockout = false,
    bool SetLockoutRequiresMfa = false,
    string SetLockoutReasonCode = "not_evaluated");

public sealed record ManagementUserSessionRevocation(
    long RevokedTokens,
    long RevokedAuthorizations);

public interface IManagementUserSessionRevoker
{
    Task<ManagementUserSessionRevocation> RevokeAsync(
        string subject,
        CancellationToken cancellationToken = default);
}

internal sealed class OpenIddictManagementUserSessionRevoker(
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations)
    : IManagementUserSessionRevoker
{
    public async Task<ManagementUserSessionRevocation> RevokeAsync(
        string subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        var revokedTokens = await tokens.RevokeBySubjectAsync(
            subject,
            cancellationToken);
        var revokedAuthorizations =
            await authorizations.RevokeBySubjectAsync(
                subject,
                cancellationToken);

        return new ManagementUserSessionRevocation(
            revokedTokens,
            revokedAuthorizations);
    }
}

[method: JsonConstructor]
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
    DateTime UpdatedAt,
    ManagementUserActions Actions)
{
    public ManagementUserDetail(
        string id,
        string? userName,
        string? email,
        bool emailConfirmed,
        string? phoneNumber,
        bool phoneNumberConfirmed,
        bool twoFactorEnabled,
        bool lockoutEnabled,
        DateTimeOffset? lockoutEnd,
        int accessFailedCount,
        IReadOnlyList<string> roles,
        IReadOnlyList<string> contextIds,
        DateTime updatedAt)
        : this(
            id,
            userName,
            email,
            emailConfirmed,
            phoneNumber,
            phoneNumberConfirmed,
            twoFactorEnabled,
            lockoutEnabled,
            lockoutEnd,
            accessFailedCount,
            roles,
            contextIds,
            updatedAt,
            new ManagementUserActions(
                CanResetPassword: false,
                ResetPasswordRequiresMfa: false,
                ResetPasswordReasonCode: "not_evaluated"))
    {
    }
}

internal sealed class EmptyManagementUserContextStore
    : IManagementUserContextStore
{
    public Task<IReadOnlySet<string>> ListKnownContextIdsAsync(
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlySet<string>>(
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

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

    public Task<ManagementUserMembership> GetMembershipAsync(
        string userId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(
            new ManagementUserMembership(
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                RequiresAdministrator: false));

    public Task<bool> UserBelongsToAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(false);

    public Task AddToContextAsync(
        string userId,
        string contextId,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException(
            "No management user-context store is configured.");
}

internal sealed class UserManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IManagementAuthorizationEvaluator authorization,
    IManagementEntitlementResolver entitlements,
    IManagementUserContextStore userContexts,
    IManagementUserSessionRevoker sessionRevoker,
    ILogger<UserManagementService> logger) : IUserManagementService
{
    private static readonly DateTimeOffset IndefiniteLockoutEnd =
        new(
            DateTimeOffset.MaxValue.Ticks
                - DateTimeOffset.MaxValue.Ticks % TimeSpan.TicksPerMicrosecond,
            TimeSpan.Zero);

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

        var contextIds = grants.HasGlobalAdministratorAccess
            ? await userContexts.ListKnownContextIdsAsync(cancellationToken)
            : grants.ManagedContextIds;

        return new ManagementUserAccess(
            grants.HasGlobalAdministratorAccess,
            contextIds
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            contextIds.Count is not 0);
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
            ManagementCapabilities.UsersRead,
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
                ManagementCapabilities.UsersRead,
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
                ManagementCapabilities.UsersRead,
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
        var membership = await userContexts.GetMembershipAsync(
            user.Id,
            cancellationToken);
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var visibleContexts = grants.HasGlobalAdministratorAccess
            ? membership.ContextIds
            : new HashSet<string>(
                normalizedContextId is null ? [] : [normalizedContextId],
                StringComparer.OrdinalIgnoreCase);
        var resetDecision = await EvaluateAccountWideActionAsync(
            user.Id,
            membership,
            context,
            ManagementCapabilities.UsersResetPassword,
            cancellationToken);
        var isLockedOut = user.LockoutEnd is { } lockoutEnd
            && lockoutEnd > DateTimeOffset.UtcNow;
        var lockoutDecision = await EvaluateLockoutChangeAsync(
            user.Id,
            membership,
            context,
            locking: !isLockedOut,
            cancellationToken);

        await WriteAuditAsync(
            context,
            ManagementCapabilities.UsersRead,
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
            user.Timestamp,
            Actions(resetDecision, lockoutDecision));
    }

    public async Task<ManagementUserDetail> CreateAsync(
        CreateManagementUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var userName = Required(
            command.UserName,
            "user_name_required",
            "Informe o nome de usuário.",
            "userName");
        var email = Required(
            command.Email,
            "user_email_required",
            "Informe o e-mail do usuário.",
            "email");
        if (userName.Length > 256)
        {
            throw new ManagementValidationException(
                "user_name_too_long",
                "Use no máximo 256 caracteres no nome de usuário.",
                "userName");
        }
        if (email.Length > 256)
        {
            throw new ManagementValidationException(
                "user_email_too_long",
                "Use no máximo 256 caracteres no e-mail.",
                "email");
        }
        var password = Required(
            command.InitialPassword,
            "user_password_required",
            "Informe a senha inicial.",
            "initialPassword",
            trim: false);
        var contextId = NormalizeContextId(command.ContextId)
            ?? throw new ManagementValidationException(
                "user_context_invalid",
                "Informe um contexto válido para o novo usuário.",
                "contextId");
        var collection = new ManagementResource(
            ManagementResourceTypes.UserCollection,
            ContextId: contextId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersCreate,
            collection,
            cancellationToken);
        var user = new ApplicationUser
        {
            UserName = userName,
            Email = email,
            EmailConfirmed = false,
            LockoutEnabled = true
        };

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var created = await userManager.CreateAsync(user, password);
            if (!created.Succeeded)
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.UsersCreate,
                        collection,
                        decision,
                        "failed",
                        IdentityReasonCode(
                            created,
                            "user_create_rejected")));
                await database.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                ThrowIdentityFailure(created, creatingUser: true);
            }

            await userContexts.AddToContextAsync(
                user.Id,
                contextId,
                cancellationToken);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersCreate,
                    new ManagementResource(
                        ManagementResourceTypes.User,
                        user.Id,
                        contextId),
                    decision,
                    "succeeded",
                    "user_created"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (ManagementValidationException)
        {
            throw;
        }
        catch (ManagementConflictException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            logger.LogError(
                exception,
                "Unable to create a contextual management user. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersCreate,
                collection,
                decision,
                "failed",
                "user_create_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_create_failed",
                "Não foi possível criar e associar o usuário ao contexto.");
        }

        return await GetAsync(
            user.Id,
            contextId,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserDetail> ResetPasswordAsync(
        string id,
        ResetManagementUserPasswordCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var password = Required(
            command.NewPassword,
            "user_password_required",
            "Informe a nova senha.",
            "newPassword",
            trim: false);
        var membership = await userContexts.GetMembershipAsync(
            id,
            cancellationToken);
        var decision = await EvaluateAccountWideActionAsync(
            id,
            membership,
            context,
            ManagementCapabilities.UsersResetPassword,
            cancellationToken);
        var auditResource = await AccountWideAuditResourceAsync(
            id,
            membership,
            context,
            decision,
            ManagementCapabilities.UsersResetPassword,
            cancellationToken);

        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersResetPassword,
                auditResource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersResetPassword,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var reset = await userManager.ResetPasswordAsync(
                user,
                token,
                password);
            if (!reset.Succeeded)
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.UsersResetPassword,
                        auditResource,
                        decision,
                        "failed",
                        IdentityReasonCode(
                            reset,
                            "user_password_reset_rejected")));
                await database.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                ThrowIdentityFailure(reset, creatingUser: false);
            }

            foreach (var resource in AccountWideAuditResources(
                id,
                membership,
                auditResource))
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.UsersResetPassword,
                        resource,
                        decision,
                        "succeeded",
                        "user_password_reset"));
            }

            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (ManagementValidationException)
        {
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(cancellationToken);
            await transaction.DisposeAsync();
            logger.LogError(
                exception,
                "Unable to reset a management user password. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersResetPassword,
                auditResource,
                decision,
                "failed",
                "user_password_reset_failed",
                cancellationToken);
            throw new ManagementConflictException(
                "user_password_reset_failed",
                "Não foi possível redefinir a senha do usuário.");
        }

        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var detailContext = grants.HasGlobalAdministratorAccess
            ? null
            : membership.ContextIds
                .Order(StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        return await GetAsync(
            id,
            detailContext,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserDetail> SetLockoutAsync(
        string id,
        SetManagementUserLockoutCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(command);

        var membership = await userContexts.GetMembershipAsync(
            id,
            cancellationToken);
        var decision = await EvaluateLockoutChangeAsync(
            id,
            membership,
            context,
            command.Locked,
            cancellationToken);
        var auditResource = await AccountWideAuditResourceAsync(
            id,
            membership,
            context,
            decision,
            ManagementCapabilities.UsersDisable,
            cancellationToken);

        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDisable,
                auditResource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDisable,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            EnsureLockoutChangeSucceeded(
                await userManager.SetLockoutEnabledAsync(user, true));
            EnsureLockoutChangeSucceeded(
                await userManager.SetLockoutEndDateAsync(
                    user,
                    command.Locked
                        ? IndefiniteLockoutEnd
                        : null));

            if (!command.Locked)
            {
                EnsureLockoutChangeSucceeded(
                    await userManager.ResetAccessFailedCountAsync(user));
            }

            EnsureLockoutChangeSucceeded(
                await userManager.UpdateSecurityStampAsync(user));

            var revocation = await sessionRevoker.RevokeAsync(
                user.Id,
                cancellationToken);
            logger.LogInformation(
                "Revoked {TokenCount} tokens and {AuthorizationCount} authorizations for management user {UserId}. CorrelationId={CorrelationId}",
                revocation.RevokedTokens,
                revocation.RevokedAuthorizations,
                user.Id,
                context.CorrelationId);

            foreach (var resource in AccountWideAuditResources(
                id,
                membership,
                auditResource))
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.UsersDisable,
                        resource,
                        decision,
                        "succeeded",
                        command.Locked
                            ? "user_locked"
                            : "user_unlocked"));
            }

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
            // UserManager and the OpenIddict managers share this scoped
            // DbContext. After rollback their tracked mutations must be
            // discarded before the failure audit is saved, otherwise the
            // audit SaveChanges could accidentally reapply the lockout.
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to change a management user lockout. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDisable,
                auditResource,
                decision,
                "failed",
                command.Locked
                    ? "user_lock_failed"
                    : "user_unlock_failed",
                cancellationToken);
            throw new ManagementConflictException(
                command.Locked
                    ? "user_lock_failed"
                    : "user_unlock_failed",
                command.Locked
                    ? "Não foi possível bloquear o acesso do usuário."
                    : "Não foi possível desbloquear o acesso do usuário.");
        }

        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var detailContext = grants.HasGlobalAdministratorAccess
            ? null
            : membership.ContextIds
                .Order(StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        return await GetAsync(
            id,
            detailContext,
            context,
            cancellationToken);
    }

    private async Task<ManagementAuthorizationDecision>
        EvaluateLockoutChangeAsync(
            string userId,
            ManagementUserMembership membership,
            ManagementRequestContext context,
            bool locking,
            CancellationToken cancellationToken)
    {
        if (locking
            && string.Equals(
                userId,
                context.OperatorSubject,
                StringComparison.Ordinal))
        {
            return ManagementAuthorizationDecision.Denied(
                "user_self_lockout_not_allowed");
        }

        return await EvaluateAccountWideActionAsync(
            userId,
            membership,
            context,
            ManagementCapabilities.UsersDisable,
            cancellationToken);
    }

    private async Task<ManagementAuthorizationDecision>
        EvaluateAccountWideActionAsync(
            string userId,
            ManagementUserMembership membership,
            ManagementRequestContext context,
            string capability,
            CancellationToken cancellationToken)
    {
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        if (grants.HasGlobalAdministratorAccess)
        {
            return await authorization.EvaluateAsync(
                context.Operator,
                capability,
                new ManagementResource(
                    ManagementResourceTypes.User,
                    userId),
                cancellationToken);
        }

        if (membership.RequiresAdministrator)
        {
            return ManagementAuthorizationDecision.Denied(
                "user_scope_requires_administrator");
        }

        if (membership.ContextIds.Count is 0)
        {
            return ManagementAuthorizationDecision.Denied(
                "user_context_required");
        }

        foreach (var contextId in membership.ContextIds
            .Order(StringComparer.OrdinalIgnoreCase))
        {
            var decision = await authorization.EvaluateAsync(
                context.Operator,
                capability,
                new ManagementResource(
                    ManagementResourceTypes.User,
                    userId,
                    contextId),
                cancellationToken);
            if (decision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired)
            {
                return decision;
            }

            if (!decision.IsAllowed)
            {
                return ManagementAuthorizationDecision.Denied(
                    "user_context_scope_incomplete");
            }
        }

        return ManagementAuthorizationDecision.Allowed();
    }

    private async Task<ManagementResource> AccountWideAuditResourceAsync(
        string userId,
        ManagementUserMembership membership,
        ManagementRequestContext context,
        ManagementAuthorizationDecision aggregateDecision,
        string capability,
        CancellationToken cancellationToken)
    {
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        if (grants.HasGlobalAdministratorAccess)
        {
            return new ManagementResource(
                ManagementResourceTypes.User,
                userId);
        }

        foreach (var contextId in membership.ContextIds
            .Order(StringComparer.OrdinalIgnoreCase))
        {
            var decision = await authorization.EvaluateAsync(
                context.Operator,
                capability,
                new ManagementResource(
                    ManagementResourceTypes.User,
                    userId,
                    contextId),
                cancellationToken);
            if (decision.Outcome == aggregateDecision.Outcome
                && !decision.IsAllowed)
            {
                return new ManagementResource(
                    ManagementResourceTypes.User,
                    userId,
                    contextId);
            }
        }

        return new ManagementResource(
            ManagementResourceTypes.User,
            userId,
            membership.ContextIds
                .Order(StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault());
    }

    private static IEnumerable<ManagementResource>
        AccountWideAuditResources(
            string userId,
            ManagementUserMembership membership,
            ManagementResource fallback)
    {
        if (fallback.ContextId is null)
        {
            yield return fallback;
            yield break;
        }

        foreach (var contextId in membership.ContextIds
            .Order(StringComparer.OrdinalIgnoreCase))
        {
            yield return new ManagementResource(
                ManagementResourceTypes.User,
                userId,
                contextId);
        }
    }

    private static ManagementUserActions Actions(
        ManagementAuthorizationDecision resetDecision,
        ManagementAuthorizationDecision lockoutDecision) =>
        new(
            resetDecision.IsAllowed,
            resetDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            resetDecision.ReasonCode,
            lockoutDecision.IsAllowed,
            lockoutDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            lockoutDecision.ReasonCode);

    private static void EnsureLockoutChangeSucceeded(
        IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                string.Join(
                    ' ',
                    result.Errors.Select(error =>
                        $"{error.Code}: {error.Description}")));
        }
    }

    private static string Required(
        string? value,
        string reasonCode,
        string message,
        string field,
        bool trim = true)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ManagementValidationException(
                reasonCode,
                message,
                field);
        }

        return trim ? value.Trim() : value;
    }

    private static string IdentityReasonCode(
        IdentityResult result,
        string fallback) =>
        result.Errors
            .Select(error => error.Code switch
            {
                "DuplicateUserName" => "user_name_conflict",
                "DuplicateEmail" => "user_email_conflict",
                "InvalidUserName" => "user_name_invalid",
                "InvalidEmail" => "user_email_invalid",
                "InvalidToken" => "user_password_reset_token_invalid",
                var code when code.StartsWith(
                    "Password",
                    StringComparison.Ordinal) =>
                    "user_password_invalid",
                _ => fallback
            })
            .FirstOrDefault() ?? fallback;

    private static void ThrowIdentityFailure(
        IdentityResult result,
        bool creatingUser)
    {
        var reasonCode = IdentityReasonCode(
            result,
            creatingUser
                ? "user_create_rejected"
                : "user_password_reset_rejected");
        if (reasonCode is "user_name_conflict" or "user_email_conflict")
        {
            throw new ManagementConflictException(
                reasonCode,
                reasonCode == "user_name_conflict"
                    ? "Já existe um usuário com esse nome."
                    : "Já existe um usuário com esse e-mail.");
        }

        var field = reasonCode switch
        {
            "user_name_invalid" => "userName",
            "user_email_invalid" => "email",
            _ => creatingUser ? "initialPassword" : "newPassword"
        };
        var messages = result.Errors
            .Select(error => error.Code switch
            {
                "PasswordTooShort" =>
                    "A senha não possui o comprimento mínimo configurado.",
                "PasswordRequiresNonAlphanumeric" =>
                    "A senha precisa conter um caractere especial.",
                "PasswordRequiresDigit" =>
                    "A senha precisa conter um número.",
                "PasswordRequiresLower" =>
                    "A senha precisa conter uma letra minúscula.",
                "PasswordRequiresUpper" =>
                    "A senha precisa conter uma letra maiúscula.",
                "PasswordRequiresUniqueChars" =>
                    "A senha precisa conter mais caracteres diferentes.",
                "InvalidUserName" =>
                    "O nome de usuário contém caracteres não permitidos.",
                "InvalidEmail" =>
                    "Informe um endereço de e-mail válido.",
                _ => "Revise os dados informados e tente novamente."
            })
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        throw new ManagementValidationException(
            reasonCode,
            string.Join(' ', messages),
            field);
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
            capability,
            resource,
            decision,
            "denied",
            decision.ReasonCode,
            cancellationToken);
        throw new ManagementAccessException(decision);
    }

    private async Task WriteAuditAsync(
        ManagementRequestContext context,
        string capability,
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
                capability,
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

    private Task TryWriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken) =>
        WriteAuditAsync(
            context,
            capability,
            resource,
            decision,
            operationOutcome,
            reasonCode,
            cancellationToken);

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
