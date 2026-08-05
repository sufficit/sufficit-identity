using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
#if !APPLICATION_CONTRACTS
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Audit;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Users;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical application boundary for identity-account administration.
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
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> CreateAsync(
        CreateManagementUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserDetail> UpdateProfileAsync(
        string id,
        UpdateManagementUserProfileCommand command,
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

    Task RequestEmailConfirmationAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementUserAccess(
    bool CanRead,
    bool CanCreate);

public sealed record CreateManagementUserCommand(
    string UserName,
    string Email,
    string InitialPassword);

public sealed record UpdateManagementUserProfileCommand(
    string UserName,
    string Email,
    string? PhoneNumber);

public sealed record ResetManagementUserPasswordCommand(
    string NewPassword);

public sealed record SetManagementUserLockoutCommand(
    bool Locked);

public sealed record ManagementUserSearch(
    string? Search = null,
    int Page = 1,
    int PageSize = 25,
    DateOnly? RegisteredFrom = null,
    DateOnly? RegisteredTo = null,
    DateOnly? RegisteredOn = null,
    ManagementUserStateFilter State = ManagementUserStateFilter.All,
    ManagementUserBooleanFilter EmailConfirmed = ManagementUserBooleanFilter.All,
    ManagementUserBooleanFilter Mfa = ManagementUserBooleanFilter.All,
    ManagementUserSort Sort = ManagementUserSort.CreatedNewest,
    int AnalyticsDays = 30,
    ManagementUserReviewFilter Review = ManagementUserReviewFilter.All);

public enum ManagementUserStateFilter
{
    All,
    Active,
    Locked,
}

public enum ManagementUserBooleanFilter
{
    All,
    Enabled,
    Disabled,
}

public enum ManagementUserSort
{
    CreatedNewest,
    CreatedOldest,
    NameAscending,
    NameDescending,
    EmailAscending,
    EmailDescending,
}

public enum ManagementUserReviewFilter
{
    All,
    StaleUnverifiedWithoutExternal,
}

public sealed record ManagementUserPage(
    IReadOnlyList<ManagementUserSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    ManagementUserAnalytics? Analytics = null);

public sealed record ManagementUserAnalytics(
    int DirectoryTotal,
    int MatchingTotal,
    int RegisteredToday,
    decimal TypicalRegistrationsPerDay,
    int AnomalyThreshold,
    IReadOnlyList<ManagementUserRegistrationDay> Days,
    int StaleUnverifiedWithoutExternalTotal = 0);

public sealed record ManagementUserRegistrationDay(
    DateOnly Date,
    int Count,
    bool IsAnomaly);

public sealed record ManagementUserSummary(
    string Id,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    bool TwoFactorEnabled,
    bool IsLockedOut,
    DateTime CreatedAtUtc = default,
    bool HasExternalLogin = false);

public sealed record ManagementUserActions(
    bool CanResetPassword,
    bool ResetPasswordRequiresMfa,
    string ResetPasswordReasonCode,
    bool CanSetLockout = false,
    bool SetLockoutRequiresMfa = false,
    string SetLockoutReasonCode = "not_evaluated",
    bool CanUpdateProfile = false,
    bool UpdateProfileRequiresMfa = false,
    string UpdateProfileReasonCode = "not_evaluated",
    bool CanDelete = false,
    bool DeleteRequiresMfa = false,
    string DeleteReasonCode = "not_evaluated");

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
            updatedAt,
            new ManagementUserActions(
                CanResetPassword: false,
                ResetPasswordRequiresMfa: false,
                ResetPasswordReasonCode: "not_evaluated"))
    {
    }
}

#else

internal sealed class UserManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IManagementAuthorizationEvaluator authorization,
    IIdentityUserSessionRevoker sessionRevoker,
    IIdentityAccountLifecycleService accountLifecycle,
    IAccountOnboardingService accountOnboarding,
    ISecurityEventTrigger securityEvents,
    ILogger<UserManagementService> logger) : IUserManagementService
{
    public async Task<ManagementUserAccess> GetAccessAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = new ManagementResource(
            ManagementResourceTypes.UserCollection);
        var readDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);
        if (!readDecision.IsAllowed)
        {
            throw new ManagementAccessException(readDecision);
        }

        var createDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersCreate,
            resource,
            cancellationToken);

        return new ManagementUserAccess(
            CanRead: true,
            CanCreate: createDecision.IsAllowed);
    }

    public async Task<ManagementUserPage> SearchAsync(
        ManagementUserSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 1, 100);
        var resource = new ManagementResource(
            ManagementResourceTypes.UserCollection);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

        var users = database.Users.AsNoTracking();
        var now = DateTimeOffset.UtcNow;

        var search = query.Search?.Trim();
        if (!string.IsNullOrWhiteSpace(search))
        {
            users = users.Where(user =>
                user.UserName != null && user.UserName.Contains(search)
                || user.Email != null && user.Email.Contains(search));
        }

        users = query.State switch
        {
            ManagementUserStateFilter.Active => users.Where(user =>
                user.LockoutEnd == null || user.LockoutEnd <= now),
            ManagementUserStateFilter.Locked => users.Where(user =>
                user.LockoutEnd != null && user.LockoutEnd > now),
            _ => users,
        };
        users = query.EmailConfirmed switch
        {
            ManagementUserBooleanFilter.Enabled => users.Where(user => user.EmailConfirmed),
            ManagementUserBooleanFilter.Disabled => users.Where(user => !user.EmailConfirmed),
            _ => users,
        };
        users = query.Mfa switch
        {
            ManagementUserBooleanFilter.Enabled => users.Where(user => user.TwoFactorEnabled),
            ManagementUserBooleanFilter.Disabled => users.Where(user => !user.TwoFactorEnabled),
            _ => users,
        };

        var staleUnverifiedCutoff = DateTime.UtcNow.AddDays(-15);
        var staleUnverifiedWithoutExternal = database.Users
            .Where(user =>
                !user.EmailConfirmed
                && user.CreatedAtUtc < staleUnverifiedCutoff
                && !database.UserLogins.Any(login => login.UserId == user.Id));
        var staleUnverifiedWithoutExternalTotal = await
            staleUnverifiedWithoutExternal.CountAsync(cancellationToken);

        if (query.Review is ManagementUserReviewFilter.StaleUnverifiedWithoutExternal)
        {
            users = users.Where(user =>
                !user.EmailConfirmed
                && user.CreatedAtUtc < staleUnverifiedCutoff
                && !database.UserLogins.Any(login => login.UserId == user.Id));
        }

        var analyticsDays = Math.Clamp(query.AnalyticsDays, 7, 120);
        var today = DateTime.UtcNow.Date;
        var analyticsStart = today.AddDays(-(analyticsDays - 1));
        var analyticsEnd = today.AddDays(1);
        var dailyRows = await users
            .Where(user => user.CreatedAtUtc >= analyticsStart &&
                user.CreatedAtUtc < analyticsEnd)
            .GroupBy(user => user.CreatedAtUtc.Date)
            .Select(group => new { Date = group.Key, Count = group.Count() })
            .ToArrayAsync(cancellationToken);
        var dailyCounts = dailyRows.ToDictionary(row => row.Date, row => row.Count);
        var counts = Enumerable.Range(0, analyticsDays)
            .Select(offset => dailyCounts.GetValueOrDefault(analyticsStart.AddDays(offset)))
            .ToArray();
        var median = Median(counts);
        var deviations = counts.Select(value => Math.Abs(value - median)).ToArray();
        var mad = Median(deviations);
        var anomalyThreshold = Math.Max(3,
            (int)Math.Ceiling(median + 3m * Math.Max(1m, 1.4826m * mad)));
        var days = Enumerable.Range(0, analyticsDays)
            .Select(offset =>
            {
                var date = analyticsStart.AddDays(offset);
                var count = dailyCounts.GetValueOrDefault(date);
                return new ManagementUserRegistrationDay(
                    DateOnly.FromDateTime(date), count, count > anomalyThreshold);
            })
            .ToArray();

        var registeredToday = dailyCounts.GetValueOrDefault(today);
        var directoryTotal = await database.Users.CountAsync(cancellationToken);

        if (query.RegisteredOn is { } registeredOn)
        {
            var start = registeredOn.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
            users = users.Where(user => user.CreatedAtUtc >= start &&
                user.CreatedAtUtc < start.AddDays(1));
        }
        else
        {
            if (query.RegisteredFrom is { } from)
            {
                var start = from.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
                users = users.Where(user => user.CreatedAtUtc >= start);
            }
            if (query.RegisteredTo is { } to)
            {
                var end = to.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc).AddDays(1);
                users = users.Where(user => user.CreatedAtUtc < end);
            }
        }

        var totalCount = await users.CountAsync(cancellationToken);
        var orderedUsers = query.Sort switch
        {
            ManagementUserSort.CreatedOldest => users
                .OrderBy(user => user.CreatedAtUtc).ThenBy(user => user.Id),
            ManagementUserSort.NameAscending => users
                .OrderBy(user => user.UserName ?? user.Email ?? user.Id).ThenBy(user => user.Id),
            ManagementUserSort.NameDescending => users
                .OrderByDescending(user => user.UserName ?? user.Email ?? user.Id).ThenBy(user => user.Id),
            ManagementUserSort.EmailAscending => users
                .OrderBy(user => user.Email ?? user.UserName ?? user.Id).ThenBy(user => user.Id),
            ManagementUserSort.EmailDescending => users
                .OrderByDescending(user => user.Email ?? user.UserName ?? user.Id).ThenBy(user => user.Id),
            _ => users.OrderByDescending(user => user.CreatedAtUtc).ThenBy(user => user.Id),
        };
        var pageRows = await orderedUsers
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                user.CreatedAtUtc,
                HasExternalLogin = database.UserLogins.Any(login =>
                    login.UserId == user.Id),
                IsLockedOut = user.LockoutEnd != null
                    && user.LockoutEnd > now
            })
            .ToArrayAsync(cancellationToken);
        var items = pageRows
            .Select(user => new ManagementUserSummary(
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                user.TwoFactorEnabled,
                user.IsLockedOut,
                user.CreatedAtUtc,
                user.HasExternalLogin))
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
            new ManagementUserAnalytics(
                directoryTotal,
                totalCount,
                registeredToday,
                median,
                anomalyThreshold,
                days,
                staleUnverifiedWithoutExternalTotal));
    }

    private static decimal Median(IReadOnlyList<int> values)
    {
        if (values.Count == 0) return 0;
        var ordered = values.OrderBy(value => value).ToArray();
        var middle = ordered.Length / 2;
        return ordered.Length % 2 == 0
            ? (ordered[middle - 1] + ordered[middle]) / 2m
            : ordered[middle];
    }

    private static decimal Median(IReadOnlyList<decimal> values)
    {
        if (values.Count == 0) return 0;
        var ordered = values.OrderBy(value => value).ToArray();
        var middle = ordered.Length / 2;
        return ordered.Length % 2 == 0
            ? (ordered[middle - 1] + ordered[middle]) / 2m
            : ordered[middle];
    }

    public async Task<ManagementUserDetail> GetAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var resource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersRead,
            resource,
            cancellationToken);

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

        var resetDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersResetPassword,
            resource,
            cancellationToken);
        var isLockedOut = user.LockoutEnd is { } lockoutEnd
            && lockoutEnd > DateTimeOffset.UtcNow;
        var lockoutDecision = await EvaluateLockoutChangeAsync(
            user.Id,
            context,
            locking: !isLockedOut,
            cancellationToken);
        var updateProfileDecision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersUpdate,
            resource,
            cancellationToken);
        var deleteDecision = await EvaluateDeleteAsync(
            user.Id,
            context,
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
            user.Timestamp,
            Actions(
                resetDecision,
                lockoutDecision,
                updateProfileDecision,
                deleteDecision));
    }

    public async Task RequestEmailConfirmationAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAsync(id, context, cancellationToken);
        if (!string.IsNullOrWhiteSpace(user.Email))
            await accountOnboarding.RequestEmailConfirmationAsync(user.Email, cancellationToken);
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
        if (!new EmailAddressAttribute().IsValid(email))
        {
            throw new ManagementValidationException(
                "user_email_invalid",
                "Informe um endereço de e-mail válido.",
                "email");
        }
        var password = Required(
            command.InitialPassword,
            "user_password_required",
            "Informe a senha inicial.",
            "initialPassword",
            trim: false);
        var collection = new ManagementResource(
            ManagementResourceTypes.UserCollection);
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

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersCreate,
                    new ManagementResource(
                        ManagementResourceTypes.User,
                        user.Id),
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
                "Unable to create a management user. CorrelationId={CorrelationId}",
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
                "Não foi possível criar o usuário.");
        }

        return await GetAsync(
            user.Id,
            context,
            cancellationToken);
    }

    public async Task<ManagementUserDetail> UpdateProfileAsync(
        string id,
        UpdateManagementUserProfileCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
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
        var phoneNumber = string.IsNullOrWhiteSpace(command.PhoneNumber)
            ? null
            : command.PhoneNumber.Trim();
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
        if (!new EmailAddressAttribute().IsValid(email))
        {
            throw new ManagementValidationException(
                "user_email_invalid",
                "Informe um endereço de e-mail válido.",
                "email");
        }
        if (phoneNumber?.Length > 256)
        {
            throw new ManagementValidationException(
                "user_phone_number_too_long",
                "Use no máximo 256 caracteres no telefone.",
                "phoneNumber");
        }

        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersUpdate,
            auditResource,
            cancellationToken);

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersUpdate,
                auditResource,
                decision,
                "not-found",
                "user_not_found",
                cancellationToken);
            throw new ManagementNotFoundException(
                "user_not_found",
                "O usuário não foi encontrado.");
        }

        var userNameChanged = !string.Equals(
            user.UserName,
            userName,
            StringComparison.Ordinal);
        var emailChanged = !string.Equals(
            user.Email,
            email,
            StringComparison.Ordinal);
        var phoneNumberChanged = !string.Equals(
            user.PhoneNumber,
            phoneNumber,
            StringComparison.Ordinal);
        var hasChanges =
            userNameChanged || emailChanged || phoneNumberChanged;

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            if (userNameChanged)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.SetUserNameAsync(user, userName));
            }

            if (emailChanged)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.SetEmailAsync(user, email));
            }

            if (phoneNumberChanged)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.SetPhoneNumberAsync(
                        user,
                        phoneNumber));
            }

            if (hasChanges)
            {
                EnsureProfileChangeSucceeded(
                    await userManager.UpdateSecurityStampAsync(user));
                var revokedTokens = await sessionRevoker.RevokeTokensAsync(
                    user.Id,
                    cancellationToken);
                logger.LogInformation(
                    "Revoked {TokenCount} tokens after updating management user {UserId}. Durable authorizations were preserved. CorrelationId={CorrelationId}",
                    revokedTokens,
                    user.Id,
                    context.CorrelationId);
            }

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersUpdate,
                    auditResource,
                    decision,
                    "succeeded",
                    hasChanges
                        ? "user_profile_updated"
                        : "user_profile_unchanged"));

            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (ProfileIdentityException exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersUpdate,
                auditResource,
                decision,
                "failed",
                IdentityReasonCode(
                    exception.Result,
                    "user_profile_update_rejected"),
                CancellationToken.None);
            throw ProfileIdentityFailure(exception.Result);
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
                "Unable to update a management user profile. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersUpdate,
                auditResource,
                decision,
                "failed",
                "user_profile_update_failed",
                CancellationToken.None);
            throw new ManagementConflictException(
                "user_profile_update_failed",
                "Não foi possível atualizar o perfil do usuário.");
        }

        return await GetAsync(
            id,
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
        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersResetPassword,
            auditResource,
            cancellationToken);

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

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersResetPassword,
                    auditResource,
                    decision,
                    "succeeded",
                    "user_password_reset"));

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

        // CAEP credential-change: administrative password reset has no target
        // session, so the emitted SET carries an iss_sub subject only.
        await securityEvents.CredentialChangedAsync(
            id,
            null,
            new CaepCredentialChange(
                CaepCredentialType.Password,
                CaepChangeOperation.Updated),
            cancellationToken);

        return await GetAsync(
            id,
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

        var decision = await EvaluateLockoutChangeAsync(
            id,
            context,
            command.Locked,
            cancellationToken);
        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);

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
            var revocation = await accountLifecycle.SetActiveAsync(
                user,
                active: !command.Locked,
                cancellationToken);
            logger.LogInformation(
                "Revoked {TokenCount} tokens and {AuthorizationCount} authorizations for management user {UserId}. CorrelationId={CorrelationId}",
                revocation.RevokedTokens,
                revocation.RevokedAuthorizations,
                user.Id,
                context.CorrelationId);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersDisable,
                    auditResource,
                    decision,
                    "succeeded",
                    command.Locked
                        ? "user_locked"
                        : "user_unlocked"));

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

        return await GetAsync(
            id,
            context,
            cancellationToken);
    }

    public async Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        var auditResource = new ManagementResource(
            ManagementResourceTypes.User,
            id);
        var decision = await EvaluateDeleteAsync(
            id,
            context,
            cancellationToken);
        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDelete,
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
                ManagementCapabilities.UsersDelete,
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
            var revocation = await accountLifecycle.DeleteAsync(
                user,
                cancellationToken);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.UsersDelete,
                    auditResource,
                    decision,
                    "succeeded",
                    "user_deleted"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Deleted identity user {UserId} after revoking {TokenCount} tokens and {AuthorizationCount} authorizations. CorrelationId={CorrelationId}",
                user.Id,
                revocation.RevokedTokens,
                revocation.RevokedAuthorizations,
                context.CorrelationId);
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
                "Unable to delete a management user. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.UsersDelete,
                auditResource,
                decision,
                "failed",
                "user_delete_failed",
                CancellationToken.None);
            throw new ManagementConflictException(
                "user_delete_failed",
                "Não foi possível excluir o usuário.");
        }
    }

    private async Task<ManagementAuthorizationDecision>
        EvaluateLockoutChangeAsync(
            string userId,
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

        return await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersDisable,
            new ManagementResource(
                ManagementResourceTypes.User,
                userId),
            cancellationToken);
    }

    private async Task<ManagementAuthorizationDecision> EvaluateDeleteAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken)
    {
        if (string.Equals(
            userId,
            context.OperatorSubject,
            StringComparison.Ordinal))
        {
            return ManagementAuthorizationDecision.Denied(
                "user_self_delete_not_allowed");
        }

        return await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.UsersDelete,
            new ManagementResource(
                ManagementResourceTypes.User,
                userId),
            cancellationToken);
    }

    private static ManagementUserActions Actions(
        ManagementAuthorizationDecision resetDecision,
        ManagementAuthorizationDecision lockoutDecision,
        ManagementAuthorizationDecision updateProfileDecision,
        ManagementAuthorizationDecision deleteDecision) =>
        new(
            resetDecision.IsAllowed,
            resetDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            resetDecision.ReasonCode,
            lockoutDecision.IsAllowed,
            lockoutDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            lockoutDecision.ReasonCode,
            updateProfileDecision.IsAllowed,
            updateProfileDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            updateProfileDecision.ReasonCode,
            deleteDecision.IsAllowed,
            deleteDecision.Outcome is
                ManagementAuthorizationOutcome.StepUpRequired,
            deleteDecision.ReasonCode);

    private static void EnsureProfileChangeSucceeded(
        IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new ProfileIdentityException(result);
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

    private static Exception ProfileIdentityFailure(
        IdentityResult result)
    {
        var reasonCode = IdentityReasonCode(
            result,
            "user_profile_update_rejected");
        if (reasonCode is "user_name_conflict" or "user_email_conflict")
        {
            return new ManagementConflictException(
                reasonCode,
                reasonCode == "user_name_conflict"
                    ? "Já existe um usuário com esse nome."
                    : "Já existe um usuário com esse e-mail.");
        }

        var field = reasonCode switch
        {
            "user_name_invalid" => "userName",
            "user_email_invalid" => "email",
            _ => null
        };
        var message = reasonCode switch
        {
            "user_name_invalid" =>
                "O nome de usuário contém caracteres não permitidos.",
            "user_email_invalid" =>
                "Informe um endereço de e-mail válido.",
            _ => "Revise os dados informados e tente novamente."
        };

        return new ManagementValidationException(
            reasonCode,
            message,
            field);
    }

    private sealed class ProfileIdentityException(
        IdentityResult result) : Exception
    {
        public IdentityResult Result { get; } = result;
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

}
#endif
