using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Management.SystemUsers;

/// <summary>
/// Creates system users, enables and disables them, and issues and revokes
/// their enrollment codes. Every change is audited with the operator.
/// </summary>
/// <remarks>
/// Capabilities follow what the action does to a user: reading and creating
/// use the users capabilities, enabling and disabling use
/// <see cref="ManagementCapabilities.UsersDisable"/>, and issuing or revoking
/// a credential uses <see cref="ManagementCapabilities.UsersReset"/>, the
/// capability that already governs a user's credentials. Issuing is marked as
/// minting a credential. Entitlements use the claims capabilities.
/// <para>
/// <see cref="ManagementCapabilities.SystemUsersManage"/> satisfies all of
/// them here and nowhere else: every operation either creates a system user or
/// resolves its target among system users first, so a holder of only that
/// capability (a provisioning service) never reaches a person.
/// </para>
/// </remarks>
internal sealed partial class SystemUserManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> users,
    IOpenIddictApplicationManager applications,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens,
    ManagementOperationGuard guard,
    TimeProvider timeProvider,
    ILogger<SystemUserManagementService> logger)
    : ISystemUserManagementService
{
    internal const int DefaultEnrollmentLifetimeHours = 24;
    internal const int MaximumEnrollmentLifetimeHours = 168;
    private const int DisplayNameMaxLength = 200;
    private const int MaximumEntitlements = 50;
    private const string EntitlementClaimType = "entitlements";

    private static readonly ManagementResource CollectionResource =
        new(ManagementResourceTypes.UserCollection);

    public async Task<IReadOnlyList<SystemUserSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        await DemandAsync(context, ManagementCapabilities.UsersRead, CollectionResource, cancellationToken);

        var records = await database.SystemUsers.AsNoTracking()
            .OrderBy(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);
        var summaries = new List<SystemUserSummary>(records.Count);
        foreach (var record in records)
        {
            summaries.Add(await SummarizeAsync(record, cancellationToken));
        }

        return summaries;
    }

    public async Task<SystemUserSummary> CreateAsync(
        CreateSystemUserCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(context);
        var decision = await DemandAsync(
            context, ManagementCapabilities.UsersCreate, CollectionResource, cancellationToken, auditDenial: true);

        var userName = command.UserName?.Trim();
        if (string.IsNullOrWhiteSpace(userName))
        {
            throw new ManagementValidationException(
                "system_user_name_required", "A user name is required.", "userName");
        }

        var displayName = string.IsNullOrWhiteSpace(command.DisplayName) ? null : command.DisplayName.Trim();
        if (displayName is { Length: > DisplayNameMaxLength })
        {
            throw new ManagementValidationException(
                "system_user_display_name_too_long",
                $"The display name must not exceed {DisplayNameMaxLength} characters.",
                "displayName");
        }

        if (await users.FindByNameAsync(userName) is not null)
        {
            throw new ManagementConflictException(
                "system_user_name_taken", "A user with this name already exists.");
        }

        if (command.UserId == Guid.Empty)
        {
            throw new ManagementValidationException(
                "system_user_id_invalid", "The user ID must not be empty.", "userId");
        }

        // No password, no e-mail, no external login: nothing a sign-in could use.
        var user = new ApplicationUser { UserName = userName };
        if (command.UserId is { } requestedId)
        {
            // Never adopt an existing account: a caller-chosen ID must be new.
            user.Id = requestedId.ToString("D");
            if (await users.FindByIdAsync(user.Id) is not null)
            {
                throw new ManagementConflictException(
                    "system_user_id_taken", "A user with this ID already exists.");
            }
        }
        var created = await users.CreateAsync(user);
        if (!created.Succeeded)
        {
            throw new ManagementValidationException(
                "system_user_invalid",
                string.Join(" ", created.Errors.Select(error => error.Description)),
                "userName");
        }

        if (displayName is not null)
        {
            await users.AddClaimAsync(user, new Claim(OpenIddictConstants.Claims.Name, displayName));
        }

        var record = new SystemUser
        {
            UserId = user.Id,
            CreatedBy = Truncate(context.OperatorSubject),
            CreatedAtUtc = timeProvider.GetUtcNow().UtcDateTime,
            CorrelationId = Truncate(context.CorrelationId, IdentityDatabaseSchema.SystemUserCorrelationLength),
        };
        database.SystemUsers.Add(record);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.UsersCreate,
            UserResource(user.Id),
            decision,
            "succeeded",
            "system_user_created"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "System user {UserId} ({UserName}) created by {Subject}; correlation={CorrelationId}.",
            user.Id, userName, context.OperatorSubject, context.CorrelationId);
        return await SummarizeAsync(record, cancellationToken);
    }

    public async Task<SystemUserSummary> ToggleAsync(
        string userId,
        bool? enabled,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var decision = await DemandAsync(
            context, ManagementCapabilities.UsersDisable, UserResource(userId), cancellationToken, auditDenial: true);

        var record = await FindTrackedAsync(userId, cancellationToken);
        var enable = enabled ?? record.DisabledAtUtc is not null;
        if (enable == (record.DisabledAtUtc is null))
        {
            return await SummarizeAsync(record, cancellationToken);
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var revoked = 0;
        if (enable)
        {
            record.DisabledAtUtc = null;
            record.DisabledBy = null;
        }
        else
        {
            record.DisabledAtUtc = now;
            record.DisabledBy = Truncate(context.OperatorSubject);
            // Disabling ends every credential: re-enabling needs a new enrollment.
            var active = await database.SystemUserEnrollments
                .Where(x => x.UserId == userId && x.RevokedAtUtc == null)
                .ToListAsync(cancellationToken);
            foreach (var enrollment in active)
            {
                await RevokeCredentialAsync(enrollment, context, now, cancellationToken);
                revoked++;
            }
        }

        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.UsersDisable,
            UserResource(userId),
            decision,
            "succeeded",
            enable ? "system_user_enabled" : "system_user_disabled"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "System user {UserId} {State} by {Subject}; credentials revoked={Revoked}; correlation={CorrelationId}.",
            userId, enable ? "enabled" : "disabled", context.OperatorSubject, revoked, context.CorrelationId);
        return await SummarizeAsync(record, cancellationToken);
    }

    public async Task<IReadOnlyList<SystemUserEnrollmentSummary>> ListEnrollmentsAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        await DemandAsync(context, ManagementCapabilities.UsersRead, UserResource(userId), cancellationToken);
        _ = await FindTrackedAsync(userId, cancellationToken);

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var records = await database.SystemUserEnrollments.AsNoTracking()
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);
        return records.Select(record => ToSummary(record, now)).ToArray();
    }

    public async Task<SystemUserEnrollmentIssueResult> IssueEnrollmentAsync(
        string userId,
        IssueSystemUserEnrollmentCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(context);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.UsersReset,
            UserResource(userId),
            cancellationToken,
            auditDenial: true,
            mintsCredential: true);

        var record = await FindTrackedAsync(userId, cancellationToken);
        if (record.DisabledAtUtc is not null)
        {
            throw new ManagementConflictException(
                "system_user_disabled", "Enable the system user before issuing a credential.");
        }

        var label = command.Label?.Trim();
        if (string.IsNullOrWhiteSpace(label))
        {
            throw new ManagementValidationException(
                "system_user_enrollment_label_required",
                "A label saying where the credential will live is required.",
                "label");
        }

        if (label.Length > IdentityDatabaseSchema.SystemUserEnrollmentLabelLength)
        {
            throw new ManagementValidationException(
                "system_user_enrollment_label_too_long",
                $"The label must not exceed {IdentityDatabaseSchema.SystemUserEnrollmentLabelLength} characters.",
                "label");
        }

        var lifetimeHours = command.LifetimeHours ?? DefaultEnrollmentLifetimeHours;
        if (lifetimeHours is < 1 or > MaximumEnrollmentLifetimeHours)
        {
            throw new ManagementValidationException(
                "system_user_enrollment_lifetime_invalid",
                $"The code lifetime must be between 1 and {MaximumEnrollmentLifetimeHours} hours.",
                "lifetimeHours");
        }

        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var application = string.IsNullOrEmpty(clientId)
            ? null
            : await applications.FindByClientIdAsync(clientId, cancellationToken);
        if (application is null
            || !await applications.HasPermissionAsync(
                application, Permissions.Prefixes.GrantType + SystemUserEnrollmentProtocol.GrantType, cancellationToken)
            || !await applications.HasPermissionAsync(
                application, Permissions.GrantTypes.RefreshToken, cancellationToken))
        {
            throw new ManagementValidationException(
                "system_user_enrollment_client_not_allowed",
                "The client must exist and allow both the system-user enrollment grant and refresh tokens.",
                "clientId");
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var (enrollment, code) = SystemUserStore.CreateEnrollment(
            userId, clientId, label, Truncate(context.OperatorSubject), now, TimeSpan.FromHours(lifetimeHours));
        database.SystemUserEnrollments.Add(enrollment);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.UsersReset,
            UserResource(userId),
            decision,
            "succeeded",
            "system_user_enrollment_issued"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Enrollment {EnrollmentId} for system user {UserId} and client {ClientId} issued by {Subject}; expiresAt={ExpiresAtUtc}; correlation={CorrelationId}.",
            enrollment.Id, userId, clientId, context.OperatorSubject, enrollment.ExpiresAtUtc, context.CorrelationId);
        return new SystemUserEnrollmentIssueResult(
            ToSummary(enrollment, now), code, SystemUserEnrollmentProtocol.GrantType);
    }

    public async Task RevokeEnrollmentAsync(
        string userId,
        Guid enrollmentId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var decision = await DemandAsync(
            context, ManagementCapabilities.UsersReset, UserResource(userId), cancellationToken, auditDenial: true);

        var enrollment = await database.SystemUserEnrollments
            .SingleOrDefaultAsync(x => x.Id == enrollmentId && x.UserId == userId, cancellationToken)
            ?? throw new ManagementNotFoundException(
                "system_user_enrollment_not_found", "The enrollment was not found.");
        if (enrollment.RevokedAtUtc is not null)
        {
            return;
        }

        await RevokeCredentialAsync(enrollment, context, timeProvider.GetUtcNow().UtcDateTime, cancellationToken);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.UsersReset,
            UserResource(userId),
            decision,
            "succeeded",
            "system_user_enrollment_revoked"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Enrollment {EnrollmentId} of system user {UserId} revoked by {Subject}; correlation={CorrelationId}.",
            enrollmentId, userId, context.OperatorSubject, context.CorrelationId);
    }

    /// <summary>Marks the enrollment revoked and ends the credential it produced, if any.</summary>
    private async Task RevokeCredentialAsync(
        SystemUserEnrollment enrollment,
        ManagementRequestContext context,
        DateTime now,
        CancellationToken cancellationToken)
    {
        enrollment.RevokedAtUtc = now;
        enrollment.RevokedBy = Truncate(context.OperatorSubject);
        if (string.IsNullOrEmpty(enrollment.AuthorizationId))
        {
            return;
        }

        await tokens.RevokeByAuthorizationIdAsync(enrollment.AuthorizationId, cancellationToken);
        if (await authorizations.FindByIdAsync(enrollment.AuthorizationId, cancellationToken) is { } authorization)
        {
            await authorizations.TryRevokeAsync(authorization, cancellationToken);
        }
    }

    public async Task<IReadOnlyList<string>> GetEntitlementsAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        await DemandAsync(context, ManagementCapabilities.ClaimsRead, UserResource(userId), cancellationToken);
        _ = await FindTrackedAsync(userId, cancellationToken);
        return await ReadEntitlementsAsync(userId, cancellationToken);
    }

    public async Task<IReadOnlyList<string>> SetEntitlementsAsync(
        string userId,
        SetSystemUserEntitlementsCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(context);
        var decision = await DemandAsync(
            context, ManagementCapabilities.ClaimsCreate, UserResource(userId), cancellationToken, auditDenial: true);
        _ = await FindTrackedAsync(userId, cancellationToken);

        var wanted = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var raw in command.Entitlements ?? [])
        {
            wanted.Add(NormalizeEntitlement(raw));
        }

        if (wanted.Count > MaximumEntitlements)
        {
            throw new ManagementValidationException(
                "system_user_entitlements_too_many",
                $"A system user holds at most {MaximumEntitlements} entitlements.",
                "entitlements");
        }

        var current = await database.UserClaims
            .Where(x => x.UserId == userId && x.ClaimType == EntitlementClaimType)
            .ToListAsync(cancellationToken);
        var removed = current.Where(x => x.ClaimValue is null || !wanted.Contains(x.ClaimValue)).ToList();
        var kept = current.Select(x => x.ClaimValue).OfType<string>().ToHashSet(StringComparer.Ordinal);
        database.UserClaims.RemoveRange(removed);
        foreach (var value in wanted.Where(value => !kept.Contains(value)))
        {
            database.UserClaims.Add(new IdentityUserClaim<string>
            {
                UserId = userId, ClaimType = EntitlementClaimType, ClaimValue = value,
            });
        }

        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.ClaimsCreate,
            UserResource(userId),
            decision,
            "succeeded",
            "system_user_entitlements_set"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Entitlements of system user {UserId} set by {Subject}: {Entitlements}; correlation={CorrelationId}.",
            userId, context.OperatorSubject, string.Join(",", wanted), context.CorrelationId);
        return [.. wanted];
    }

    private async Task<IReadOnlyList<string>> ReadEntitlementsAsync(string userId, CancellationToken cancellationToken) =>
        await database.UserClaims.AsNoTracking()
            .Where(x => x.UserId == userId && x.ClaimType == EntitlementClaimType && x.ClaimValue != null)
            .OrderBy(x => x.ClaimValue)
            .Select(x => x.ClaimValue!)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// <c>key</c> or <c>key:context</c>; a context in any UUID spelling is stored
    /// compact (32 lowercase hex), the form every entitlement uses since 2026-09-02.
    /// </summary>
    internal static string NormalizeEntitlement(string? raw)
    {
        var value = raw?.Trim().ToLowerInvariant() ?? string.Empty;
        var separator = value.IndexOf(':');
        var key = separator < 0 ? value : value[..separator];
        if (!EntitlementKey().IsMatch(key))
        {
            throw new ManagementValidationException(
                "system_user_entitlement_invalid", $"Invalid entitlement: '{raw}'.", "entitlements");
        }

        if (separator < 0)
        {
            return key;
        }

        if (!Guid.TryParse(value[(separator + 1)..], out var contextId) || contextId == Guid.Empty)
        {
            throw new ManagementValidationException(
                "system_user_entitlement_invalid", $"Invalid entitlement context: '{raw}'.", "entitlements");
        }

        return key + ":" + contextId.ToString("N");
    }

    [System.Text.RegularExpressions.GeneratedRegex("^[a-z][a-z0-9._-]{0,63}$")]
    private static partial System.Text.RegularExpressions.Regex EntitlementKey();

    /// <summary>
    /// <see cref="ManagementCapabilities.SystemUsersManage"/> first, then the
    /// general capability; only the second refusal is reported and audited.
    /// </summary>
    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken,
        bool auditDenial = false,
        bool mintsCredential = false)
    {
        try
        {
            return await guard.DemandAsync(
                context, ManagementCapabilities.SystemUsersManage, resource, cancellationToken,
                mintsCredential: mintsCredential);
        }
        catch (ManagementAccessException)
        {
            return await guard.DemandAsync(
                context, capability, resource, cancellationToken, auditDenial, mintsCredential);
        }
    }

    private async Task<SystemUser> FindTrackedAsync(string userId, CancellationToken cancellationToken) =>
        await database.SystemUsers.SingleOrDefaultAsync(x => x.UserId == userId, cancellationToken)
        ?? throw new ManagementNotFoundException("system_user_not_found", "The system user was not found.");

    private async Task<SystemUserSummary> SummarizeAsync(SystemUser record, CancellationToken cancellationToken)
    {
        var user = await database.Users.AsNoTracking()
            .Where(x => x.Id == record.UserId)
            .Select(x => new { x.UserName })
            .SingleOrDefaultAsync(cancellationToken);
        var displayName = await database.UserClaims.AsNoTracking()
            .Where(x => x.UserId == record.UserId && x.ClaimType == OpenIddictConstants.Claims.Name)
            .Select(x => x.ClaimValue)
            .FirstOrDefaultAsync(cancellationToken);
        var activeCredentials = await database.SystemUserEnrollments.AsNoTracking()
            .CountAsync(x => x.UserId == record.UserId && x.RedeemedAtUtc != null && x.RevokedAtUtc == null,
                cancellationToken);
        return new SystemUserSummary(
            record.UserId,
            user?.UserName ?? record.UserId,
            displayName,
            record.CreatedBy,
            record.CreatedAtUtc,
            record.DisabledAtUtc is not null,
            record.DisabledAtUtc,
            activeCredentials);
    }

    private static SystemUserEnrollmentSummary ToSummary(SystemUserEnrollment record, DateTime now) =>
        new(record.Id,
            record.ClientId,
            record.Label,
            record.CodeHint,
            record.IssuedBy,
            record.CreatedAtUtc,
            record.ExpiresAtUtc,
            record.RedeemedAtUtc,
            record.RevokedAtUtc,
            record.RevokedAtUtc is not null ? SystemUserEnrollmentStatus.Revoked
            : record.RedeemedAtUtc is not null ? SystemUserEnrollmentStatus.Active
            : record.ExpiresAtUtc <= now ? SystemUserEnrollmentStatus.Expired
            : SystemUserEnrollmentStatus.Pending);

    private static ManagementResource UserResource(string userId) =>
        new(ManagementResourceTypes.User, userId, userId);

    private static string Truncate(string? value, int length = IdentityDatabaseSchema.SystemUserSubjectLength) =>
        string.IsNullOrEmpty(value) ? "unknown" : value.Length <= length ? value : value[..length];
}
