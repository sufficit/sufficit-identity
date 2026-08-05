#if !APPLICATION_CONTRACTS
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Users;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Sessions;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical application boundary for provider-issued credentials. OpenIddict
/// remains the source of truth; no parallel browser-session store is created.
/// </summary>
public interface ISessionManagementService
{
    Task<ManagementSessionPage> SearchAsync(
        ManagementSessionSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserSessionRevocation> RevokeAllForUserAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementSessionSearch(
    string? Search = null,
    string? UserId = null,
    string? ClientId = null,
    bool ActiveOnly = true,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementSessionPage(
    IReadOnlyList<ManagementSessionSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? UserId,
    string? ClientId,
    bool ActiveOnly);

public sealed record ManagementSessionSummary(
    string Id,
    string? UserId,
    string? UserName,
    string? Email,
    string? ClientId,
    string? ClientDisplayName,
    string? AuthorizationId,
    string Type,
    string Status,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RedeemedAt,
    bool IsActive);

public sealed record ManagementUserSessionRevocation(
    long RevokedTokens,
    long RevokedAuthorizations);

#else

internal sealed class SessionManagementService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IOpenIddictTokenManager tokenManager,
    IIdentityUserSessionRevoker sessionRevoker,
    IManagementAuthorizationEvaluator authorization,
    ILogger<SessionManagementService> logger) : ISessionManagementService
{
    public async Task<ManagementSessionPage> SearchAsync(
        ManagementSessionSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 1, 100);
        var userId = NullIfWhiteSpace(query.UserId);
        var clientId = NullIfWhiteSpace(query.ClientId);
        var resource = new ManagementResource(
            ManagementResourceTypes.SessionCollection,
            userId,
            clientId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.SessionsRead,
            resource,
            cancellationToken);

        var tokens =
            from token in database
                .Set<OpenIddictEntityFrameworkCoreToken>()
                .AsNoTracking()
            join application in database
                .Set<OpenIddictEntityFrameworkCoreApplication>()
                .AsNoTracking()
                on EF.Property<string?>(token, "ApplicationId")
                equals application.Id
                into applications
            from application in applications.DefaultIfEmpty()
            join user in database.Users.AsNoTracking()
                on token.Subject equals user.Id
                into users
            from user in users.DefaultIfEmpty()
            select new
            {
                token.Id,
                token.Subject,
                UserName = user == null ? null : user.UserName,
                Email = user == null ? null : user.Email,
                ClientId = application == null ? null : application.ClientId,
                ClientDisplayName =
                    application == null ? null : application.DisplayName,
                AuthorizationId =
                    EF.Property<string?>(token, "AuthorizationId"),
                token.Type,
                token.Status,
                token.CreationDate,
                token.ExpirationDate,
                token.RedemptionDate
            };

        if (userId is not null)
        {
            tokens = tokens.Where(token => token.Subject == userId);
        }
        if (clientId is not null)
        {
            tokens = tokens.Where(token => token.ClientId == clientId);
        }
        if (query.ActiveOnly)
        {
            tokens = tokens.Where(token =>
                token.Status == OpenIddictConstants.Statuses.Valid);
        }

        var search = NullIfWhiteSpace(query.Search);
        if (search is not null)
        {
            tokens = tokens.Where(token =>
                token.Subject != null && token.Subject.Contains(search)
                || token.UserName != null && token.UserName.Contains(search)
                || token.Email != null && token.Email.Contains(search)
                || token.ClientId != null && token.ClientId.Contains(search)
                || token.ClientDisplayName != null
                    && token.ClientDisplayName.Contains(search)
                || token.Type != null && token.Type.Contains(search)
                || token.Status != null && token.Status.Contains(search));
        }

        var totalCount = await tokens.CountAsync(cancellationToken);
        var rows = await tokens
            .OrderByDescending(token => token.CreationDate)
            .ThenBy(token => token.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToArrayAsync(cancellationToken);
        var items = rows
            .Select(token => new ManagementSessionSummary(
                token.Id,
                token.Subject,
                token.UserName,
                token.Email,
                token.ClientId,
                token.ClientDisplayName,
                token.AuthorizationId,
                token.Type ?? "unknown",
                token.Status ?? "unknown",
                ToOffset(token.CreationDate),
                ToOffset(token.ExpirationDate),
                ToOffset(token.RedemptionDate),
                string.Equals(
                    token.Status,
                    OpenIddictConstants.Statuses.Valid,
                    StringComparison.Ordinal)))
            .ToArray();

        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.SessionsRead,
                resource,
                decision,
                "succeeded",
                "sessions_listed"));
        await database.SaveChangesAsync(cancellationToken);

        return new ManagementSessionPage(
            items,
            page,
            pageSize,
            totalCount,
            userId,
            clientId,
            query.ActiveOnly);
    }

    public async Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        id = RequiredId(id);
        var resource = new ManagementResource(
            ManagementResourceTypes.Session,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.SessionsRevoke,
            resource,
            cancellationToken);
        var token = await tokenManager.FindByIdAsync(id, cancellationToken);
        if (token is null)
        {
            throw new ManagementNotFoundException(
                "session_not_found",
                "A credencial emitida não foi encontrada.");
        }

        if (!await tokenManager.TryRevokeAsync(token, cancellationToken))
        {
            throw new ManagementConflictException(
                "session_revoke_failed",
                "Não foi possível revogar a credencial emitida.");
        }

        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.SessionsRevoke,
                resource,
                decision,
                "succeeded",
                "session_revoked"));
        await database.SaveChangesAsync(cancellationToken);
        logger.LogInformation(
            "Revoked provider-issued credential {SessionId}. CorrelationId={CorrelationId}",
            id,
            context.CorrelationId);
    }

    public async Task<ManagementUserSessionRevocation> RevokeAllForUserAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        userId = RequiredId(userId);
        var resource = new ManagementResource(
            ManagementResourceTypes.SessionCollection,
            userId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.SessionsRevoke,
            resource,
            cancellationToken);
        var user = await userManager.FindByIdAsync(userId);
        if (user is null)
        {
            throw new ManagementNotFoundException(
                "session_user_not_found",
                "A conta não foi encontrada.");
        }

        var stampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!stampResult.Succeeded)
        {
            throw new ManagementConflictException(
                "session_cookie_revoke_failed",
                "Não foi possível invalidar as sessões da conta.");
        }

        var result = await sessionRevoker.RevokeAsync(
            userId,
            cancellationToken);
        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.SessionsRevoke,
                resource,
                decision,
                "succeeded",
                "user_sessions_revoked"));
        await database.SaveChangesAsync(cancellationToken);
        logger.LogInformation(
            "Invalidated account sessions for {UserId}; revoked {TokenCount} credentials and {AuthorizationCount} authorizations. CorrelationId={CorrelationId}",
            userId,
            result.RevokedTokens,
            result.RevokedAuthorizations,
            context.CorrelationId);
        return new ManagementUserSessionRevocation(
            result.RevokedTokens,
            result.RevokedAuthorizations);
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

    private static string RequiredId(string? value)
    {
        var id = NullIfWhiteSpace(value);
        if (id is null)
        {
            throw new ManagementValidationException(
                "session_id_required",
                "Informe a sessão.",
                "id");
        }

        return id;
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static DateTimeOffset? ToOffset(DateTime? value) =>
        value is null
            ? null
            : new DateTimeOffset(
                DateTime.SpecifyKind(value.Value, DateTimeKind.Utc));
}
#endif
