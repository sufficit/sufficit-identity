#if !APPLICATION_CONTRACTS
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Authorizations;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical application boundary for OpenID Connect/OAuth authorizations and
/// consents. Opaque payloads and token material never cross this boundary.
/// </summary>
public interface IAuthorizationManagementService
{
    Task<ManagementAuthorizationPage> SearchAsync(
        ManagementAuthorizationSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementAuthorizationSearch(
    string? Search = null,
    string? UserId = null,
    string? ClientId = null,
    bool ActiveOnly = true,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementAuthorizationPage(
    IReadOnlyList<ManagementAuthorizationSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? UserId,
    string? ClientId,
    bool ActiveOnly);

public sealed record ManagementAuthorizationSummary(
    string Id,
    string? UserId,
    string? UserName,
    string? Email,
    string? ClientId,
    string? ClientDisplayName,
    string Type,
    string Status,
    DateTimeOffset? CreatedAt,
    IReadOnlyList<string> Scopes,
    int CredentialCount,
    bool IsActive);

#else

internal sealed class AuthorizationManagementService(
    AppDbContext database,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictTokenManager tokenManager,
    IManagementAuthorizationEvaluator authorization,
    ILogger<AuthorizationManagementService> logger)
    : IAuthorizationManagementService
{
    public async Task<ManagementAuthorizationPage> SearchAsync(
        ManagementAuthorizationSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 1, 100);
        var userId = NullIfWhiteSpace(query.UserId);
        var clientId = NullIfWhiteSpace(query.ClientId);
        var resource = new ManagementResource(
            ManagementResourceTypes.AuthorizationCollection,
            userId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.AuthorizationsRead,
            resource,
            cancellationToken);

        var authorizations =
            from grant in database
                .Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .AsNoTracking()
            join application in database
                .Set<OpenIddictEntityFrameworkCoreApplication>()
                .AsNoTracking()
                on EF.Property<string?>(grant, "ApplicationId")
                equals application.Id
                into applications
            from application in applications.DefaultIfEmpty()
            join user in database.Users.AsNoTracking()
                on grant.Subject equals user.Id
                into users
            from user in users.DefaultIfEmpty()
            select new
            {
                grant.Id,
                grant.Subject,
                // A client-credentials authorization uses the client subject
                // as its OpenIddict subject. It is not an Identity user and
                // must never be projected as a user-management resource ID.
                UserId = user == null ? null : grant.Subject,
                UserName = user == null ? null : user.UserName,
                Email = user == null ? null : user.Email,
                ClientId = application == null ? null : application.ClientId,
                ClientDisplayName =
                    application == null ? null : application.DisplayName,
                grant.Type,
                grant.Status,
                grant.CreationDate,
                grant.Scopes,
                CredentialCount = database
                    .Set<OpenIddictEntityFrameworkCoreToken>()
                    .Count(token =>
                        EF.Property<string?>(token, "AuthorizationId")
                            == grant.Id)
            };

        if (userId is not null)
        {
            authorizations = authorizations.Where(
                grant => grant.Subject == userId);
        }
        if (clientId is not null)
        {
            authorizations = authorizations.Where(
                grant => grant.ClientId == clientId);
        }
        if (query.ActiveOnly)
        {
            authorizations = authorizations.Where(grant =>
                grant.Status == OpenIddictConstants.Statuses.Valid);
        }

        var search = NullIfWhiteSpace(query.Search);
        if (search is not null)
        {
            authorizations = authorizations.Where(grant =>
                grant.Subject != null && grant.Subject.Contains(search)
                || grant.UserName != null && grant.UserName.Contains(search)
                || grant.Email != null && grant.Email.Contains(search)
                || grant.ClientId != null && grant.ClientId.Contains(search)
                || grant.ClientDisplayName != null
                    && grant.ClientDisplayName.Contains(search)
                || grant.Type != null && grant.Type.Contains(search)
                || grant.Status != null && grant.Status.Contains(search));
        }

        var totalCount = await authorizations.CountAsync(cancellationToken);
        var rows = await authorizations
            .OrderByDescending(grant => grant.CreationDate)
            .ThenBy(grant => grant.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToArrayAsync(cancellationToken);
        var items = rows
            .Select(grant => new ManagementAuthorizationSummary(
                grant.Id,
                grant.UserId,
                grant.UserName,
                grant.Email,
                grant.ClientId,
                grant.ClientDisplayName,
                grant.Type ?? "unknown",
                grant.Status ?? "unknown",
                ToOffset(grant.CreationDate),
                ParseScopes(grant.Scopes),
                grant.CredentialCount,
                string.Equals(
                    grant.Status,
                    OpenIddictConstants.Statuses.Valid,
                    StringComparison.Ordinal)))
            .ToArray();

        // L3 fix (eval): no audit row on read paths.

        return new ManagementAuthorizationPage(
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
            ManagementResourceTypes.Authorization,
            id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.AuthorizationsRevoke,
            resource,
            cancellationToken);
        var grant = await authorizationManager.FindByIdAsync(
            id,
            cancellationToken);
        if (grant is null)
        {
            throw new ManagementNotFoundException(
                "authorization_not_found",
                "A autorização não foi encontrada.");
        }

        var revokedCredentials = await tokenManager.RevokeByAuthorizationIdAsync(
            id,
            cancellationToken);
        if (!await authorizationManager.TryRevokeAsync(
                grant,
                cancellationToken))
        {
            throw new ManagementConflictException(
                "authorization_revoke_failed",
                "Não foi possível revogar a autorização.");
        }

        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.AuthorizationsRevoke,
                resource,
                decision,
                "succeeded",
                "authorization_revoked"));
        await database.SaveChangesAsync(cancellationToken);
        logger.LogInformation(
            "Revoked authorization {AuthorizationId} and {TokenCount} related credentials. CorrelationId={CorrelationId}",
            id,
            revokedCredentials,
            context.CorrelationId);
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

    private static IReadOnlyList<string> ParseScopes(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(value) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static string RequiredId(string? value)
    {
        var id = NullIfWhiteSpace(value);
        if (id is null)
        {
            throw new ManagementValidationException(
                "authorization_id_required",
                "Informe a autorização.",
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
