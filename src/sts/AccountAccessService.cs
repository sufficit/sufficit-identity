using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// OpenIddict implementation of the authenticated account access boundary.
/// Store access and ownership checks remain in the runtime, independently of
/// whether the caller is the embedded UI or a future HTTP adapter.
/// </summary>
public sealed class AccountAccessService(
    AppDbContext database,
    UserManager<ApplicationUser> userManager,
    IOpenIddictAuthorizationManager authorizationManager,
    IOpenIddictTokenManager tokenManager,
    IIdentityUserSessionRevoker sessionRevoker,
    ILogger<AccountAccessService> logger)
    : IAccountAccessService
{
    public async Task<IReadOnlyList<AccountConnectedApplication>>
        GetConnectedApplicationsAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return [];
        }

        var now = DateTime.UtcNow;
        var rows = await (
                from authorization in database
                    .Set<OpenIddictEntityFrameworkCoreAuthorization>()
                    .AsNoTracking()
                join application in database
                    .Set<OpenIddictEntityFrameworkCoreApplication>()
                    .AsNoTracking()
                    on EF.Property<string?>(authorization, "ApplicationId")
                    equals application.Id
                where authorization.Subject == user.Id
                    && authorization.Status
                        == OpenIddictConstants.Statuses.Valid
                select new
                {
                    ApplicationId = application.Id,
                    application.ClientId,
                    application.DisplayName,
                    authorization.CreationDate,
                    authorization.Scopes,
                    ActiveCredentialCount = database
                        .Set<OpenIddictEntityFrameworkCoreToken>()
                        .Count(token =>
                            EF.Property<string?>(token, "AuthorizationId")
                                == authorization.Id
                            && token.Status
                                == OpenIddictConstants.Statuses.Valid
                            && (token.ExpirationDate == null
                                || token.ExpirationDate > now)),
                })
            .ToArrayAsync(cancellationToken);

        return rows
            .GroupBy(row => new
            {
                row.ApplicationId,
                row.ClientId,
                row.DisplayName,
            })
            .Select(group => new AccountConnectedApplication(
                group.Key.ApplicationId,
                group.Key.ClientId,
                DisplayName(group.Key.DisplayName, group.Key.ClientId),
                ToOffset(group.Max(row => row.CreationDate)),
                group
                    .SelectMany(row => ParseScopes(row.Scopes))
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(scope => scope, StringComparer.Ordinal)
                    .ToArray(),
                group.Count(),
                group.Sum(row => row.ActiveCredentialCount)))
            .OrderByDescending(application => application.AuthorizedAt)
            .ThenBy(application => application.DisplayName, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<IReadOnlyList<AccountSessionCredential>> GetSessionsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return [];
        }

        var now = DateTime.UtcNow;
        var rows = await (
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
                where token.Subject == user.Id
                    && token.Status == OpenIddictConstants.Statuses.Valid
                    && (token.ExpirationDate == null
                        || token.ExpirationDate > now)
                orderby token.CreationDate descending, token.Id
                select new
                {
                    token.Id,
                    ClientId = application == null
                        ? null
                        : application.ClientId,
                    ApplicationDisplayName = application == null
                        ? null
                        : application.DisplayName,
                    token.Type,
                    token.CreationDate,
                    token.ExpirationDate,
                })
            .ToArrayAsync(cancellationToken);

        return rows
            .Select(row => new AccountSessionCredential(
                row.Id,
                row.ClientId,
                DisplayName(row.ApplicationDisplayName, row.ClientId),
                row.Type ?? "unknown",
                ToOffset(row.CreationDate),
                ToOffset(row.ExpirationDate)))
            .ToArray();
    }

    public async Task<AccountSelfServiceResult>
        RevokeConnectedApplicationAsync(
            ClaimsPrincipal principal,
            string applicationId,
            CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        applicationId = NormalizeId(applicationId);
        if (applicationId.Length == 0)
        {
            return NotFoundApplication();
        }

        var authorizationIds = await database
            .Set<OpenIddictEntityFrameworkCoreAuthorization>()
            .AsNoTracking()
            .Where(authorization =>
                authorization.Subject == user.Id
                && authorization.Status == OpenIddictConstants.Statuses.Valid
                && EF.Property<string?>(authorization, "ApplicationId")
                    == applicationId)
            .Select(authorization => authorization.Id!)
            .ToArrayAsync(cancellationToken);
        if (authorizationIds.Length == 0)
        {
            return NotFoundApplication();
        }

        long revokedCredentials = 0;
        foreach (var authorizationId in authorizationIds)
        {
            revokedCredentials += await tokenManager
                .RevokeByAuthorizationIdAsync(
                    authorizationId,
                    cancellationToken);
            var authorization = await authorizationManager.FindByIdAsync(
                authorizationId,
                cancellationToken);
            if (authorization is null
                || !await authorizationManager.TryRevokeAsync(
                    authorization,
                    cancellationToken))
            {
                return AccountSelfServiceResult.Failure(
                    "connected-application-revoke-failed",
                    "Not all of the application's access could be revoked.");
            }
        }

        logger.LogInformation(
            "User {UserId} revoked application {ApplicationId}; {AuthorizationCount} authorizations and {CredentialCount} credentials were revoked.",
            user.Id,
            applicationId,
            authorizationIds.Length,
            revokedCredentials);
        return AccountSelfServiceResult.Success;
    }

    public async Task<AccountSelfServiceResult> RevokeSessionAsync(
        ClaimsPrincipal principal,
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        sessionId = NormalizeId(sessionId);
        if (sessionId.Length == 0)
        {
            return NotFoundSession();
        }

        var owned = await database
            .Set<OpenIddictEntityFrameworkCoreToken>()
            .AsNoTracking()
            .AnyAsync(
                token => token.Id == sessionId
                    && token.Subject == user.Id
                    && token.Status == OpenIddictConstants.Statuses.Valid,
                cancellationToken);
        if (!owned)
        {
            return NotFoundSession();
        }

        var token = await tokenManager.FindByIdAsync(
            sessionId,
            cancellationToken);
        if (token is null
            || !await tokenManager.TryRevokeAsync(token, cancellationToken))
        {
            return AccountSelfServiceResult.Failure(
                "session-revoke-failed",
                "The issued credential could not be revoked.");
        }

        logger.LogInformation(
            "User {UserId} revoked their credential {SessionId}.",
            user.Id,
            sessionId);
        return AccountSelfServiceResult.Success;
    }

    public async Task<AccountSelfServiceResult> RevokeAllSessionsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        cancellationToken.ThrowIfCancellationRequested();
        var stampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!stampResult.Succeeded)
        {
            return FromIdentityResult(stampResult);
        }

        var revoked = await sessionRevoker.RevokeAsync(
            user.Id,
            cancellationToken);
        logger.LogInformation(
            "User {UserId} invalidated all account access; {TokenCount} credentials, {AuthorizationCount} authorizations and {SessionCount} browser sessions were revoked.",
            user.Id,
            revoked.RevokedTokens,
            revoked.RevokedAuthorizations,
            revoked.RevokedBrowserSessions);
        return AccountSelfServiceResult.Success;
    }

    public async Task<IReadOnlyList<AccountDelegatedCredential>>
        GetDelegatedCredentialsAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return [];
        }

        var rows = await DelegatedAuthorizations(user.Id)
            .ToArrayAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return rows
            .Select(row => (Row: row, Record: ReadDelegation(row.Properties)))
            .Where(item => item.Record is not null && item.Record.ExpiresAt > now)
            .Select(item => new AccountDelegatedCredential(
                item.Row.Id,
                item.Row.ClientId,
                DisplayName(item.Row.DisplayName, item.Row.ClientId),
                item.Record!.Label,
                item.Record.Delegator,
                ToOffset(item.Row.CreationDate),
                DateTimeOffset.FromUnixTimeSeconds(item.Record.ExpiresAt)))
            .OrderByDescending(credential => credential.CreatedAt)
            .ThenBy(credential => credential.Label, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<AccountSelfServiceResult> RevokeDelegatedCredentialAsync(
        ClaimsPrincipal principal,
        string credentialId,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        credentialId = NormalizeId(credentialId);
        var owned = credentialId.Length > 0
            && (await DelegatedAuthorizations(user.Id, credentialId)
                    .ToArrayAsync(cancellationToken))
                .Any(row => ReadDelegation(row.Properties) is not null);
        if (!owned)
        {
            return NotFoundDelegatedCredential();
        }

        var revokedCredentials = await tokenManager.RevokeByAuthorizationIdAsync(
            credentialId,
            cancellationToken);
        var authorization = await authorizationManager.FindByIdAsync(
            credentialId,
            cancellationToken);
        if (authorization is null
            || !await authorizationManager.TryRevokeAsync(
                authorization,
                cancellationToken))
        {
            return AccountSelfServiceResult.Failure(
                "delegated-credential-revoke-failed",
                "The delegated credential could not be revoked.");
        }

        logger.LogInformation(
            "User {UserId} revoked delegated credential {AuthorizationId}; {CredentialCount} tokens were revoked.",
            user.Id,
            credentialId,
            revokedCredentials);
        return AccountSelfServiceResult.Success;
    }

    /// <summary>
    /// Valid authorizations of the user whose properties mention the
    /// delegated-credential record. The text match only narrows the query;
    /// <see cref="ReadDelegation"/> decides.
    /// </summary>
    private IQueryable<DelegatedAuthorizationRow> DelegatedAuthorizations(
        string userId,
        string? authorizationId = null) =>
        from authorization in database
            .Set<OpenIddictEntityFrameworkCoreAuthorization>()
            .AsNoTracking()
        join application in database
            .Set<OpenIddictEntityFrameworkCoreApplication>()
            .AsNoTracking()
            on EF.Property<string?>(authorization, "ApplicationId")
            equals application.Id
            into applications
        from application in applications.DefaultIfEmpty()
        where authorization.Subject == userId
            && (authorizationId == null || authorization.Id == authorizationId)
            && authorization.Status == OpenIddictConstants.Statuses.Valid
            && authorization.Properties != null
            && authorization.Properties.Contains(
                Grants.DelegatedCredential.AuthorizationPropertyName)
        select new DelegatedAuthorizationRow(
            authorization.Id!,
            application == null ? null : application.ClientId,
            application == null ? null : application.DisplayName,
            authorization.CreationDate,
            authorization.Properties);

    private static Grants.DelegatedCredentialRecord? ReadDelegation(string? properties)
    {
        if (string.IsNullOrWhiteSpace(properties))
        {
            return null;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(properties);
            return parsed is not null
                && Grants.DelegatedCredentialRecord.TryRead(parsed, out var record)
                ? record
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record DelegatedAuthorizationRow(
        string Id,
        string? ClientId,
        string? DisplayName,
        DateTime? CreationDate,
        string? Properties);

    private static AccountSelfServiceResult NotFoundDelegatedCredential() =>
        AccountSelfServiceResult.Failure(
            "delegated-credential-not-found",
            "The delegated credential was not found.");

    private async Task<ApplicationUser?> GetAuthenticatedUserAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        cancellationToken.ThrowIfCancellationRequested();
        if (principal.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        var user = await userManager.GetUserAsync(principal);
        cancellationToken.ThrowIfCancellationRequested();
        return user;
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

    private static string DisplayName(string? displayName, string? clientId) =>
        string.IsNullOrWhiteSpace(displayName)
            ? string.IsNullOrWhiteSpace(clientId)
                ? "Unknown application"
                : clientId
            : displayName;

    private static string NormalizeId(string? value) => value?.Trim() ?? "";

    private static DateTimeOffset? ToOffset(DateTime? value) =>
        value is null
            ? null
            : new DateTimeOffset(
                DateTime.SpecifyKind(value.Value, DateTimeKind.Utc));

    private static AccountSelfServiceResult FromIdentityResult(
        IdentityResult result) =>
        new(
            result.Succeeded,
            result.Errors
                .Select(error => new AccountSelfServiceError(
                    error.Code,
                    error.Description))
                .ToArray());

    private static AccountSelfServiceResult Unauthenticated() =>
        AccountSelfServiceResult.Failure(
            "unauthenticated",
            "The session is not authenticated.");

    private static AccountSelfServiceResult NotFoundApplication() =>
        AccountSelfServiceResult.Failure(
            "connected-application-not-found",
            "The connected application was not found.");

    private static AccountSelfServiceResult NotFoundSession() =>
        AccountSelfServiceResult.Failure(
            "session-not-found",
            "The issued credential was not found.");
}
