using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

public sealed record IdentityUserSessionRevocation(
    long RevokedTokens,
    long RevokedAuthorizations,
    long RevokedBrowserSessions);

public interface IIdentityUserSessionRevoker
{
    Task<long> RevokeTokensAsync(
        string subject,
        CancellationToken cancellationToken = default);

    Task<IdentityUserSessionRevocation> RevokeAsync(
        string subject,
        CancellationToken cancellationToken = default);
}

public sealed class OpenIddictIdentityUserSessionRevoker(
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations,
    ISessionManagement browserSessions)
    : IIdentityUserSessionRevoker
{
    public async Task<long> RevokeTokensAsync(
        string subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        return await tokens.RevokeBySubjectAsync(subject, cancellationToken);
    }

    public async Task<IdentityUserSessionRevocation> RevokeAsync(
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
        // Also drop the server-side browser-session rows so every device the
        // subject is signed in on is terminated, not just the OAuth
        // credentials. Callers that bump the security stamp invalidate the
        // cookies; this keeps the session table consistent and lets the
        // per-device enumeration reflect reality.
        var revokedBrowserSessions = await browserSessions.RevokeAllBySubjectAsync(
            subject,
            exceptSessionId: null,
            cancellationToken);
        return new IdentityUserSessionRevocation(
            revokedTokens,
            revokedAuthorizations,
            revokedBrowserSessions);
    }
}

public interface IIdentityAccountLifecycleService
{
    Task<IdentityUserSessionRevocation> SetActiveAsync(
        ApplicationUser user,
        bool active,
        CancellationToken cancellationToken = default);

    Task<IdentityUserSessionRevocation> DeleteAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Canonical security mutation boundary shared by every transport adapter
/// (Management UI/API, SCIM and future protocols). Callers own the surrounding
/// database transaction and audit record.
/// </summary>
public sealed class IdentityAccountLifecycleService(
    UserManager<ApplicationUser> userManager,
    IIdentityUserSessionRevoker sessionRevoker)
    : IIdentityAccountLifecycleService
{
    private static readonly DateTimeOffset IndefiniteLockoutEnd =
        new(
            DateTimeOffset.MaxValue.Ticks
                - DateTimeOffset.MaxValue.Ticks % TimeSpan.TicksPerMicrosecond,
            TimeSpan.Zero);

    public async Task<IdentityUserSessionRevocation> SetActiveAsync(
        ApplicationUser user,
        bool active,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        cancellationToken.ThrowIfCancellationRequested();

        EnsureSucceeded(
            await userManager.SetLockoutEnabledAsync(user, true));
        EnsureSucceeded(
            await userManager.SetLockoutEndDateAsync(
                user,
                active ? null : IndefiniteLockoutEnd));
        if (active)
        {
            EnsureSucceeded(
                await userManager.ResetAccessFailedCountAsync(user));
        }
        EnsureSucceeded(
            await userManager.UpdateSecurityStampAsync(user));

        return await sessionRevoker.RevokeAsync(
            user.Id,
            cancellationToken);
    }

    public async Task<IdentityUserSessionRevocation> DeleteAsync(
        ApplicationUser user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        var revocation = await sessionRevoker.RevokeAsync(
            user.Id,
            cancellationToken);
        EnsureSucceeded(await userManager.DeleteAsync(user));
        return revocation;
    }

    private static void EnsureSucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new IdentityAccountLifecycleException(result);
        }
    }
}

public sealed class IdentityAccountLifecycleException(
    IdentityResult result) : Exception(
        string.Join(
            ' ',
            result.Errors.Select(error =>
                $"{error.Code}: {error.Description}")))
{
    public IdentityResult Result { get; } = result;
}
