using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

public sealed record IdentityUserSessionRevocation(
    long RevokedTokens,
    long RevokedAuthorizations);

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
    IOpenIddictAuthorizationManager authorizations)
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
        return new IdentityUserSessionRevocation(
            revokedTokens,
            revokedAuthorizations);
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
