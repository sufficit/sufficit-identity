using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Core Identity adapter for the canonical interactive sign-in
/// boundary. Cookie issuance and temporary two-factor state remain runtime
/// implementation details.
/// </summary>
public sealed class AspNetCoreIdentityInteractiveSignInService(
    SignInManager<ApplicationUser> signInManager,
    ILogger<AspNetCoreIdentityInteractiveSignInService> logger)
    : IInteractiveSignInService
{
    public async Task<IReadOnlyList<InteractiveSignInProvider>>
        GetExternalProvidersAsync(
            CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var schemes = await signInManager
            .GetExternalAuthenticationSchemesAsync();
        cancellationToken.ThrowIfCancellationRequested();
        return schemes
            .Select(scheme => new InteractiveSignInProvider(
                scheme.Name,
                string.IsNullOrWhiteSpace(scheme.DisplayName)
                    ? scheme.Name
                    : scheme.DisplayName))
            .ToArray();
    }

    public async Task<InteractiveSignInResult> PasswordSignInAsync(
        PasswordSignInCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        var result = await signInManager.PasswordSignInAsync(
            command.UserName,
            command.Password,
            command.IsPersistent,
            lockoutOnFailure: true);
        cancellationToken.ThrowIfCancellationRequested();
        var mapped = Map(result);
        if (mapped.Status == InteractiveSignInStatus.Succeeded)
        {
            logger.LogInformation(
                "User {UserName} completed password sign-in.",
                command.UserName);
        }

        return mapped;
    }

    public async Task<bool> HasPendingTwoFactorSignInAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
        cancellationToken.ThrowIfCancellationRequested();
        return user is not null;
    }

    public async Task<InteractiveSignInResult> AuthenticatorSignInAsync(
        AuthenticatorSignInCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        var pendingUser = await signInManager
            .GetTwoFactorAuthenticationUserAsync();
        if (pendingUser is null)
        {
            return new InteractiveSignInResult(
                InteractiveSignInStatus.Failed);
        }

        var code = NormalizeAuthenticatorCode(command.Code);
        var result = await signInManager.TwoFactorAuthenticatorSignInAsync(
            code,
            command.IsPersistent,
            command.RememberClient);
        cancellationToken.ThrowIfCancellationRequested();
        var mapped = Map(result);
        if (mapped.Status == InteractiveSignInStatus.Succeeded)
        {
            logger.LogInformation(
                "User {UserId} completed authenticator sign-in.",
                pendingUser.Id);
        }

        return mapped;
    }

    public async Task<InteractiveSignInResult> RecoveryCodeSignInAsync(
        string code,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var pendingUser = await signInManager
            .GetTwoFactorAuthenticationUserAsync();
        if (pendingUser is null)
        {
            return new InteractiveSignInResult(
                InteractiveSignInStatus.Failed);
        }

        var result = await signInManager.TwoFactorRecoveryCodeSignInAsync(
            NormalizeRecoveryCode(code));
        cancellationToken.ThrowIfCancellationRequested();
        var mapped = Map(result);
        if (mapped.Status == InteractiveSignInStatus.Succeeded)
        {
            logger.LogInformation(
                "User {UserId} completed recovery-code sign-in.",
                pendingUser.Id);
        }

        return mapped;
    }

    private static InteractiveSignInResult Map(SignInResult result) =>
        new(result switch
        {
            { Succeeded: true } => InteractiveSignInStatus.Succeeded,
            { RequiresTwoFactor: true } =>
                InteractiveSignInStatus.RequiresTwoFactor,
            { IsLockedOut: true } => InteractiveSignInStatus.LockedOut,
            { IsNotAllowed: true } => InteractiveSignInStatus.NotAllowed,
            _ => InteractiveSignInStatus.Failed,
        });

    private static string NormalizeAuthenticatorCode(string? code) =>
        (code ?? string.Empty)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);

    private static string NormalizeRecoveryCode(string? code) =>
        (code ?? string.Empty)
            .Replace(" ", string.Empty, StringComparison.Ordinal);
}
