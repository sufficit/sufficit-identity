using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Core Identity adapter for the canonical interactive sign-in
/// boundary. Cookie issuance and temporary two-factor state remain runtime
/// implementation details.
/// </summary>
public sealed class AspNetCoreIdentityInteractiveSignInService(
    SignInManager<ApplicationUser> signInManager,
    IAuthenticationContextAccessor authenticationContextAccessor,
    TimeProvider timeProvider,
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
        SetAuthenticationContext(["pwd"], "urn:sufficit:acr:loa1");
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
        SetAuthenticationContext(["pwd", "otp", "mfa"], "urn:sufficit:acr:loa2");
        var result = await signInManager.TwoFactorAuthenticatorSignInAsync(
            code,
            command.IsPersistent,
            command.RememberClient);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.Succeeded)
        {
            // Identity has just accepted the OTP and issued the application
            // cookie. Its normal RefreshSignInAsync path reconstructs the
            // principal through a new claims-factory invocation; with the
            // production security-stamp validator running on every request,
            // that invocation can lose the request-scoped MFA evidence. Issue
            // the replacement ticket with the elevated claims explicitly so
            // the server-side session cannot fall back to Loa1 at this point.
            await signInManager.SignInWithClaimsAsync(
                pendingUser,
                command.IsPersistent,
                MfaClaims("otp"));
            cancellationToken.ThrowIfCancellationRequested();
        }
        var mapped = Map(result);
        if (mapped.Status == InteractiveSignInStatus.Succeeded)
        {
            logger.LogInformation(
                "User {UserId} completed authenticator sign-in with "
                + "authentication methods {AuthenticationMethods} and "
                + "context {AuthenticationContextClass}.",
                pendingUser.Id,
                string.Join(
                    ' ',
                    authenticationContextAccessor.Current?.AuthenticationMethods
                        ?? []),
                authenticationContextAccessor.Current?.AuthenticationContextClass
                    ?? "missing");
        }
        else
        {
            logger.LogWarning(
                "Authenticator sign-in for user {UserId} ended with status {Status}.",
                pendingUser.Id,
                mapped.Status);
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

        SetAuthenticationContext(["pwd", "rc", "mfa"], "urn:sufficit:acr:loa2");
        var result = await signInManager.TwoFactorRecoveryCodeSignInAsync(
            NormalizeRecoveryCode(code));
        cancellationToken.ThrowIfCancellationRequested();
        if (result.Succeeded)
        {
            await signInManager.SignInWithClaimsAsync(
                pendingUser,
                isPersistent: false,
                MfaClaims("rc"));
            cancellationToken.ThrowIfCancellationRequested();
        }
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

    private static IReadOnlyCollection<Claim> MfaClaims(string secondFactor) =>
    [
        new("amr", "pwd"),
        new("amr", secondFactor),
        new("amr", "mfa"),
        new("aal", "Loa2"),
        new("acr", "urn:sufficit:acr:loa2"),
    ];

    private void SetAuthenticationContext(
        IReadOnlyCollection<string> methods,
        string authenticationContextClass) =>
        authenticationContextAccessor.Set(new AuthenticationContextEvidence(
            methods,
            timeProvider.GetUtcNow(),
            authenticationContextClass));
}
