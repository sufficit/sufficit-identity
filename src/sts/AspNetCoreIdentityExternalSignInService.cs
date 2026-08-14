using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Core Identity implementation of the canonical external sign-in
/// boundary.
/// </summary>
public sealed class AspNetCoreIdentityExternalSignInService(
    SufficitSignInManager signInManager,
    UserManager<ApplicationUser> userManager,
    IAccountExternalIdentityService externalIdentityService,
    IAccountOnboardingService onboardingService,
    IAccountLookupPolicy accountLookup,
    IAuthenticationContextAccessor authenticationContextAccessor,
    TimeProvider timeProvider,
    ILogger<AspNetCoreIdentityExternalSignInService> logger)
    : IExternalSignInService
{
    public Task<ExternalSignInChallenge> CreateChallengeAsync(
        string provider,
        string callbackUri,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var properties = signInManager
            .ConfigureExternalAuthenticationProperties(provider, callbackUri);
        return Task.FromResult(new ExternalSignInChallenge(
            provider,
            properties.RedirectUri ?? callbackUri,
            new Dictionary<string, string?>(
                properties.Items,
                StringComparer.Ordinal)));
    }

    public async Task<ExternalSignInResult> CompleteAsync(
        ClaimsPrincipal currentPrincipal,
        bool forceMfa,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentPrincipal);
        cancellationToken.ThrowIfCancellationRequested();
        var info = await signInManager.GetExternalLoginInfoAsync();
        cancellationToken.ThrowIfCancellationRequested();
        if (info is null)
        {
            logger.LogWarning(
                "External login callback has no protected provider state.");
            return new ExternalSignInResult(ExternalSignInStatus.Unavailable);
        }

        var linkedUser = await userManager.FindByLoginAsync(
            info.LoginProvider,
            info.ProviderKey);
        cancellationToken.ThrowIfCancellationRequested();
        var rememberedMfa = !forceMfa
            && linkedUser is not null
            && await userManager.GetTwoFactorEnabledAsync(linkedUser)
            && await signInManager.IsTwoFactorClientRememberedAsync(linkedUser);
        cancellationToken.ThrowIfCancellationRequested();
        SetExternalAuthenticationContext(info.LoginProvider, rememberedMfa);
        SignInResult signIn;
        if (forceMfa && linkedUser is { } sensitiveUser)
        {
            // A remembered browser is allowed for ordinary interactive login,
            // but never for the sensitive Management return path. Clear the
            // Identity remember-client cookie before asking the canonical
            // SignInManager flow to produce pending 2FA.
            await signInManager.ForgetTwoFactorClientAsync();
            logger.LogInformation(
                "External sign-in through {Provider} requires fresh MFA for a "
                + "sensitive return path. TraceId={TraceId}.",
                info.LoginProvider,
                AuthenticationFlowDiagnostics.TraceId);

            if (await userManager.IsLockedOutAsync(sensitiveUser))
                return new ExternalSignInResult(ExternalSignInStatus.LockedOut);
            if (!await signInManager.CanSignInAsync(sensitiveUser))
                return new ExternalSignInResult(ExternalSignInStatus.NotAllowed);

            signIn = await signInManager.SignInOrTwoFactorForExternalAsync(
                sensitiveUser,
                info.LoginProvider);
        }
        else
        {
            signIn = await signInManager.ExternalLoginSignInAsync(
                info.LoginProvider,
                info.ProviderKey,
                isPersistent: rememberedMfa,
                bypassTwoFactor: false);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (signIn.Succeeded)
        {
            logger.LogInformation(
                "User completed external sign-in through {Provider}. "
                + "Persistent={Persistent}; RememberedMfa={RememberedMfa}; "
                + "TraceId={TraceId}.",
                info.LoginProvider,
                rememberedMfa,
                rememberedMfa,
                AuthenticationFlowDiagnostics.TraceId);
            return new ExternalSignInResult(ExternalSignInStatus.Succeeded);
        }

        if (signIn.IsLockedOut)
            return new ExternalSignInResult(ExternalSignInStatus.LockedOut);
        if (signIn.IsNotAllowed)
            return new ExternalSignInResult(ExternalSignInStatus.NotAllowed);
        if (signIn.RequiresTwoFactor)
        {
            return new ExternalSignInResult(
                ExternalSignInStatus.RequiresTwoFactor);
        }

        if (currentPrincipal.Identity?.IsAuthenticated == true)
        {
            var link = await externalIdentityService.LinkAsync(
                currentPrincipal,
                new AccountExternalIdentityLink(
                    info.LoginProvider,
                    info.ProviderKey,
                    info.ProviderDisplayName),
                cancellationToken);
            if (link.Succeeded)
            {
                return new ExternalSignInResult(
                    ExternalSignInStatus.Linked,
                    info.ProviderDisplayName ?? info.LoginProvider);
            }

            var errorCode = link.Errors.FirstOrDefault()?.Code
                ?? "external-identity-link-failed";
            logger.LogWarning(
                "External identity link through {Provider} failed: {ErrorCode}.",
                info.LoginProvider,
                errorCode);
            return new ExternalSignInResult(
                ExternalSignInStatus.LinkFailed,
                ErrorCode: errorCode);
        }

        var email = info.Principal.FindFirst(ClaimTypes.Email)?.Value
            ?? info.Principal.FindFirst("email")?.Value;
        if (string.IsNullOrWhiteSpace(email))
        {
            return new ExternalSignInResult(
                ExternalSignInStatus.MissingEmail);
        }

        if (await accountLookup.FindUniqueByEmailAsync(email, cancellationToken) is not null)
        {
            logger.LogWarning(
                "External {Provider} identity matched an existing local email "
                + "without an authenticated account-linking session.",
                info.LoginProvider);
            return new ExternalSignInResult(
                ExternalSignInStatus.AccountLinkRequiresSignIn);
        }

        var registration = await onboardingService
            .GetRegistrationPolicyAsync(cancellationToken);
        if (!registration.Enabled)
        {
            return new ExternalSignInResult(
                ExternalSignInStatus.RegistrationDisabled);
        }

        var verifiedClaim = info.Principal.FindFirst("email_verified")?.Value;
        var emailVerified = string.Equals(
                verifiedClaim,
                "true",
                StringComparison.OrdinalIgnoreCase)
            || verifiedClaim == "1";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = emailVerified,
        };
        var creation = await userManager.CreateAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        if (!creation.Succeeded)
        {
            logger.LogWarning(
                "External account creation through {Provider} failed: {Codes}.",
                info.LoginProvider,
                string.Join(',', creation.Errors.Select(error => error.Code)));
            return new ExternalSignInResult(
                ExternalSignInStatus.CreateFailed);
        }

        var addLogin = await userManager.AddLoginAsync(
            user,
            new UserLoginInfo(
                info.LoginProvider,
                info.ProviderKey,
                info.ProviderDisplayName));
        cancellationToken.ThrowIfCancellationRequested();
        if (!addLogin.Succeeded)
        {
            var rollback = await userManager.DeleteAsync(user);
            logger.LogWarning(
                "External login persistence through {Provider} failed. "
                + "New account rollback succeeded: {RollbackSucceeded}.",
                info.LoginProvider,
                rollback.Succeeded);
            return new ExternalSignInResult(
                ExternalSignInStatus.CreateFailed,
                ErrorCode: "external-identity-link-failed");
        }

        // M5 fix (eval M5): gate the post-creation sign-in on the SAME policy
        // every token grant uses (CanSignInAsync), so RequireConfirmedEmail is
        // honored on the interactive path — not only on /connect/token. Without
        // this, a freshly-created external user whose email the provider did NOT
        // assert as verified (GitHub/Facebook do not map email_verified today)
        // would get an Identity cookie despite EmailConfirmed=false, reaching the
        // /account/manage self-service surface even though RequireConfirmedEmail
        // says they should not be able to sign in. The account is still created
        // (so the external identity is linked); the user simply has to confirm
        // their email before the next sign-in succeeds — exactly like the local
        // registration path.
        if (!await signInManager.CanSignInAsync(user))
        {
            logger.LogInformation(
                "Created external user {UserId} through {Provider} but deferred "
                + "sign-in: the sign-in policy (e.g. RequireConfirmedEmail) is not "
                + "yet satisfied. Verified email: {EmailVerified}.",
                user.Id,
                info.LoginProvider,
                emailVerified);
            return new ExternalSignInResult(ExternalSignInStatus.NotAllowed);
        }

        SetExternalAuthenticationContext(info.LoginProvider, rememberedMfa: false);
        await signInManager.SignInAsync(user, isPersistent: false);
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "Created and signed in user {UserId} through {Provider}; "
            + "verified email: {EmailVerified}.",
            user.Id,
            info.LoginProvider,
            emailVerified);
        return new ExternalSignInResult(ExternalSignInStatus.Succeeded);
    }

    private void SetExternalAuthenticationContext(
        string provider,
        bool rememberedMfa) =>
        authenticationContextAccessor.Set(new AuthenticationContextEvidence(
            rememberedMfa
                ? ["federated", provider.ToLowerInvariant(), "mfa"]
                : ["federated", provider.ToLowerInvariant()],
            timeProvider.GetUtcNow(),
            rememberedMfa
                ? "urn:sufficit:acr:loa2"
                : "urn:sufficit:acr:loa1"));
}
