using Sufficit.Identity.Application.Security;
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
    IAuthenticationContextClassMapper authenticationContextClasses,
    IExternalIdentityLinkingPolicy linkingPolicy,
    PendingExternalIdentityStore pendingLinks,
    ExternalIdentityVerificationMessenger verificationMessenger,
    SufficitIdentityOptions identityOptions,
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
            // Best-effort: capture the provider's profile picture url (consented data)
            // so downstream avatar flows can consume it without extra provider calls.
            await PersistPictureClaimAsync(
                userManager,
                linkedUser,
                info.Principal.FindFirst(PictureClaimType)?.Value,
                cancellationToken);

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
        var pictureUrl = info.Principal.FindFirst(PictureClaimType)?.Value;

        // Account pre-hijacking gate. Creating the account and binding the
        // external identity BEFORE the address is proven is what lets an
        // attacker who registered the victim's address at a provider that does
        // not verify addresses keep that binding after the victim later proves
        // the address through registration recovery or a confirmation resend.
        // Nothing is persisted until the policy says control is established.
        var evaluation = await linkingPolicy.EvaluateAsync(
            new ExternalIdentityAssertion(
                info.LoginProvider,
                info.ProviderKey,
                info.ProviderDisplayName,
                email,
                emailVerified),
            cancellationToken);

        switch (evaluation.Decision)
        {
            case ExternalIdentityLinkingDecision.Denied:
                logger.LogInformation(
                    "External account bootstrap denied for {Provider}: {Reason}.",
                    info.LoginProvider,
                    evaluation.Reason);
                return new ExternalSignInResult(
                    ExternalSignInStatus.RegistrationDeniedForProvider,
                    ErrorCode: evaluation.Reason);

            case ExternalIdentityLinkingDecision.RequiresEmailVerification:
                return await HoldForEmailVerificationAsync(
                    info,
                    email,
                    pictureUrl,
                    evaluation.Reason,
                    cancellationToken);
        }

        return await CreateAndSignInAsync(
            new PendingExternalIdentity(
                info.LoginProvider,
                info.ProviderKey,
                info.ProviderDisplayName,
                email,
                pictureUrl),
            emailConfirmed: true,
            cancellationToken);
    }

    public async Task<ExternalSignInResult> CompletePendingLinkAsync(
        string? ticket,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var pending = await pendingLinks.RedeemAsync(ticket, cancellationToken);
        if (pending is null)
        {
            logger.LogInformation(
                "External link confirmation presented an unknown, expired or "
                + "already-redeemed ticket.");
            return new ExternalSignInResult(
                ExternalSignInStatus.LinkTicketInvalid);
        }

        // Between the message going out and the link being clicked, the address
        // may have been claimed by a legitimate registration. Binding to it now
        // would hand the external identity an account it never proved.
        if (await accountLookup.FindUniqueByEmailAsync(
                pending.Email,
                cancellationToken) is not null)
        {
            logger.LogWarning(
                "External link confirmation for {Provider} found the address "
                + "already claimed; refusing to bind without an authenticated "
                + "linking session.",
                pending.Provider);
            return new ExternalSignInResult(
                ExternalSignInStatus.AccountLinkRequiresSignIn);
        }

        // Redeeming the ticket IS the proof of possession, so the account is
        // born confirmed. Requiring a second confirmation afterwards would
        // prove the same address twice.
        return await CreateAndSignInAsync(
            pending,
            emailConfirmed: true,
            cancellationToken);
    }

    /// <summary>
    /// Persists nothing; parks the assertion and sends the proof message. The
    /// answer is identical whether or not delivery succeeded, so the response
    /// cannot be used to probe which addresses exist or which deliver.
    /// </summary>
    private async Task<ExternalSignInResult> HoldForEmailVerificationAsync(
        ExternalLoginInfo info,
        string email,
        string? pictureUrl,
        string? reason,
        CancellationToken cancellationToken)
    {
        var ticket = await pendingLinks.CreateAsync(
            new PendingExternalIdentity(
                info.LoginProvider,
                info.ProviderKey,
                info.ProviderDisplayName,
                email,
                pictureUrl),
            PendingExternalIdentityStore.ResolveLifetime(
                identityOptions.ExternalIdentities),
            cancellationToken);

        await verificationMessenger.SendAsync(
            email,
            ticket,
            info.ProviderDisplayName ?? info.LoginProvider,
            cancellationToken);

        logger.LogInformation(
            "External identity through {Provider} is awaiting email proof "
            + "before any account is created. Reason={Reason}.",
            info.LoginProvider,
            reason);
        return new ExternalSignInResult(
            ExternalSignInStatus.EmailVerificationRequired,
            info.ProviderDisplayName ?? info.LoginProvider);
    }

    private async Task<ExternalSignInResult> CreateAndSignInAsync(
        PendingExternalIdentity pending,
        bool emailConfirmed,
        CancellationToken cancellationToken)
    {
        var user = new ApplicationUser
        {
            UserName = pending.Email,
            Email = pending.Email,
            EmailConfirmed = emailConfirmed,
        };
        var creation = await userManager.CreateAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        if (!creation.Succeeded)
        {
            logger.LogWarning(
                "External account creation through {Provider} failed: {Codes}.",
                pending.Provider,
                string.Join(',', creation.Errors.Select(error => error.Code)));
            return new ExternalSignInResult(
                ExternalSignInStatus.CreateFailed);
        }

        var addLogin = await userManager.AddLoginAsync(
            user,
            new UserLoginInfo(
                pending.Provider,
                pending.ProviderKey,
                pending.ProviderDisplayName));
        cancellationToken.ThrowIfCancellationRequested();
        if (!addLogin.Succeeded)
        {
            var rollback = await userManager.DeleteAsync(user);
            logger.LogWarning(
                "External login persistence through {Provider} failed. "
                + "New account rollback succeeded: {RollbackSucceeded}.",
                pending.Provider,
                rollback.Succeeded);
            return new ExternalSignInResult(
                ExternalSignInStatus.CreateFailed,
                ErrorCode: "external-identity-link-failed");
        }

        // Best-effort: capture the provider's profile picture url on registration too,
        // so a brand-new external account already carries it.
        await PersistPictureClaimAsync(
            userManager,
            user,
            pending.PictureUrl,
            cancellationToken);

        // Gate the post-creation sign-in on the SAME policy every token grant
        // uses (CanSignInAsync), so a deployment policy such as
        // RequireConfirmedEmail is honored on the interactive path and not only
        // on /connect/token.
        if (!await signInManager.CanSignInAsync(user))
        {
            logger.LogInformation(
                "Created external user {UserId} through {Provider} but deferred "
                + "sign-in: the sign-in policy is not yet satisfied.",
                user.Id,
                pending.Provider);
            return new ExternalSignInResult(ExternalSignInStatus.NotAllowed);
        }

        SetExternalAuthenticationContext(pending.Provider, rememberedMfa: false);
        await signInManager.SignInAsync(user, isPersistent: false);
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "Created and signed in user {UserId} through {Provider}.",
            user.Id,
            pending.Provider);
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
            authenticationContextClasses.Map(rememberedMfa
                ? CaepAssuranceLevel.Loa2
                : CaepAssuranceLevel.Loa1)));

    /// <summary>
    /// The OIDC claim type the service persists from the external provider principal.
    /// </summary>
    const string PictureClaimType = "picture";

    /// <summary>
    /// Persists (add or replace) the provider's picture url claim on the user.
    /// Best-effort by design: any failure is logged and never blocks the sign-in.
    /// </summary>
    async Task PersistPictureClaimAsync(
        UserManager<ApplicationUser> userManager,
        ApplicationUser? user,
        string? pictureUrl,
        CancellationToken cancellationToken)
    {
        if (user is null || string.IsNullOrWhiteSpace(pictureUrl))
        {
            return;
        }

        try
        {
            var existing = (await userManager.GetClaimsAsync(user))
                .FirstOrDefault(claim => string.Equals(
                    claim.Type,
                    PictureClaimType,
                    StringComparison.Ordinal));
            if (existing is null)
            {
                var add = await userManager.AddClaimAsync(
                    user,
                    new Claim(PictureClaimType, pictureUrl));
                if (!add.Succeeded)
                {
                    logger.LogWarning(
                        "External picture claim persistence (add) failed for {UserId}: {Codes}.",
                        user.Id,
                        string.Join(',', add.Errors.Select(error => error.Code)));
                }
            }
            else if (!string.Equals(existing.Value, pictureUrl, StringComparison.Ordinal))
            {
                // Google rotates picture urls: replace whenever the value changed
                // so consumers always hold the current one.
                var replace = await userManager.ReplaceClaimAsync(
                    user,
                    existing,
                    new Claim(PictureClaimType, pictureUrl));
                if (!replace.Succeeded)
                {
                    logger.LogWarning(
                        "External picture claim persistence (replace) failed for {UserId}: {Codes}.",
                        user.Id,
                        string.Join(',', replace.Errors.Select(error => error.Code)));
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                "External picture claim persistence failed for {UserId}: {Message}.",
                user.Id,
                ex.Message);
        }
    }
}
