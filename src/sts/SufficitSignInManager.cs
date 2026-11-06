using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Exposes the canonical ASP.NET Identity external-login-to-2FA transition
/// to the application boundary without duplicating Identity's cookie format,
/// and keeps system users out of every interactive sign-in.
/// </summary>
/// <remarks>
/// A system user (<see cref="SystemUserStore.WhereSystemUser"/>) is an
/// ordinary user without e-mail, password, external login or passkey: it has
/// nothing to sign in with. As defense in depth every interactive sign-in
/// still passes through <see cref="PreSignInCheck"/> and every session cookie
/// through <see cref="SignInWithClaimsAsync"/>, both refusing it. Token
/// issuance asks <see cref="CanSignInAsync"/>: without an e-mail there is
/// nothing to confirm, so a system user may hold tokens while not locked out
/// (disabling is the ordinary lockout).
/// </remarks>
public sealed class SufficitSignInManager(
    UserManager<ApplicationUser> userManager,
    IHttpContextAccessor contextAccessor,
    IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory,
    IOptions<IdentityOptions> optionsAccessor,
    ILogger<SignInManager<ApplicationUser>> logger,
    IAuthenticationSchemeProvider schemes,
    IUserConfirmation<ApplicationUser> confirmation,
    SystemUserStore systemUsers,
    IPasskeyAssurancePolicy passkeyAssurance,
    IAuthenticationContextAccessor authenticationContext,
    IAuthenticationContextClassMapper authenticationClasses,
    TimeProvider timeProvider)
    : SignInManager<ApplicationUser>(
        userManager,
        contextAccessor,
        claimsFactory,
        optionsAccessor,
        logger,
        schemes,
        confirmation)
{
    public override async Task<PasskeyAssertionResult<ApplicationUser>> PerformPasskeyAssertionAsync(string credentialJson)
    {
        var result = await base.PerformPasskeyAssertionAsync(credentialJson);
        if (result.Succeeded)
        {
            // Identity calls this virtual method before it constructs the
            // application cookie. Only signed, validated flags become evidence.
            var evidence = passkeyAssurance.Read(credentialJson)
                ?? throw new InvalidOperationException("Validated passkey evidence is missing.");
            authenticationContext.Set(new AuthenticationContextEvidence(
                passkeyAssurance.AuthenticationMethods(evidence), timeProvider.GetUtcNow(),
                authenticationClasses.Map(evidence.UserVerified
                    ? CaepAssuranceLevel.PhishingResistant : CaepAssuranceLevel.Loa1)));
        }
        return result;
    }

    public Task<SignInResult> SignInOrTwoFactorForExternalAsync(
        ApplicationUser user,
        string loginProvider,
        bool isPersistent = false) =>
        SignInOrTwoFactorAsync(
            user,
            isPersistent,
            loginProvider,
            bypassTwoFactor: false);

    /// <summary>
    /// Creates the same protected pending-MFA state used after a password
    /// sign-in, but for an account already established by the application
    /// cookie. The caller must first clear any remembered-browser MFA cookie.
    /// </summary>
    public Task<SignInResult> BeginTwoFactorReauthenticationAsync(
        ApplicationUser user,
        bool isPersistent = true) =>
        SignInOrTwoFactorAsync(
            user,
            isPersistent,
            loginProvider: null,
            bypassTwoFactor: false);

    /// <summary>
    /// Refuses every interactive sign-in of a system user with the result of
    /// a wrong credential, so the answer does not reveal which accounts are
    /// system users.
    /// </summary>
    protected override async Task<SignInResult?> PreSignInCheck(ApplicationUser user)
    {
        if (await systemUsers.IsSystemUserAsync(user.Id))
        {
            Logger.LogWarning("Refused an interactive sign-in of system user {UserId}.", user.Id);
            return SignInResult.Failed;
        }

        return await base.PreSignInCheck(user);
    }

    /// <summary>
    /// For a system user: allowed while not locked out. Confirmation
    /// requirements (e-mail, phone) have nothing to confirm without them.
    /// </summary>
    public override async Task<bool> CanSignInAsync(ApplicationUser user)
    {
        if (await systemUsers.IsSystemUserAsync(user.Id))
        {
            return !await UserManager.IsLockedOutAsync(user);
        }

        return await base.CanSignInAsync(user);
    }

    /// <summary>
    /// Every session cookie is written here. A system user never gets one,
    /// whatever path reached this point.
    /// </summary>
    public override async Task SignInWithClaimsAsync(
        ApplicationUser user,
        AuthenticationProperties? authenticationProperties,
        IEnumerable<Claim> additionalClaims)
    {
        if (await systemUsers.IsSystemUserAsync(user.Id))
        {
            throw new InvalidOperationException("System users cannot hold an interactive session.");
        }

        await base.SignInWithClaimsAsync(user, authenticationProperties, additionalClaims);
    }
}
