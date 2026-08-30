using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Account lockout policy enforced by ASP.NET Core Identity during password
/// verification (interactive login and the password grant alike).
/// </summary>
public sealed class LockoutOptions
{
    /// <summary>
    /// Consecutive failed attempts before the account is locked.
    /// </summary>
    public int MaxFailedAttempts { get; init; } = 5;

    /// <summary>
    /// How long the account stays locked, in minutes.
    /// </summary>
    public double DurationMinutes { get; init; } = 5;
}
/// <summary>
/// Password complexity policy enforced by ASP.NET Core Identity on user
/// creation and password change/reset (eval M2). The defaults raise the bar
/// above the ASP.NET Core defaults (<c>RequiredLength=6</c>) toward the 2026
/// baseline (NIST 800-63B: favor length over composition rules, but require a
/// minimum of 8 — this policy defaults to 12). Existing users are NOT forced
/// to change their password on login: ASP.NET Core Identity applies password
/// rules only at creation/change time, never retroactively.
/// </summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>Minimum password length. Default 12 (NIST 800-63B floor is 8).</summary>
    public int RequiredLength { get; init; } = 12;

    /// <summary>Require at least one digit ('0'-'9'). Default true.</summary>
    public bool RequireDigit { get; init; } = true;

    /// <summary>Require at least one lowercase letter ('a'-'z'). Default true.</summary>
    public bool RequireLowercase { get; init; } = true;

    /// <summary>Require at least one uppercase letter ('A'-'Z'). Default true.</summary>
    public bool RequireUppercase { get; init; } = true;

    /// <summary>Require at least one non-alphanumeric character. Default true.</summary>
    public bool RequireNonAlphanumeric { get; init; } = true;

    /// <summary>Minimum number of distinct characters. Default 4.</summary>
    public int RequiredUniqueChars { get; init; } = 4;

    /// <summary>
    /// OPT-IN hook for a breached-password validator (HaveIBeenPwned k-anonymity
    /// range API, or a local top-N blocklist). Default <c>false</c>: the flag
    /// exists to surface the decision as explicit config, but NO validator is
    /// wired up by default in this pass — implementing the validator itself
    /// (HIBP range call with network/mock, or a local list) is tracked as a
    /// separate hardening item, since a network-dependent validator needs
    /// careful handling of latency/availability and a local list is of limited
    /// value. Flip to <c>true</c> only after the validator is implemented and
    /// its latency/availability characteristics are validated for the target
    /// environment.
    /// </summary>
    public bool RejectBreached { get; init; } = false;
}
/// <summary>
/// Sign-in policy applied by ASP.NET Core Identity's
/// <see cref="Microsoft.AspNetCore.Identity.SignInManager{TUser}.CanSignInAsync"/>
/// — which every grant in <c>AuthorizationController</c> consults. See
/// <see cref="SignInPolicyOptions"/>.
/// </summary>
public sealed class SignInPolicyOptions
{
    /// <summary>
    /// When <c>true</c> (default — secure-by-default, eval M3), a user cannot
    /// sign in until they have proven possession of their email. Combined with
    /// the public self-registration surface (gated separately in the embedded UI
    /// repo via <c>Sufficit:Identity:Register:Enabled</c>), this closes the
    /// "register with someone else's email and use the account" hole. Every
    /// grant in <c>AuthorizationController</c> collapses the unconfirmed-email
    /// case into the same generic <c>invalid_grant</c> as a wrong password, so
    /// this does NOT introduce user enumeration.
    /// </summary>
    /// <remarks>
    /// <b>External-login dependency.</b> Accounts created via an external
    /// provider (Google/GitHub/Facebook) by the runtime's
    /// <c>AspNetCoreIdentityExternalSignInService</c> are only marked
    /// <c>EmailConfirmed=true</c>
    /// when the provider asserts <c>email_verified</c>. The STS wires that
    /// <c>ClaimAction</c> for all three providers (<c>ServiceCollectionExtensions.
    /// AddExternalProviders</c>: Google and GitHub map <c>email_verified</c>
    /// directly; Facebook maps the Graph API's <c>verified</c> boolean onto the
    /// same claim). This remark previously stated Facebook/GitHub were not yet
    /// wired — corrected per eval 2026-08-14 (doc/code drift, code wins).
    /// Flipping this to <c>true</c> in production still REQUIRES confirming
    /// every newly configured provider emits an equivalent assertion, or its
    /// users will be locked out. See <c>docs/runbooks/RUNBOOK-CONFIRMED-EMAIL.md</c>
    /// for the production rollout steps, including the legacy-user migration
    /// query.
    /// </remarks>
    public bool RequireConfirmedEmail { get; init; } = true;
}
/// <summary>
/// Authenticator-app two-factor settings used by the account-management
/// application service.
/// </summary>
public sealed class TwoFactorOptions
{
    /// <summary>
    /// Issuer displayed by authenticator applications.
    /// </summary>
    public string AuthenticatorIssuer { get; init; } = "Sufficit Identity";

    /// <summary>
    /// One-time recovery codes generated after activation or regeneration.
    /// Values outside 1..20 are clamped by the runtime.
    /// </summary>
    public int RecoveryCodeCount { get; init; } = 10;
}
/// <summary>
/// Provider-neutral account passkey settings. The STS adapter maps these
/// values to the concrete WebAuthn implementation used at runtime.
/// </summary>
public sealed class AccountPasskeyOptions
{
    /// <summary>
    /// Optional WebAuthn relying-party identifier. When absent, ASP.NET
    /// Identity derives it from the validated request host.
    /// </summary>
    public string? RelyingPartyId { get; init; }

    /// <summary>
    /// Maximum passkeys that one account may retain.
    /// </summary>
    public int MaximumCredentialsPerAccount { get; init; } = 10;

    /// <summary>
    /// Maximum display-name length accepted from the account UI.
    /// </summary>
    public int MaximumNameLength { get; init; } = 100;

    /// <summary>
    /// Maximum UTF-8 size accepted for a serialized WebAuthn credential.
    /// </summary>
    public int MaximumCredentialPayloadBytes { get; init; } = 131_072;
}
