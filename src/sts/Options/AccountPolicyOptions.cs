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
/// creation and password change/reset. The product policy defaults to eight
/// characters; deployments may configure a different minimum. This is not a
/// claim of NIST compliance. Existing users are NOT forced
/// to change their password on login: ASP.NET Core Identity applies password
/// rules only at creation/change time, never retroactively.
/// </summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>Minimum password length. Product default: 8.</summary>
    public int RequiredLength { get; init; } = 8;

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
    /// Rejects new and changed passwords found in known breaches, using
    /// <see cref="BreachedPasswordValidator"/> against the HaveIBeenPwned
    /// k-anonymity range API: only the first five hex characters of the SHA-1
    /// hash leave the server. Default <c>false</c>, because it requires
    /// outbound HTTPS access that an isolated deployment may not have.
    /// </summary>
    public bool RejectBreached { get; init; } = false;

    /// <summary>
    /// What happens when the breach check cannot complete (timeout, network
    /// failure or an error response). <see cref="BreachedPasswordFailureMode.FailOpen"/>
    /// (default) accepts the password so an outage of the external API does
    /// not block registration and password changes;
    /// <see cref="BreachedPasswordFailureMode.FailClosed"/> rejects it until
    /// the check succeeds.
    /// </summary>
    public BreachedPasswordFailureMode BreachedCheckFailureMode { get; init; } =
        BreachedPasswordFailureMode.FailOpen;

    /// <summary>
    /// Extra passwords the local fallback refuses, one per line, read once at
    /// startup. Comments start with <c>#</c>; blank lines are ignored.
    /// </summary>
    /// <remarks>
    /// Only consulted by
    /// <see cref="BreachedPasswordFailureMode.LocalFallback"/>, and only while
    /// the remote check is unavailable. A deployment that wants more than the
    /// built-in floor points this at its own list.
    /// </remarks>
    public string? LocalBreachedPasswordListPath { get; init; }

    /// <summary>
    /// How many range responses to keep, so a repeated prefix does not go back
    /// to the network and an outage does not affect a prefix already seen.
    /// Default 512; each entry is the suffix list of one prefix.
    /// </summary>
    public int BreachedRangeCacheSize { get; init; } = 512;

    /// <summary>How long a cached range answer stays usable. Default one hour.</summary>
    public int BreachedRangeCacheMinutes { get; init; } = 60;
}

public enum BreachedPasswordFailureMode
{
    /// <summary>Accept the password. An outage does not block anybody.</summary>
    FailOpen,

    /// <summary>
    /// Refuse the password until the check succeeds. Nobody registers or
    /// changes a password while the service is unreachable.
    /// </summary>
    FailClosed,

    /// <summary>
    /// Answer from what is known locally — a cached range for this prefix, or
    /// the local list — and accept only what neither refuses.
    /// </summary>
    /// <remarks>
    /// The middle ground the other two do not offer: an outage stops being a
    /// choice between letting a known-breached password through and stopping
    /// every password change in the deployment. What it cannot do is promise
    /// the full answer, so it is weaker than a completed check and the
    /// degraded decision is recorded.
    /// </remarks>
    LocalFallback,
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
    /// <remarks>
    /// Empty falls back to <c>Sufficit:Identity:Branding:ProductName</c>. The
    /// issuer is what the user sees next to the code in their authenticator, so
    /// it names the deployment, never the software vendor.
    /// </remarks>
    public string AuthenticatorIssuer { get; init; } = string.Empty;

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

    /// <summary>
    /// Requests WebAuthn <c>userVerification=required</c> and refuses an
    /// assertion that reports no user verification.
    /// </summary>
    /// <remarks>
    /// Default <c>true</c>, because the server claims <c>amr=mfa</c> for a
    /// passkey sign-in and only user verification makes that claim true.
    /// Turning it off keeps the sign-in working and drops the claim: the
    /// ceremony then reports possession alone, and any policy demanding a
    /// second factor will ask for one.
    /// </remarks>
    public bool RequireUserVerification { get; init; } = true;
}
