using System.Security.Claims;

namespace Sufficit.Identity.Application.Accounts;

public sealed record ExternalSignInChallenge(
    string AuthenticationScheme,
    string RedirectUri,
    IReadOnlyDictionary<string, string?> Properties);

public enum ExternalSignInStatus
{
    Unavailable,
    Succeeded,
    LockedOut,
    NotAllowed,
    RequiresTwoFactor,
    Linked,
    LinkFailed,
    MissingEmail,
    AccountLinkRequiresSignIn,
    RegistrationDisabled,
    CreateFailed,

    /// <summary>
    /// The provider did not prove control of the email address, so nothing was
    /// persisted and a proof message was sent instead. No account exists yet.
    /// </summary>
    EmailVerificationRequired,

    /// <summary>
    /// A pending-link ticket was missing, already redeemed or expired.
    /// </summary>
    LinkTicketInvalid,

    /// <summary>
    /// The provider may authenticate existing accounts but is not allowed to
    /// create one.
    /// </summary>
    RegistrationDeniedForProvider,
}

public sealed record ExternalSignInResult(
    ExternalSignInStatus Status,
    string? ProviderDisplayName = null,
    string? ErrorCode = null,
    string? ReturnUrl = null);

/// <summary>
/// Canonical external authentication boundary. Provider cookies, temporary
/// correlation state, user stores and local cookie issuance belong to the
/// runtime implementation.
/// </summary>
public interface IExternalSignInService
{
    Task<ExternalSignInChallenge> CreateChallengeAsync(
        string provider,
        string callbackUri,
        CancellationToken cancellationToken = default);

    Task<ExternalSignInResult> CompleteAsync(
        ClaimsPrincipal currentPrincipal,
        bool forceMfa,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes a link that was held pending proof of email ownership, using
    /// the single-use ticket delivered to that address.
    /// </summary>
    /// <remarks>
    /// Redeeming the ticket IS the proof: it was only ever sent to the address
    /// under dispute, so whoever presents it controls the mailbox. The account
    /// is created and bound here, not at the provider callback.
    /// </remarks>
    Task<ExternalSignInResult> CompletePendingLinkAsync(
        string? ticket,
        CancellationToken cancellationToken = default);
}
