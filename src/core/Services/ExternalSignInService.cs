using System.Security.Claims;

namespace Sufficit.Identity.Core.Services;

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
}

public sealed record ExternalSignInResult(
    ExternalSignInStatus Status,
    string? ProviderDisplayName = null,
    string? ErrorCode = null);

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
        CancellationToken cancellationToken = default);
}
