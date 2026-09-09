namespace Sufficit.Identity.STS.Controllers;

public sealed record IntegrationOAuthStatus(
    string Provider,
    bool Available,
    bool Connected,
    DateTimeOffset? ExpiresAtUtc,
    string? AuthorizationRevision = null);

public sealed record IntegrationOAuthAuthorization(string AuthorizationUrl);

public sealed record IntegrationOAuthAccess(
    IReadOnlyDictionary<string, string> Headers,
    DateTimeOffset? ExpiresAtUtc,
    string? AuthorizationRevision = null);

internal sealed record IntegrationOAuthTicket(
    string Subject,
    string Provider,
    string Nonce,
    // Carried in the encrypted ticket as well as in the pending record so the
    // browser can still be sent home when the pending record has expired but
    // the ticket itself is intact.
    string ReturnUri,
    bool Popup = false);

internal sealed record PendingIntegrationOAuth(
    string Provider,
    string ReturnUri,
    string CallbackUri,
    string? CodeVerifier,
    string? ClientId,
    string? ClientSecret,
    bool Popup = false);

internal sealed record IntegrationOAuthToken(
    string AccessToken,
    string? RefreshToken,
    string? TokenType,
    DateTimeOffset? ExpiresAtUtc,
    string? Scope,
    string? ClientId,
    string? ClientSecret,
    string? AuthorizationRevision = null);
