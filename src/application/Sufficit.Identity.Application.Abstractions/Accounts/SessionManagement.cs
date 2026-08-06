namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Read/revoke surface over the server-side browser-session store. Implemented
/// by the STS's <c>ITicketStore</c> backing the ASP.NET Core Identity
/// application cookie, so the store remains the single source of truth for
/// browser sessions. Lives in the application abstractions layer so both the
/// STS (implementation) and the management module (admin revocation) can depend
/// on it without a project cycle.
/// </summary>
public interface ISessionManagement
{
    /// <summary>
    /// Lists every active browser session for a subject. Does NOT include the
    /// protected ticket material. <see cref="OidcUserSessionSummary.IsCurrent"/>
    /// flags the session matching the caller's own cookie, if any.
    /// </summary>
    Task<IReadOnlyList<OidcUserSessionSummary>> ListBySubjectAsync(
        string subject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single browser session by its <c>sid</c>. Does NOT bump the
    /// security stamp — only that one session is invalidated.
    /// </summary>
    Task RevokeAsync(string sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every browser session for a subject, optionally sparing the
    /// caller's own session (<paramref name="exceptSessionId"/>). Returns the
    /// number of sessions removed. Does NOT bump the security stamp.
    /// </summary>
    Task<int> RevokeAllBySubjectAsync(
        string subject,
        string? exceptSessionId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// A non-sensitive projection of a browser session for enumeration/UI. Never
/// carries the protected ticket.
/// </summary>
public sealed record OidcUserSessionSummary(
    string SessionId,
    string Subject,
    DateTime CreatedAtUtc,
    DateTime LastActivityUtc,
    DateTime? ExpiresUtc,
    string? RemoteIpAddress,
    string? UserAgent,
    bool IsCurrent);
