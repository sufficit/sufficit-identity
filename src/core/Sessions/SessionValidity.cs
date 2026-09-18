namespace Sufficit.Identity.Core.Sessions;

/// <summary>
/// Best-effort notification that a user's sessions must be revalidated. The
/// database stays authoritative: a node that hears nothing simply keeps
/// reading the security stamp, exactly as it did before this existed.
/// </summary>
/// <remarks>
/// Same shape as <c>ITrustedProxyChangePublisher</c>, and for the same reason:
/// the core declares what it needs, the host decides whether a transport is
/// configured at all.
/// </remarks>
public interface IUserSecurityChangePublisher
{
    bool Enabled { get; }

    bool Connected { get; }

    Task<bool> PublishAsync(string userId, CancellationToken cancellationToken);
}

/// <summary>
/// Remembers, per user, the moment their sessions last had to be revalidated.
/// </summary>
/// <remarks>
/// <para>
/// A cookie-authenticated request reads the user's security stamp to find out
/// whether the session is still valid. That read is one primary-key lookup,
/// but it happens on every single request of every signed-in user. This cache
/// lets a request skip it while two things hold: the ticket was verified after
/// the last known invalidation of that user, and the entry is younger than the
/// configured window.
/// </para>
/// <para>
/// Invalidation arrives from this node (a password change, a revoked session)
/// and from the other nodes through <see cref="IUserSecurityChangePublisher"/>.
/// The window is what bounds the damage when a notification is lost: after it
/// elapses the stamp is read again.
/// </para>
/// </remarks>
public interface ISessionValidityCache
{
    /// <summary>
    /// Whether a ticket verified at <paramref name="verifiedAt"/> can be
    /// trusted without reading the user row again.
    /// </summary>
    bool IsRevalidationNeeded(string userId, DateTimeOffset verifiedAt);

    /// <summary>Records that the user row was just read and accepted.</summary>
    void MarkVerified(string userId);

    /// <summary>
    /// Marks every session of the user as needing a fresh read. Called on this
    /// node when credentials or sessions change, and when another node says so.
    /// </summary>
    void Invalidate(string userId);
}
