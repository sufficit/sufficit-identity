using System.Collections.Concurrent;

namespace Sufficit.Identity.Management.Mcp;

/// <summary>
/// Short-lived MCP transport sessions. A session is bound to the authenticated
/// subject that initialized it, so a stolen <c>mcp-session-id</c> cannot be
/// replayed with another user's bearer token.
/// </summary>
public sealed class McpSessionManager : IDisposable
{
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, Session> sessions =
        new(StringComparer.Ordinal);
    private readonly Timer cleanupTimer;

    public McpSessionManager()
    {
        cleanupTimer = new Timer(
            _ => RemoveExpired(),
            state: null,
            dueTime: CleanupInterval,
            period: CleanupInterval);
    }

    public string Create(string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var id = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow;
        sessions[id] = new Session(subject, now, initialized: true);
        return id;
    }

    /// <summary>
    /// Reuses a requested session only when it already belongs to the same
    /// subject. Unknown or cross-subject ids result in a fresh session.
    /// </summary>
    public string Initialize(string? requestedId, string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        if (!string.IsNullOrWhiteSpace(requestedId)
            && sessions.TryGetValue(requestedId.Trim(), out var existing)
            && string.Equals(existing.Subject, subject, StringComparison.Ordinal)
            && Touch(existing))
        {
            existing.Initialized = true;
            return requestedId.Trim();
        }

        return Create(subject);
    }

    public bool Validate(string? id, string subject)
    {
        if (string.IsNullOrWhiteSpace(id)
            || string.IsNullOrWhiteSpace(subject)
            || !sessions.TryGetValue(id.Trim(), out var session)
            || !session.Initialized
            || !string.Equals(session.Subject, subject, StringComparison.Ordinal))
        {
            return false;
        }

        return Touch(session);
    }

    public void Dispose() => cleanupTimer.Dispose();

    private static bool Touch(Session session)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - session.LastAccessedAtUtc > SessionLifetime)
            return false;

        session.LastAccessedAtUtc = now;
        return true;
    }

    private void RemoveExpired()
    {
        var cutoff = DateTimeOffset.UtcNow - SessionLifetime;
        foreach (var pair in sessions)
        {
            if (pair.Value.LastAccessedAtUtc < cutoff)
                sessions.TryRemove(pair.Key, out _);
        }
    }

    private sealed class Session(
        string subject,
        DateTimeOffset lastAccessedAtUtc,
        bool initialized)
    {
        public string Subject { get; } = subject;
        public DateTimeOffset LastAccessedAtUtc { get; set; } = lastAccessedAtUtc;
        public bool Initialized { get; set; } = initialized;
    }
}
