using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Sufficit.Identity.Management.Mcp;

/// <summary>
/// MCP transport sessions. A session id is the subject that initialized it, protected with
/// the Data Protection keys every node shares (persisted in the database), so any node
/// validates it and it survives restarts; a stolen <c>mcp-session-id</c> still cannot be
/// replayed with another user's bearer token. The bearer token authenticates every request;
/// the session only binds the transport to that subject.
/// </summary>
/// <remarks>
/// Sessions used to live in one node's memory with a 30-minute idle expiry: behind the
/// load balancer a request reaching another node, a pause in the conversation or a deploy
/// answered "Session not found", which clients reported as stale credentials.
/// </remarks>
public sealed class McpSessionManager
{
    /// <summary>Upper bound for one transport session; clients re-initialize after it.</summary>
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(24);

    private readonly ITimeLimitedDataProtector protector;

    public McpSessionManager(IDataProtectionProvider provider) =>
        protector = provider.CreateProtector("Sufficit.Identity.Mcp.Session.v1").ToTimeLimitedDataProtector();

    public string Create(string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        // A random part keeps two sessions of the same subject distinct.
        var payload = $"{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}:{subject}";
        return protector.Protect(payload, SessionLifetime);
    }

    /// <summary>Reuses a requested session that belongs to the same subject; otherwise a fresh one.</summary>
    public string Initialize(string? requestedId, string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        return Validate(requestedId, subject) ? requestedId!.Trim() : Create(subject);
    }

    public bool Validate(string? id, string subject)
    {
        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(subject)) return false;
        try
        {
            var payload = protector.Unprotect(id.Trim());
            var separator = payload.IndexOf(':');
            return separator > 0 && string.Equals(payload[(separator + 1)..], subject, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            return false; // expired, tampered or from another key ring
        }
    }
}
