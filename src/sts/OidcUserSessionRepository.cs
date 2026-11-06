using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Durable browser-session persistence. Tickets remain opaque protected bytes;
/// no HttpContext, cryptography or cache policy belongs in this boundary.
/// Every operation owns a short-lived context and propagates cancellation.
/// </summary>
internal interface IOidcUserSessionRepository
{
    Task<bool> RenewAsync(OidcUserSession session, CancellationToken cancellationToken);
    Task UpsertAsync(OidcUserSession session, CancellationToken cancellationToken);
    Task<OidcUserSession?> FindAsync(string sessionId, CancellationToken cancellationToken);
    Task DeleteSnapshotAsync(OidcUserSession session, CancellationToken cancellationToken);
    Task TouchAsync(OidcUserSession session, DateTime now, CancellationToken cancellationToken);
    Task DeleteAsync(string sessionId, CancellationToken cancellationToken);
    Task<IReadOnlyList<OidcUserSessionSummary>> ListBySubjectAsync(string subject, string? currentSid, CancellationToken cancellationToken);
    Task<SessionDeletionResult> DeleteBySubjectAsync(string subject, string? exceptSessionId, CancellationToken cancellationToken);
}

internal sealed record SessionDeletionResult(int Removed, IReadOnlyList<string> SessionIds);

internal sealed class OidcUserSessionRepository(IDbContextFactory<AppDbContext> databaseFactory)
    : IOidcUserSessionRepository
{
    public async Task UpsertAsync(OidcUserSession session, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var existing = await database.OidcUserSessions.AsTracking()
            .SingleOrDefaultAsync(s => s.SessionId == session.SessionId, cancellationToken);
        if (existing is null)
        {
            database.OidcUserSessions.Add(session);
        }
        else
        {
            existing.Subject = session.Subject;
            existing.LastActivityUtc = session.LastActivityUtc;
            existing.ExpiresUtc = session.ExpiresUtc;
            existing.ProtectedTicket = session.ProtectedTicket;
            // Renewing a ticket preserves the original creation/device metadata.
        }
        await database.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> RenewAsync(OidcUserSession session, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        // A single conditional update cannot insert a row removed by revocation
        // or transfer an existing session to a different subject.
        var updated = await database.OidcUserSessions
            .Where(s => s.SessionId == session.SessionId && s.Subject == session.Subject)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(s => s.LastActivityUtc, session.LastActivityUtc)
                .SetProperty(s => s.ExpiresUtc, session.ExpiresUtc)
                .SetProperty(s => s.ProtectedTicket, session.ProtectedTicket), cancellationToken);
        return updated != 0;
    }

    public async Task<OidcUserSession?> FindAsync(string sessionId, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.OidcUserSessions.AsNoTracking()
            .SingleOrDefaultAsync(s => s.SessionId == sessionId, cancellationToken);
    }

    public async Task DeleteSnapshotAsync(OidcUserSession session, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        database.OidcUserSessions.Remove(session);
        await database.SaveChangesAsync(cancellationToken);
    }

    public async Task TouchAsync(OidcUserSession session, DateTime now, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        database.OidcUserSessions.Attach(session);
        session.LastActivityUtc = now;
        try
        {
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            // A concurrent removal must not recreate the session.
        }
    }

    public async Task DeleteAsync(string sessionId, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        await database.OidcUserSessions.Where(s => s.SessionId == sessionId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<OidcUserSessionSummary>> ListBySubjectAsync(
        string subject, string? currentSid, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.OidcUserSessions.AsNoTracking()
            .Where(s => s.Subject == subject)
            .OrderByDescending(s => s.LastActivityUtc)
            .Select(s => new OidcUserSessionSummary(
                s.SessionId, s.Subject, s.CreatedAtUtc, s.LastActivityUtc, s.ExpiresUtc,
                s.RemoteIpAddress, s.UserAgent, s.SessionId == currentSid))
            .ToListAsync(cancellationToken);
    }

    public async Task<SessionDeletionResult> DeleteBySubjectAsync(
        string subject, string? exceptSessionId, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var sessionIds = await database.OidcUserSessions
            .Where(s => s.Subject == subject && s.SessionId != exceptSessionId)
            .Select(s => s.SessionId).ToListAsync(cancellationToken);
        var removed = await database.OidcUserSessions
            .Where(s => s.Subject == subject && s.SessionId != exceptSessionId)
            .ExecuteDeleteAsync(cancellationToken);
        return new SessionDeletionResult(removed, sessionIds);
    }
}
