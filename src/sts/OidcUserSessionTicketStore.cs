using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using System.Security.Cryptography;

namespace Sufficit.Identity.STS;

/// <summary>
/// Server-side <see cref="ITicketStore"/> for the ASP.NET Core Identity
/// application cookie (<c>IdentityConstants.ApplicationScheme</c>), wired via
/// <c>CookieAuthenticationOptions.SessionStore</c>. The browser receives only
/// the opaque OIDC <c>sid</c> as its session cookie value; the full
/// <see cref="AuthenticationTicket"/> lives in the <see cref="OidcUserSession"/>
/// table, DataProtection-protected and serialized exactly as
/// <see cref="PasskeyAuthenticationTicketStore"/> does for the 2FA cookie.
/// </summary>
/// <remarks>
/// <para>
/// The store key <strong>is the <c>sid</c></strong> already minted by
/// <see cref="OidcSessionClaimsPrincipalFactory"/> and carried in the ticket's
/// <see cref="OidcSessionClaimsPrincipalFactory.SessionIdClaimType"/> claim.
/// Using the <c>sid</c> as the key keeps every existing behavior intact: the
/// <c>sid</c> stays byte-identical across a refresh-token grant, the logout
/// fan-out continues to read the same value off the cookie, and the ID-token
/// <c>sid</c> matches the cookie value. The store simply gives that value a
/// durable, enumerable, revocable row.
/// </para>
/// <para>
/// <b>Lifecycle.</b> <see cref="StoreAsync"/> runs on sign-in (insert),
/// <see cref="RenewAsync"/> on <c>RefreshSignInAsync</c> / sliding (upsert by
/// sid), <see cref="RetrieveAsync"/> on every cookie-authenticated request
/// (read + lazy expiry sweep + activity touch), and <see cref="RemoveAsync"/>
/// on explicit per-session revoke (delete by sid).
/// </para>
/// <para>
/// <b>Singleton.</b> <c>CookieAuthenticationOptions.SessionStore</c> is
/// resolved from the root service provider (it is effectively singleton), so
/// this store MUST be singleton. It therefore depends on
/// <see cref="IDbContextFactory{TContext}"/> (singleton) rather than the
/// request-scoped <see cref="AppDbContext"/>, creating a short-lived context
/// per operation. <see cref="IHttpContextAccessor"/> is singleton-safe.
/// Multi-replica safe out of the box: persistence is the shared database, not
/// an in-memory cache (unlike the DPoP/CIBA stores that need Redis) — no extra
/// distributed-cache dependency required.
/// </para>
/// </remarks>
internal sealed class OidcUserSessionTicketStore(
    IDbContextFactory<AppDbContext> databaseFactory,
    IDataProtectionProvider dataProtectionProvider,
    IDistributedCache cache,
    IHttpContextAccessor httpContextAccessor,
    SufficitIdentityOptions options,
    TimeProvider timeProvider,
    ILogger<OidcUserSessionTicketStore> logger) : ITicketStore, ISessionManagement
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(
        "Sufficit.Identity.OidcUserSessionTicketStore.v1");
    private readonly TimeSpan _cacheLifetime = TimeSpan.FromSeconds(
        Math.Clamp(options.UserSessions.CacheLifetimeSeconds, 5, 300));
    private readonly TimeSpan _cacheOperationTimeout = TimeSpan.FromMilliseconds(
        Math.Clamp(options.UserSessions.CacheOperationTimeoutMilliseconds, 50, 2000));
    private readonly TimeSpan _activityUpdateInterval = TimeSpan.FromSeconds(
        Math.Clamp(options.UserSessions.ActivityUpdateIntervalSeconds, 60, 3600));

    // -----------------------------------------------------------------------
    // ITicketStore
    // -----------------------------------------------------------------------

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var sid = ResolveSessionId(ticket);
        await using var database = await databaseFactory.CreateDbContextAsync(CancellationToken.None);
        await StoreAsync(database, sid, ticket, insertIfMissing: true, CancellationToken.None);
        await TrySetCacheAsync(sid, ticket);
        return sid;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(ticket);
        // The cookie handler passes back the key it received from StoreAsync
        // (= the sid). An upsert keeps the row stable across RefreshSignInAsync
        // and sliding renewal while refreshing the protected ticket + metadata.
        await using var database = await databaseFactory.CreateDbContextAsync(CancellationToken.None);
        await StoreAsync(database, key, ticket, insertIfMissing: false, CancellationToken.None);
        await TrySetCacheAsync(key, ticket);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var cached = await TryGetCacheAsync(key);
        if (cached is not null)
        {
            return cached;
        }

        await using var database = await databaseFactory.CreateDbContextAsync(CancellationToken.None);
        var session = await database.OidcUserSessions
            .AsTracking()
            .SingleOrDefaultAsync(s => s.SessionId == key, CancellationToken.None);
        if (session is null)
        {
            return null;
        }

        // Lazy expiry sweep: a session past its absolute expiration is treated
        // as absent and removed, so the caller sees an unauthenticated request.
        var now = timeProvider.GetUtcNow();
        if (session.ExpiresUtc is { } expires && expires <= now)
        {
            database.OidcUserSessions.Remove(session);
            await database.SaveChangesAsync(CancellationToken.None);
            return null;
        }

        AuthenticationTicket? ticket;
        try
        {
            ticket = TicketSerializer.Default.Deserialize(
                _protector.Unprotect(session.ProtectedTicket));
        }
        catch (Exception exception) when (exception is CryptographicException
            or InvalidOperationException
            or FormatException)
        {
            logger.LogWarning(exception,
                "A user-session ticket (sid {SessionId}) could not be restored and was discarded.",
                key);
            database.OidcUserSessions.Remove(session);
            await database.SaveChangesAsync(CancellationToken.None);
            return null;
        }

        if (ticket is null)
        {
            return null;
        }

        // Touch last-activity cheaply (only when a minute has elapsed, to avoid
        // a write on every single request). best-effort: never let this throw
        // surface as an auth failure.
        if (now - session.LastActivityUtc >= _activityUpdateInterval)
        {
            session.LastActivityUtc = now.UtcDateTime;
            try
            {
                await database.SaveChangesAsync(CancellationToken.None);
            }
            catch (DbUpdateConcurrencyException)
            {
                // Another request updated the same row concurrently; harmless.
            }
        }

        await TrySetCacheAsync(key, ticket);
        return ticket;
    }

    public async Task RemoveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        await using var database = await databaseFactory.CreateDbContextAsync(CancellationToken.None);
        await database.OidcUserSessions
            .Where(s => s.SessionId == key)
            .ExecuteDeleteAsync(CancellationToken.None);
        await TryRemoveCacheAsync(key);
    }

    // -----------------------------------------------------------------------
    // ISessionManagement
    // -----------------------------------------------------------------------

    public async Task<IReadOnlyList<OidcUserSessionSummary>> ListBySubjectAsync(
        string subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var currentSid = httpContextAccessor.HttpContext?.User
            .FindFirst(OidcSessionClaimsPrincipalFactory.SessionIdClaimType)?.Value;

        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var rows = await database.OidcUserSessions
            .AsNoTracking()
            .Where(s => s.Subject == subject)
            .OrderByDescending(s => s.LastActivityUtc)
            .Select(s => new OidcUserSessionSummary(
                s.SessionId,
                s.Subject,
                s.CreatedAtUtc,
                s.LastActivityUtc,
                s.ExpiresUtc,
                s.RemoteIpAddress,
                s.UserAgent,
                IsCurrent: s.SessionId == currentSid))
            .ToListAsync(cancellationToken);

        return rows;
    }

    async Task ISessionManagement.RevokeAsync(string sessionId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        await database.OidcUserSessions
            .Where(s => s.SessionId == sessionId)
            .ExecuteDeleteAsync(cancellationToken);
        await TryRemoveCacheAsync(sessionId, cancellationToken);
    }

    public async Task<int> RevokeAllBySubjectAsync(
        string subject,
        string? exceptSessionId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var sessionIds = await database.OidcUserSessions
            .Where(s => s.Subject == subject && s.SessionId != exceptSessionId)
            .Select(s => s.SessionId)
            .ToListAsync(cancellationToken);
        var removed = await database.OidcUserSessions
            .Where(s => s.Subject == subject && s.SessionId != exceptSessionId)
            .ExecuteDeleteAsync(cancellationToken);
        foreach (var sessionId in sessionIds)
        {
            await TryRemoveCacheAsync(sessionId, cancellationToken);
        }

        return removed;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// The sid that identifies this session. Read from the ticket's
    /// <c>sid</c> claim (placed there by <c>OidcSessionClaimsPrincipalFactory</c>
    /// before the cookie handler calls <see cref="StoreAsync"/>); minted only
    /// as a defensive fallback if the claim is somehow absent.
    /// </summary>
    private static string ResolveSessionId(AuthenticationTicket ticket)
    {
        var existing = ticket.Principal.FindFirst(
            OidcSessionClaimsPrincipalFactory.SessionIdClaimType)?.Value;
        if (!string.IsNullOrWhiteSpace(existing))
        {
            return existing;
        }
        return WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    }

    private async Task StoreAsync(
        AppDbContext database,
        string sid,
        AuthenticationTicket ticket,
        bool insertIfMissing,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var protectedTicket = _protector.Protect(
            TicketSerializer.Default.Serialize(ticket));

        var subject = ticket.Principal.FindFirst(
            System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? ticket.Principal.FindFirst("sub")?.Value
            ?? string.Empty;

        var existing = await database.OidcUserSessions
            .AsTracking()
            .SingleOrDefaultAsync(s => s.SessionId == sid, cancellationToken);

        if (existing is null)
        {
            database.OidcUserSessions.Add(new OidcUserSession
            {
                SessionId = sid,
                Subject = subject,
                RemoteIpAddress = ResolveRemoteIp(),
                UserAgent = ResolveUserAgent(),
                CreatedAtUtc = now,
                LastActivityUtc = now,
                ExpiresUtc = ResolveExpiration(ticket),
                ProtectedTicket = protectedTicket,
            });
        }
        else
        {
            existing.Subject = subject;
            existing.LastActivityUtc = now;
            existing.ExpiresUtc = ResolveExpiration(ticket);
            existing.ProtectedTicket = protectedTicket;
            // Device metadata is captured at creation only — refreshing it on
            // every sliding renewal would mask the originating device.
        }

        await database.SaveChangesAsync(cancellationToken);
    }

    private DateTime? ResolveExpiration(AuthenticationTicket ticket)
    {
        var expires = ticket.Properties.ExpiresUtc;
        return expires is { } e ? e.UtcDateTime : null;
    }

    private string? ResolveRemoteIp() =>
        httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();

    private string? ResolveUserAgent()
    {
        var ua = httpContextAccessor.HttpContext?.Request.Headers.UserAgent.ToString();
        return string.IsNullOrWhiteSpace(ua) ? null : ua;
    }

    private async Task<AuthenticationTicket?> TryGetCacheAsync(string key)
    {
        using var timeout = new CancellationTokenSource(_cacheOperationTimeout);
        try
        {
            var protectedTicket = await cache.GetAsync(
                CacheKey(key),
                timeout.Token);
            if (protectedTicket is null)
            {
                return null;
            }

            var ticket = TicketSerializer.Default.Deserialize(
                _protector.Unprotect(protectedTicket));
            if (ticket?.Properties.ExpiresUtc is { } expires
                && expires <= timeProvider.GetUtcNow())
            {
                await TryRemoveCacheAsync(key);
                return null;
            }

            return ticket;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            logger.LogWarning(
                "Shared user-session cache read exceeded {TimeoutMilliseconds} ms; falling back to the database.",
                _cacheOperationTimeout.TotalMilliseconds);
            return null;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(
                exception,
                "Shared user-session cache read failed; falling back to the database.");
            return null;
        }
    }

    private async Task TrySetCacheAsync(
        string key,
        AuthenticationTicket ticket)
    {
        using var timeout = new CancellationTokenSource(_cacheOperationTimeout);
        try
        {
            var lifetime = _cacheLifetime;
            if (ticket.Properties.ExpiresUtc is { } expires)
            {
                lifetime = expires - timeProvider.GetUtcNow() < lifetime
                    ? expires - timeProvider.GetUtcNow()
                    : lifetime;
            }
            if (lifetime <= TimeSpan.Zero)
            {
                return;
            }

            await cache.SetAsync(
                CacheKey(key),
                _protector.Protect(
                    TicketSerializer.Default.Serialize(ticket)),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = lifetime,
                },
                timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            logger.LogWarning(
                "Shared user-session cache write exceeded {TimeoutMilliseconds} ms; database persistence remains authoritative.",
                _cacheOperationTimeout.TotalMilliseconds);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(
                exception,
                "Shared user-session cache write failed; database persistence remains authoritative.");
        }
    }

    private async Task TryRemoveCacheAsync(
        string key,
        CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_cacheOperationTimeout);
        try
        {
            await cache.RemoveAsync(CacheKey(key), timeout.Token);
        }
        catch (OperationCanceledException) when (
            !cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
        {
            logger.LogWarning(
                "Shared user-session cache invalidation exceeded {TimeoutMilliseconds} ms; the entry remains bounded by its short TTL.",
                _cacheOperationTimeout.TotalMilliseconds);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(
                exception,
                "Shared user-session cache invalidation failed; the entry remains bounded by its short TTL.");
        }
    }

    private static string CacheKey(string sessionId) =>
        "identity:oidc-session:v1:" + sessionId;
}
