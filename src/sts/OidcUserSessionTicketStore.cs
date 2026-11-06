using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Accounts;
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
/// <see cref="RenewAsync"/> on <c>RefreshSignInAsync</c> / sliding (conditional update by
/// sid and subject), <see cref="RetrieveAsync"/> on every cookie-authenticated request
/// (cache read, or database read with lazy expiry/activity touch on a miss),
/// and <see cref="RemoveAsync"/>
/// on explicit per-session revoke (delete by sid).
/// </para>
/// <para>
/// <b>Singleton.</b> <c>CookieAuthenticationOptions.SessionStore</c> is
/// resolved from the root service provider (it is effectively singleton), so
/// this store MUST be singleton. Its repository owns short-lived database
/// contexts per operation. <see cref="IHttpContextAccessor"/> is singleton-safe.
/// Persistence is authoritative in the shared database. The distributed ticket
/// cache is optional acceleration; invalidation failure leaves staleness bounded
/// by its configured TTL. Request cancellation propagates to both stores.
/// </para>
/// </remarks>
internal sealed class OidcUserSessionTicketStore(
    IOidcUserSessionRepository repository,
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

    public Task<string> StoreAsync(AuthenticationTicket ticket) =>
        StoreAsync(ticket, httpContextAccessor.HttpContext?.RequestAborted ?? default);

    public Task RenewAsync(string key, AuthenticationTicket ticket) =>
        RenewAsync(key, ticket, httpContextAccessor.HttpContext?.RequestAborted ?? default);

    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        RetrieveAsync(key, httpContextAccessor.HttpContext?.RequestAborted ?? default);

    public Task RemoveAsync(string key) =>
        RemoveAsync(key, httpContextAccessor.HttpContext?.RequestAborted ?? default);

    public async Task<string> StoreAsync(AuthenticationTicket ticket, HttpContext context, CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, cancellationToken);
        return await StoreAsync(ticket, linked.Token);
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket, HttpContext context, CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, cancellationToken);
        await RenewAsync(key, ticket, linked.Token);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key, HttpContext context, CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, cancellationToken);
        return await RetrieveAsync(key, linked.Token);
    }

    public async Task RemoveAsync(string key, HttpContext context, CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, cancellationToken);
        await RemoveAsync(key, linked.Token);
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        cancellationToken.ThrowIfCancellationRequested();
        var cacheDeadline = timeProvider.GetUtcNow() + _cacheLifetime;
        var sid = ResolveSessionId(ticket);
        await repository.UpsertAsync(CreateSession(sid, ticket), cancellationToken);
        await TrySetCacheAsync(sid, ticket, cacheDeadline, cancellationToken);
        return sid;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(ticket);
        cancellationToken.ThrowIfCancellationRequested();
        var cacheDeadline = timeProvider.GetUtcNow() + _cacheLifetime;
        // Renewal never creates a session: a revoked row must remain absent.
        if (await repository.RenewAsync(CreateSession(key, ticket), cancellationToken))
        {
            await TrySetCacheAsync(key, ticket, cacheDeadline, cancellationToken);
        }
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        cancellationToken.ThrowIfCancellationRequested();
        var cached = await TryGetCacheAsync(key, cancellationToken);
        if (cached is not null)
        {
            return cached;
        }

        var cacheDeadline = timeProvider.GetUtcNow() + _cacheLifetime;
        var session = await repository.FindAsync(key, cancellationToken);
        if (session is null)
        {
            return null;
        }

        // Lazy expiry sweep: a session past its absolute expiration is treated
        // as absent and removed, so the caller sees an unauthenticated request.
        var now = timeProvider.GetUtcNow();
        if (session.ExpiresUtc is { } expires && expires <= now.UtcDateTime)
        {
            await repository.DeleteSnapshotAsync(session, cancellationToken);
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
            await repository.DeleteSnapshotAsync(session, cancellationToken);
            return null;
        }

        if (ticket is null)
        {
            return null;
        }

        // Touch activity on database reads only after the configured interval.
        // Ignore concurrent-update conflicts; cancellation and other storage
        // failures propagate to the caller.
        if (now - session.LastActivityUtc >= _activityUpdateInterval)
        {
            await repository.TouchAsync(session, now.UtcDateTime, cancellationToken);
        }

        await TrySetCacheAsync(key, ticket, cacheDeadline, cancellationToken);
        return ticket;
    }

    public async Task RemoveAsync(string key, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        cancellationToken.ThrowIfCancellationRequested();
        await repository.DeleteAsync(key, cancellationToken);
        await TryRemoveCacheAsync(key, cancellationToken);
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

        return await repository.ListBySubjectAsync(subject, currentSid, cancellationToken);
    }

    async Task ISessionManagement.RevokeAsync(string sessionId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        await repository.DeleteAsync(sessionId, cancellationToken);
        await TryRemoveCacheAsync(sessionId, cancellationToken);
    }

    public async Task<int> RevokeAllBySubjectAsync(
        string subject,
        string? exceptSessionId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var result = await repository.DeleteBySubjectAsync(subject, exceptSessionId, cancellationToken);
        foreach (var sessionId in result.SessionIds)
        {
            await TryRemoveCacheAsync(sessionId, cancellationToken);
        }

        return result.Removed;
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

    private OidcUserSession CreateSession(string sid, AuthenticationTicket ticket)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        return new OidcUserSession
        {
            SessionId = sid,
            Subject = ticket.Principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? ticket.Principal.FindFirst("sub")?.Value ?? string.Empty,
            RemoteIpAddress = ResolveRemoteIp(),
            UserAgent = ResolveUserAgent(),
            CreatedAtUtc = now,
            LastActivityUtc = now,
            ExpiresUtc = ResolveExpiration(ticket),
            ProtectedTicket = _protector.Protect(TicketSerializer.Default.Serialize(ticket)),
        };
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

    private async Task<AuthenticationTicket?> TryGetCacheAsync(string key, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_cacheOperationTimeout);
        cancellationToken.ThrowIfCancellationRequested();
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
                await TryRemoveCacheAsync(key, cancellationToken);
                return null;
            }

            return ticket;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
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
        AuthenticationTicket ticket,
        DateTimeOffset cacheDeadline,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_cacheOperationTimeout);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            // Anchor the cache window before the database operation. A delayed
            // write after revocation must not start a fresh relative TTL.
            if (ticket.Properties.ExpiresUtc is { } expires && expires < cacheDeadline)
            {
                cacheDeadline = expires;
            }
            if (cacheDeadline <= timeProvider.GetUtcNow())
            {
                return;
            }

            await cache.SetAsync(
                CacheKey(key),
                _protector.Protect(
                    TicketSerializer.Default.Serialize(ticket)),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpiration = cacheDeadline,
                },
                timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && timeout.IsCancellationRequested)
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
