using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS;

/// <summary>
/// Keeps the short-lived ASP.NET Identity WebAuthn ceremony ticket on the
/// server. The browser receives only an opaque random key instead of the full
/// protected challenge, avoiding oversized Set-Cookie response headers.
/// </summary>
/// <remarks>
/// The ticket is held in a durable store as well as the distributed cache: the
/// cache defaults to process-local memory, so with more than one replica a
/// ceremony started on one host could not be completed on another and the user
/// simply saw the passkey sign-in fail (eval 2026-08-30, F-4). The payload is
/// data-protected either way, so the shared table never holds a readable
/// ticket.
/// </remarks>
internal sealed class PasskeyAuthenticationTicketStore(
    IDistributedCache cache,
    IDataProtectionProvider dataProtectionProvider,
    ILogger<PasskeyAuthenticationTicketStore> logger,
    IProtocolStateStore? state = null) : ITicketStore
{
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(10);
    private const string CacheKeyPrefix = "identity:passkey-ceremony:";
    private const string StatePurpose = "passkey-ceremony";
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(
        "Sufficit.Identity.PasskeyAuthenticationTicketStore.v1");

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var key = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        await StoreAsync(key, ticket, CancellationToken.None);
        return key;
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(ticket);
        return StoreAsync(key, ticket, CancellationToken.None);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        // Durable store first; the cache still answers for a ceremony started
        // by a not-yet-upgraded replica during a rolling deployment.
        var protectedTicket = state is null
            ? null
            : await state.GetAsync(StatePurpose, key, CancellationToken.None);
        protectedTicket ??= await cache.GetAsync(
            CacheKey(key),
            CancellationToken.None);
        if (protectedTicket is null)
        {
            return null;
        }

        try
        {
            return TicketSerializer.Default.Deserialize(
                _protector.Unprotect(protectedTicket));
        }
        catch (Exception exception) when (exception is CryptographicException
            or InvalidOperationException
            or FormatException)
        {
            logger.LogWarning(
                exception,
                "A passkey ceremony ticket could not be restored and was discarded.");
            await RemoveEverywhereAsync(key);
            return null;
        }
    }

    public Task RemoveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        return RemoveEverywhereAsync(key);
    }

    // Both copies go, or the ceremony would still be resumable from whichever
    // backend was left holding it.
    private async Task RemoveEverywhereAsync(string key)
    {
        if (state is not null)
        {
            await state.RemoveAsync(StatePurpose, key, CancellationToken.None);
        }

        await cache.RemoveAsync(CacheKey(key), CancellationToken.None);
    }

    private async Task StoreAsync(
        string key,
        AuthenticationTicket ticket,
        CancellationToken cancellationToken)
    {
        var serializedTicket = TicketSerializer.Default.Serialize(ticket);
        var protectedTicket = _protector.Protect(serializedTicket);
        var expiresAt = ResolveExpiration(ticket);

        if (state is not null)
        {
            var lifetime = expiresAt - DateTimeOffset.UtcNow;
            if (lifetime > TimeSpan.Zero)
            {
                await state.SetAsync(
                    StatePurpose,
                    key,
                    protectedTicket,
                    lifetime,
                    cancellationToken);
            }
        }

        await cache.SetAsync(
            CacheKey(key),
            protectedTicket,
            new DistributedCacheEntryOptions { AbsoluteExpiration = expiresAt },
            cancellationToken);
    }

    private static DateTimeOffset ResolveExpiration(AuthenticationTicket ticket)
    {
        var now = DateTimeOffset.UtcNow;
        return ticket.Properties.ExpiresUtc is { } expiration && expiration > now
            ? expiration
            : now.Add(DefaultLifetime);
    }

    private static string CacheKey(string key) => $"{CacheKeyPrefix}{key}";
}
