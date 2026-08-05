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
internal sealed class PasskeyAuthenticationTicketStore(
    IDistributedCache cache,
    IDataProtectionProvider dataProtectionProvider,
    ILogger<PasskeyAuthenticationTicketStore> logger) : ITicketStore
{
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(10);
    private const string CacheKeyPrefix = "identity:passkey-ceremony:";
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
        var protectedTicket = await cache.GetAsync(
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
            await cache.RemoveAsync(CacheKey(key), CancellationToken.None);
            return null;
        }
    }

    public Task RemoveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        return cache.RemoveAsync(CacheKey(key), CancellationToken.None);
    }

    private async Task StoreAsync(
        string key,
        AuthenticationTicket ticket,
        CancellationToken cancellationToken)
    {
        var serializedTicket = TicketSerializer.Default.Serialize(ticket);
        var cacheOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = ResolveExpiration(ticket),
        };
        await cache.SetAsync(
            CacheKey(key),
            _protector.Protect(serializedTicket),
            cacheOptions,
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
