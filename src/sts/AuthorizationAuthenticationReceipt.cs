using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.WebUtilities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Evidence that a credential ceremony completed for this exact authorization
/// request. max_age=0 means new authentication, not an impossible zero-duration
/// cookie. Never issued by an authorize GET, a refresh, or the continuation page.
/// </summary>
internal static class AuthorizationAuthenticationReceipt
{
    internal const string CookieName = "__Host-Identity.AuthenticationReceipt";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    internal static void Issue(HttpContext context, string returnUrl)
    {
        if (!returnUrl.StartsWith("/connect/authorize?", StringComparison.Ordinal)
            || context.User.Identity?.IsAuthenticated != true)
            return;

        var sid = context.User.FindFirst("sid")?.Value;
        var authTime = context.User.FindFirst("auth_time")?.Value;
        var evidence = context.RequestServices.GetService<IAuthenticationContextAccessor>()?.Current;
        if (string.IsNullOrEmpty(sid) || string.IsNullOrEmpty(authTime) || evidence is null
            || authTime != evidence.AuthenticatedAt.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))
            return;

        var expires = Clock(context).GetUtcNow().Add(Lifetime);
        var receipt = new Receipt(Hash(returnUrl), sid, authTime, expires);
        context.Response.Cookies.Append(CookieName,
            Protector(context).Protect(JsonSerializer.Serialize(receipt)), Options(expires));
    }

    internal static bool IsValid(HttpContext context, string authorizationUrl)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName, out var value))
            return false;
        try
        {
            var receipt = JsonSerializer.Deserialize<Receipt>(Protector(context).Unprotect(value));
            var now = Clock(context).GetUtcNow();
            if (receipt is null || receipt.Expires <= now || receipt.Expires > now.Add(Lifetime)
                || context.User.Identity?.IsAuthenticated != true
                || receipt.RequestHash != Hash(authorizationUrl)
                || receipt.SessionId != context.User.FindFirst("sid")?.Value
                || receipt.AuthTime != context.User.FindFirst("auth_time")?.Value)
                return false;

            return true;
        }
        catch (Exception error) when (error is CryptographicException or JsonException)
        {
            return false;
        }
    }

    internal static void Clear(HttpContext context) =>
        context.Response.Cookies.Delete(CookieName, Options());

    private static string Hash(string value)
    {
        var separator = value.IndexOf('?');
        var path = separator < 0 ? value : value[..separator];
        var query = QueryHelpers.ParseQuery(separator < 0 ? "" : value[separator..]);
        // Consent adds these form fields on the same authorization request.
        query.Remove("consent_decision");
        query.Remove("__RequestVerificationToken");
        var canonical = path + QueryString.Create(query.OrderBy(pair => pair.Key, StringComparer.Ordinal));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
    private static TimeProvider Clock(HttpContext context) => context.RequestServices.GetRequiredService<TimeProvider>();
    private static IDataProtector Protector(HttpContext context) => context.RequestServices
        .GetRequiredService<IDataProtectionProvider>().CreateProtector("Identity.AuthorizationAuthenticationReceipt.v1");
    private static CookieOptions Options(DateTimeOffset? expires = null) => new()
    {
        HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = "/",
        IsEssential = true, Expires = expires,
    };
    private sealed record Receipt(string RequestHash, string SessionId, string AuthTime, DateTimeOffset Expires);
}
