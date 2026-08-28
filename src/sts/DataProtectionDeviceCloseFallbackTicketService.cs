using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Carries a client's validated close fallback URL across the browser
/// redirects of a device transaction as an encrypted, expiring ticket.
/// Separate purpose from the native-return ticket so one can never be
/// replayed as the other.
/// </summary>
public sealed class DataProtectionDeviceCloseFallbackTicketService
    : IDeviceCloseFallbackTicketService
{
    // The approved terminal page is rendered right after the redirect, so the
    // ticket only has to survive one round trip; anything longer is a replay
    // window.
    private static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(10);

    private readonly ITimeLimitedDataProtector _protector;

    public DataProtectionDeviceCloseFallbackTicketService(
        IDataProtectionProvider dataProtectionProvider)
    {
        _protector = dataProtectionProvider
            .CreateProtector("Sufficit.Identity.DeviceCloseFallback.v1")
            .ToTimeLimitedDataProtector();
    }

    public string Protect(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        return _protector.Protect(url.Trim(), TicketLifetime);
    }

    public string? Unprotect(string? ticket)
    {
        if (string.IsNullOrWhiteSpace(ticket))
        {
            return null;
        }

        try
        {
            return _protector.Unprotect(ticket);
        }
        catch (Exception exception)
            when (exception is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
