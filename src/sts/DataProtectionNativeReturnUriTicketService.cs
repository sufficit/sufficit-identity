using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS;

/// <summary>
/// Carries a validated native callback across the browser redirects of a
/// device transaction as an encrypted, expiring ticket.
/// </summary>
public sealed class DataProtectionNativeReturnUriTicketService
    : INativeReturnUriTicketService
{
    // The completion page is reached right after the grant, so the ticket only
    // has to survive one redirect; anything longer is a replay window.
    private static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(10);

    private readonly ITimeLimitedDataProtector _protector;

    public DataProtectionNativeReturnUriTicketService(
        IDataProtectionProvider dataProtectionProvider)
    {
        _protector = dataProtectionProvider
            .CreateProtector("Sufficit.Identity.NativeReturnUri.v1")
            .ToTimeLimitedDataProtector();
    }

    public string Protect(string returnUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(returnUri);
        return _protector.Protect(returnUri.Trim(), TicketLifetime);
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
