using System.Net;

namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Shared validation for security metadata that the server retrieves over HTTPS.
/// DNS resolution must still be pinned by the outbound HTTP transport.
/// </summary>
public static class PublicHttpsUriPolicy
{
    public static bool IsAllowed(Uri? uri) =>
        uri is { IsAbsoluteUri: true }
        && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.IsNullOrEmpty(uri.Fragment)
        && (!IPAddress.TryParse(uri.Host, out var address)
            || !IsBlockedAddress(address));

    public static bool IsBlockedAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.IsIPv6LinkLocal
            || address.IsIPv6Multicast
            || address.IsIPv6SiteLocal)
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length == 16)
        {
            return (bytes[0] & 0xfe) == 0xfc;
        }

        return bytes[0] switch
        {
            0 or 10 or 127 => true,
            100 when bytes[1] is >= 64 and <= 127 => true,
            169 when bytes[1] == 254 => true,
            172 when bytes[1] is >= 16 and <= 31 => true,
            192 when bytes[1] == 168 => true,
            192 when bytes[1] == 0 && bytes[2] is 0 or 2 => true,
            198 when bytes[1] is 18 or 19 => true,
            198 when bytes[1] == 51 && bytes[2] == 100 => true,
            203 when bytes[1] == 0 && bytes[2] == 113 => true,
            >= 224 => true,
            _ => false,
        };
    }
}
