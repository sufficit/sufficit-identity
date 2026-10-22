using System.Net;
using System.Net.Sockets;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// The unit a client is counted by for rate limits and abuse counters. IPv4 is
/// one address; IPv6 is its /64, which a single subscriber holds whole and can
/// rotate inside at will, so counting /128s would never reach any limit.
/// </summary>
public static class ClientAddressPartition
{
    public static string? Of(IPAddress? address)
    {
        if (address is null) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return address.ToString();
        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes) + "/64";
    }
}
