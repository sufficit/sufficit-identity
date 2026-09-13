using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;

namespace Sufficit.Identity.Core.Networking;

public sealed class TrustedProxyOptions
{
    public string[] TrustedProxies { get; set; } = [];
    public int ForwardLimit { get; set; } = 2;
    public TrustedProxySynchronizationOptions ProxySynchronization { get; set; } = new();
}

public sealed record TrustedProxySnapshot(
    ImmutableArray<string> FileNetworks,
    ImmutableArray<string> DatabaseNetworks,
    ImmutableArray<string> EffectiveNetworks,
    int FileForwardLimit,
    int? DatabaseForwardLimit,
    string Revision,
    DateTime? UpdatedAtUtc)
{
    public int ForwardLimit => DatabaseForwardLimit ?? FileForwardLimit;
}

public static class TrustedProxyValidation
{
    public static ImmutableArray<string> Normalize(IEnumerable<string> networks)
    {
        var result = new SortedSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var value in networks)
        {
            if (++count > 128) throw new ArgumentException("Provide at most 128 proxies or networks.");
            var text = value?.Trim();
            if (string.IsNullOrWhiteSpace(text) || text.Length > 64 || text.Contains('%'))
                throw new ArgumentException("Provide a valid IP address or CIDR network.");
            if (!text.Contains('/'))
            {
                if (!IPAddress.TryParse(text, out var address))
                    throw new ArgumentException($"Invalid address: {text}.");
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                text = $"{address}/{(address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)}";
            }
            if (!IPNetwork.TryParse(text, out var network) || network.PrefixLength == 0
                || network.BaseAddress.IsIPv4MappedToIPv6)
                throw new ArgumentException($"Invalid network: {text}. Use a delimited network with a canonical base address.");
            result.Add(network.ToString());
        }
        return result.ToImmutableArray();
    }

    public static void ValidateForwardLimit(int? limit)
    {
        if (limit is < 1 or > 10)
            throw new ArgumentException("The limit must be between 1 and 10 hops.");
    }
}
