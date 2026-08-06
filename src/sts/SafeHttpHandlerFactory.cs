using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace Sufficit.Identity.STS;

/// <summary>
/// Factory for outbound HttpClients that blocks connections to private/loopback/
/// metadata IP addresses (SSRF defense, finding #6). Applied to all STS outbound
/// HTTP: backchannel logout, SSF push delivery, stream verification, HIBP range API.
/// </summary>
public static class SafeHttpHandlerFactory
{
    /// <summary>
    /// Configures an HttpClient with an SSRF-blocking connect callback. The
    /// callback resolves the destination IP and rejects connections to:
    /// loopback (127.0.0.0/8, ::1), private (10/8, 172.16/12, 192.168/16),
    /// link-local (169.254/16, fe80::/10), and metadata endpoints
    /// (169.254.169.254 — AWS/GCP/Azure metadata).
    /// </summary>
    public static HttpClientHandler CreateSafeHandler() => new()
    {
        AllowAutoRedirect = false,
    };

    /// <summary>
    /// Registers a named HttpClient with SSRF protection. Use for all outbound
    /// HTTP from the STS that receives user/admin-controlled URLs.
    /// </summary>
    public static IHttpClientBuilder AddSafeHttpClient(
        this IServiceCollection services,
        string name) =>
        services.AddHttpClient(name)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectCallback = async (context, cancellationToken) =>
                {
                    var addresses = await Dns.GetHostAddressesAsync(
                        context.DnsEndPoint.Host, cancellationToken);
                    if (addresses.Length == 0)
                    {
                        throw new HttpRequestException(
                            $"DNS resolution failed for {context.DnsEndPoint.Host}.");
                    }

                    foreach (var ip in addresses)
                    {
                        if (IsBlocked(ip))
                        {
                            throw new HttpRequestException(
                                $"Connection to {ip} ({context.DnsEndPoint.Host}) blocked " +
                                "by SSRF protection (private/loopback/metadata address).");
                        }
                    }

                    // All resolved IPs passed — connect to the first one.
                    return await new SocketsHttpHandler().ConnectCallback!(
                        context, cancellationToken);
                },
            });

    /// <summary>
    /// Returns true if the IP is private, loopback, link-local, or a known
    /// cloud metadata endpoint.
    /// </summary>
    private static bool IsBlocked(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (link-local + cloud metadata 169.254.169.254)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 127.0.0.0/8 (extra loopback range)
            if (bytes[0] == 127) return true;
            // 0.0.0.0/8
            if (bytes[0] == 0) return true;
        }

        // IPv6: loopback (::1) and link-local (fe80::/10)
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.IsIPv6LinkLocal) return true;

        return false;
    }
}
