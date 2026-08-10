using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

public sealed class OutboundHttpSecurityOptions
{
    public HashSet<string> AllowedPrivateHosts { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> AllowedHttpHosts { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public bool UseEnvironmentProxy { get; init; }
}

public static class SafeHttpHandlerFactory
{
    public static IHttpClientBuilder AddSafeHttpClient(
        this IServiceCollection services,
        string name,
        OutboundHttpSecurityOptions options) =>
        services.AddHttpClient(name).UseSafeOutboundHttp(options);

    public static IHttpClientBuilder UseSafeOutboundHttp(
        this IHttpClientBuilder builder,
        OutboundHttpSecurityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return builder
            .AddHttpMessageHandler(() => new OutboundRequestGuard(options))
            .ConfigurePrimaryHttpMessageHandler(() => CreateSafeHandler(options));
    }

    public static SocketsHttpHandler CreateSafeHandler(
        OutboundHttpSecurityOptions? options = null)
    {
        options ??= new OutboundHttpSecurityOptions();
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = options.UseEnvironmentProxy,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectCallback = (context, cancellationToken) =>
                ConnectAsync(context, options, cancellationToken),
        };
    }

    internal static bool IsBlockedAddress(IPAddress address) =>
        PublicHttpsUriPolicy.IsBlockedAddress(address);

    internal static bool HostMatches(
        IEnumerable<string> configuredHosts,
        string host)
    {
        var normalizedHost = NormalizeHost(host);
        return configuredHosts.Any(configured =>
        {
            var candidate = NormalizeHost(configured);
            return candidate.StartsWith("*.", StringComparison.Ordinal)
                ? normalizedHost.EndsWith(candidate[1..], StringComparison.OrdinalIgnoreCase)
                    && normalizedHost.Length > candidate.Length - 1
                : string.Equals(candidate, normalizedHost, StringComparison.OrdinalIgnoreCase);
        });
    }

    internal static void ValidateRequestUri(
        Uri? uri,
        OutboundHttpSecurityOptions options)
    {
        if (uri is null
            || !uri.IsAbsoluteUri
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            || !string.IsNullOrEmpty(uri.UserInfo))
            throw new HttpRequestException(
                "Outbound URI must be an absolute HTTP(S) URI without user-info.");

        if (uri.Scheme == Uri.UriSchemeHttp
            && !HostMatches(options.AllowedHttpHosts, uri.Host))
            throw new HttpRequestException(
                $"Clear-text HTTP to '{uri.Host}' is not allowlisted.");
    }

    private static async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        OutboundHttpSecurityOptions options,
        CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        if (addresses.Length == 0)
            throw new HttpRequestException($"DNS resolution returned no addresses for '{host}'.");

        var allowsPrivate = HostMatches(options.AllowedPrivateHosts, host);
        if (!allowsPrivate && addresses.Any(IsBlockedAddress))
            throw new HttpRequestException(
                $"Outbound connection to '{host}' was blocked by the private-network policy.");

        Exception? lastFailure = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                await socket.ConnectAsync(
                    new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception exception) when (exception is SocketException or IOException)
            {
                lastFailure = exception;
                socket.Dispose();
            }
        }

        throw new HttpRequestException(
            $"Could not connect to any resolved address for '{host}'.", lastFailure);
    }

    private static string NormalizeHost(string host) =>
        host.Trim().TrimEnd('.').ToLowerInvariant();

    private sealed class OutboundRequestGuard(
        OutboundHttpSecurityOptions options) : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            ValidateRequestUri(request.RequestUri, options);

            return base.SendAsync(request, cancellationToken);
        }
    }
}
