using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.STS;

public enum PublicOriginMode
{
    Audit,
    Enforce,
}

public sealed class PublicOriginPolicyOptions
{
    public PublicOriginMode Mode { get; init; } = PublicOriginMode.Enforce;
}

public interface IPublicOriginResolver
{
    string Resolve(HttpRequest request);

    string BuildAbsolute(HttpRequest request, string pathAndQuery);
}

public sealed class PublicOriginResolver(
    SufficitIdentityOptions options,
    ILogger<PublicOriginResolver> logger) : IPublicOriginResolver
{
    private readonly string? _configuredBaseUrl = ResolveConfigured(options);
    private int _requestFallbackLogged;

    public string Resolve(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_configuredBaseUrl is not null)
        {
            return _configuredBaseUrl;
        }

        if (options.PublicOrigin.Mode == PublicOriginMode.Enforce)
        {
            throw new InvalidOperationException(
                "A canonical Sufficit:Identity:PublicUrl or Issuer is required before public URLs can be emitted.");
        }

        if (Interlocked.Exchange(ref _requestFallbackLogged, 1) == 0)
        {
            logger.LogWarning(
                "Public URL generation is using the request scheme/host in compatibility Audit mode. Configure Sufficit:Identity:PublicUrl and then set PublicOrigin:Mode=Enforce to eliminate Host-header-derived links.");
        }

        return $"{request.Scheme}://{request.Host}{request.PathBase}"
            .TrimEnd('/');
    }

    public string BuildAbsolute(HttpRequest request, string pathAndQuery)
    {
        ArgumentNullException.ThrowIfNull(pathAndQuery);
        var path = pathAndQuery.StartsWith("/", StringComparison.Ordinal)
            ? pathAndQuery
            : "/" + pathAndQuery;
        return Resolve(request) + path;
    }

    internal static string? ResolveConfigured(SufficitIdentityOptions options)
    {
        var configured = string.IsNullOrWhiteSpace(options.PublicUrl)
            ? options.Issuer
            : options.PublicUrl;
        if (string.IsNullOrWhiteSpace(configured))
        {
            return null;
        }

        if (!Uri.TryCreate(configured, UriKind.Absolute, out var uri)
            || (!string.Equals(
                    uri.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase)
                && !string.Equals(
                    uri.Scheme,
                    Uri.UriSchemeHttp,
                    StringComparison.OrdinalIgnoreCase))
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:PublicUrl/Issuer must be an absolute HTTP(S) URL without query or fragment.");
        }

        return uri.AbsoluteUri.TrimEnd('/');
    }
}
