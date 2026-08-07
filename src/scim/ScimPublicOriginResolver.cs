using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.Scim;

public interface IScimPublicOriginResolver
{
    string BuildAbsolute(HttpRequest request, string relativePath);
}

public sealed class ScimPublicOriginResolver(
    IConfiguration configuration,
    ILogger<ScimPublicOriginResolver> logger) : IScimPublicOriginResolver
{
    private readonly string? configuredOrigin = ResolveConfigured(configuration);
    private readonly bool enforce = string.Equals(
        configuration["Sufficit:Identity:PublicOrigin:Mode"],
        "Enforce",
        StringComparison.OrdinalIgnoreCase);
    private int fallbackLogged;

    public string BuildAbsolute(HttpRequest request, string relativePath)
    {
        ArgumentNullException.ThrowIfNull(request);
        var origin = configuredOrigin;
        if (origin is null)
        {
            if (enforce)
            {
                throw new InvalidOperationException(
                    "SCIM location generation requires a canonical PublicUrl or Issuer in Enforce mode.");
            }

            if (Interlocked.Exchange(ref fallbackLogged, 1) == 0)
            {
                logger.LogWarning(
                    "SCIM Location values are using request scheme/host in compatibility Audit mode.");
            }
            origin = $"{request.Scheme}://{request.Host}{request.PathBase}"
                .TrimEnd('/');
        }

        return origin + "/" + relativePath.TrimStart('/');
    }

    private static string? ResolveConfigured(IConfiguration configuration)
    {
        var value = configuration["Sufficit:Identity:PublicUrl"]
            ?? configuration["Sufficit:Identity:Issuer"];
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (!string.Equals(
                    uri.Scheme,
                    Uri.UriSchemeHttp,
                    StringComparison.OrdinalIgnoreCase)
                && !string.Equals(
                    uri.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase))
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException(
                "SCIM PublicUrl/Issuer must be an absolute HTTP(S) URL without query or fragment.");
        }

        return uri.AbsoluteUri.TrimEnd('/');
    }
}
