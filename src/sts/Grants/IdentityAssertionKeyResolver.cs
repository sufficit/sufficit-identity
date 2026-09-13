using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Resolves a trusted ID-JAG issuer's signing keys from its configured
/// <c>JwksUri</c>, or from the <c>jwks_uri</c> of its OpenID Connect discovery
/// document. Key sets are fetched and cached by <see cref="Jar.RemoteJwksProvider"/>,
/// which only accepts public HTTPS locations through the outbound HTTP policy.
/// </summary>
internal sealed class DiscoveryIdentityAssertionKeyResolver(
    IHttpClientFactory clients,
    Jar.RemoteJwksProvider remoteJwks,
    TimeProvider timeProvider) : IIdentityAssertionKeyResolver
{
    private static readonly TimeSpan DiscoveryCacheLifetime = TimeSpan.FromHours(1);
    private readonly ConcurrentDictionary<string, (Uri JwksUri, DateTimeOffset FreshUntil)> _discovery =
        new(StringComparer.Ordinal);

    public async Task<IReadOnlyList<SecurityKey>> GetSigningKeysAsync(
        IdentityAssertionTrustedIssuer issuer,
        string? keyId,
        CancellationToken cancellationToken)
    {
        var jwksUri = !string.IsNullOrWhiteSpace(issuer.JwksUri)
            ? new Uri(issuer.JwksUri, UriKind.Absolute)
            : await DiscoverJwksUriAsync(issuer.Issuer, cancellationToken);
        return await remoteJwks.GetKeysAsync(jwksUri, keyId, cancellationToken);
    }

    private async Task<Uri> DiscoverJwksUriAsync(
        string issuer,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        if (_discovery.TryGetValue(issuer, out var cached) && cached.FreshUntil > now)
        {
            return cached.JwksUri;
        }

        var discoveryUri = new Uri(
            issuer.TrimEnd('/') + "/.well-known/openid-configuration",
            UriKind.Absolute);
        Jar.RemoteJwksProvider.ValidateUri(discoveryUri);

        using var request = new HttpRequestMessage(HttpMethod.Get, discoveryUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await clients.CreateClient("jar-remote-jwks")
            .SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;

        // Mix-up defense: the document must describe the configured issuer.
        if (!root.TryGetProperty("issuer", out var published)
            || !string.Equals(published.GetString(), issuer, StringComparison.Ordinal)
            || !root.TryGetProperty("jwks_uri", out var jwks)
            || !Uri.TryCreate(jwks.GetString(), UriKind.Absolute, out var jwksUri))
        {
            throw new InvalidOperationException(
                "The identity provider's discovery document does not match the trusted issuer.");
        }

        _discovery[issuer] = (jwksUri, now.Add(DiscoveryCacheLifetime));
        return jwksUri;
    }
}
