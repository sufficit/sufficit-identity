namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>
/// Cached, coalescing introspection client. The handler uses it; resources with their own pipeline
/// (for example DPoP or a legacy fallback client) may call it directly with the options of a scheme.
/// </summary>
public interface IOAuth2IntrospectionClient
{
    /// <exception cref="IntrospectionUnavailableException">The endpoint gave no verdict.</exception>
    Task<IntrospectionResult> IntrospectAsync(string token, OAuth2IntrospectionOptions options, CancellationToken cancellationToken = default);
}
