using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>Options of the introspection handler. Names follow Duende's OAuth2IntrospectionOptions.</summary>
public sealed class OAuth2IntrospectionOptions : AuthenticationSchemeOptions
{
    /// <summary>Issuer base URL; the endpoint defaults to <c>{Authority}/connect/introspect</c>.</summary>
    public string? Authority { get; set; }

    /// <summary>Explicit introspection endpoint; wins over <see cref="Authority"/>.</summary>
    public string? IntrospectionEndpoint { get; set; }

    /// <summary>Client id of this resource server (sent as <c>client_secret_post</c>).</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client secret of this resource server.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Optional <c>token_type_hint</c>; Duende sends <c>access_token</c>.</summary>
    public string? TokenTypeHint { get; set; } = "access_token";

    /// <summary>Caches active introspection results in <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>.</summary>
    public bool EnableCaching { get; set; }

    /// <summary>Maximum lifetime of a cached result; never beyond the token's own <c>exp</c>.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Prefix of every cache key, so several resources can share one cache.</summary>
    public string CacheKeyPrefix { get; set; } = string.Empty;

    /// <summary>Builds the cache key. Default: prefix + SHA-256 (hex) of the token; the token itself is never a key.</summary>
    public Func<OAuth2IntrospectionOptions, string, string> CacheKeyGenerator { get; set; } = DefaultCacheKey;

    /// <summary>Reads the token from the request. Default: <c>Authorization: Bearer</c>.</summary>
    public Func<HttpRequest, string?> TokenRetriever { get; set; } = TokenRetrieval.FromAuthorizationHeader();

    /// <summary>Claim type used as <see cref="System.Security.Claims.ClaimsIdentity.Name"/>.</summary>
    public string NameClaimType { get; set; } = "name";

    /// <summary>Claim type used for roles.</summary>
    public string RoleClaimType { get; set; } = "role";

    /// <summary>Authentication type of the produced identity; defaults to the scheme name.</summary>
    public string? AuthenticationType { get; set; }

    /// <summary>Stores the token in the authentication properties (<c>access_token</c>).</summary>
    public bool SaveToken { get; set; }

    /// <summary>Lifecycle callbacks.</summary>
    public new OAuth2IntrospectionEvents Events
    {
        get => (OAuth2IntrospectionEvents)base.Events!;
        set => base.Events = value;
    }

    public OAuth2IntrospectionOptions() => base.Events = new OAuth2IntrospectionEvents();

    /// <summary>Endpoint actually called.</summary>
    public string ResolveEndpoint()
        => !string.IsNullOrWhiteSpace(IntrospectionEndpoint) ? IntrospectionEndpoint!
            : Authority!.TrimEnd('/') + OAuth2IntrospectionDefaults.IntrospectionPath;

    public override void Validate()
    {
        base.Validate();
        if (string.IsNullOrWhiteSpace(Authority) && string.IsNullOrWhiteSpace(IntrospectionEndpoint))
            throw new InvalidOperationException("Set Authority or IntrospectionEndpoint.");
        if (string.IsNullOrWhiteSpace(ClientId))
            throw new InvalidOperationException("ClientId is required to call the introspection endpoint.");
        if (EnableCaching && CacheDuration <= TimeSpan.Zero)
            throw new InvalidOperationException("CacheDuration must be positive when caching is enabled.");
    }

    public static string DefaultCacheKey(OAuth2IntrospectionOptions options, string token)
        => options.CacheKeyPrefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
