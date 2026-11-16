using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>Registration, mirroring Duende's <c>AddOAuth2Introspection</c>.</summary>
public static class OAuth2IntrospectionExtensions
{
    public static AuthenticationBuilder AddOAuth2Introspection(this AuthenticationBuilder builder, Action<OAuth2IntrospectionOptions> configure)
        => builder.AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, configure);

    public static AuthenticationBuilder AddOAuth2Introspection(this AuthenticationBuilder builder, string scheme, Action<OAuth2IntrospectionOptions> configure)
    {
        builder.Services.AddOAuth2IntrospectionClient();
        return builder.AddScheme<OAuth2IntrospectionOptions, OAuth2IntrospectionHandler>(scheme, configure);
    }

    /// <summary>
    /// Registers only <see cref="IOAuth2IntrospectionClient"/> (cache + coalescing), for pipelines that authenticate
    /// outside the handler. Uses the application's <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>
    /// (Redis, SQL, ...) and falls back to an in-memory one when none is registered.
    /// </summary>
    public static IServiceCollection AddOAuth2IntrospectionClient(this IServiceCollection services)
    {
        services.AddDistributedMemoryCache();
        services.AddHttpClient(OAuth2IntrospectionDefaults.HttpClientName, http => http.Timeout = TimeSpan.FromSeconds(10));
        services.TryAddSingleton<IOAuth2IntrospectionClient, OAuth2IntrospectionClient>();
        return services;
    }
}
