using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS;

namespace Sufficit.Identity.Server;

/// <summary>
/// Registers the exact-origin CORS policy shared by the production host and
/// its integration test host.
/// </summary>
public static class BrowserCorsExtensions
{
    public const string PolicyName = "BrowserClients";

    public static IServiceCollection AddSufficitCors(
        this IServiceCollection services,
        CorsOptions options)
    {
        if (!options.Enabled)
        {
            return services;
        }

        var allowedOrigins = options.AllowedOrigins
            .Select(origin => origin.TrimEnd('/'))
            .Where(origin => Uri.TryCreate(origin, UriKind.Absolute, out var uri)
                && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)
                && uri.AbsolutePath == "/"
                && string.IsNullOrEmpty(uri.Query)
                && string.IsNullOrEmpty(uri.Fragment)
                && !origin.Contains('*', StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (allowedOrigins.Length == 0)
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:Cors:AllowedOrigins must contain at least one exact http(s) origin when CORS is enabled.");
        }

        services.AddCors(cors => cors.AddPolicy(PolicyName, policy =>
        {
            policy.WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod();

            if (options.AllowCredentials)
            {
                policy.AllowCredentials();
            }
        }));

        return services;
    }

    public static IApplicationBuilder UseSufficitCors(
        this IApplicationBuilder app,
        CorsOptions options)
    {
        if (options.Enabled)
        {
            app.UseCors(PolicyName);
        }

        return app;
    }
}
