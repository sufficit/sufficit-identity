using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.STS;

namespace Sufficit.Identity.Server;

/// <summary>
/// Registers the STS host rate limiter. Extracted from <c>Program.cs</c> so the
/// production wiring and the integration-test factory register the SAME limiter
/// instead of two hand-maintained reproductions that drift (eval 2026-08-30,
/// architecture item 1). The classification lives in
/// <see cref="IdentityRateLimitPolicy"/>; this method only assembles the
/// partitions and windows from <see cref="RateLimitOptions"/>.
/// </summary>
internal static class RateLimiterServiceCollectionExtensions
{
    public static IServiceCollection AddSufficitIdentityRateLimiter(
        this IServiceCollection services,
        RateLimitOptions rateLimit,
        string managementRoutePrefix)
    {
        ArgumentNullException.ThrowIfNull(rateLimit);
        ArgumentException.ThrowIfNullOrWhiteSpace(managementRoutePrefix);

        var credentialWindow = TimeSpan.FromSeconds(Math.Max(1, rateLimit.WindowSeconds));
        var pushedAuthorizationWindow = TimeSpan.FromSeconds(
            Math.Max(1, rateLimit.PushedAuthorizationWindowSeconds));
        var administrativeWindow = TimeSpan.FromSeconds(
            Math.Max(1, rateLimit.AdministrativeWindowSeconds));
        var administrativeBulkWindow = TimeSpan.FromSeconds(
            Math.Max(1, rateLimit.AdministrativeBulkWindowSeconds));

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.OnRejected = async (context, cancellationToken) =>
            {
                var httpContext = context.HttpContext;
                var retryAfter = httpContext switch
                {
                    _ when IdentityRateLimitPolicy.IsPushedAuthorizationEndpoint(
                        httpContext.Request.Path,
                        httpContext.Request.Method) => pushedAuthorizationWindow,
                    _ when IdentityRateLimitPolicy.IsAdministrativeEndpoint(
                        httpContext.Request.Path,
                        managementRoutePrefix) =>
                        IdentityRateLimitPolicy.IsBulkEndpoint(
                            httpContext.Request.Path,
                            managementRoutePrefix)
                            ? administrativeBulkWindow
                            : administrativeWindow,
                    _ => credentialWindow,
                };
                var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));

                httpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Sufficit.Identity.RateLimiting")
                    .LogWarning(
                        "Rate limit exceeded for {Method} {Path} from {RemoteIp}; retry after {RetryAfterSeconds}s.",
                        httpContext.Request.Method,
                        httpContext.Request.Path,
                        httpContext.Connection.RemoteIpAddress,
                        retryAfterSeconds);

                await IdentityRateLimitPolicy.WriteRejectionResponseAsync(
                    httpContext,
                    retryAfterSeconds,
                    cancellationToken);
            };

            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            {
                if (IdentityRateLimitPolicy.IsDeviceInformationEndpoint(
                    httpContext.Request.Path,
                    httpContext.Request.Method))
                {
                    var clientId = httpContext.User.FindFirst("client_id")?.Value
                        ?? httpContext.User.FindFirst("azp")?.Value;
                    var partition = !string.IsNullOrWhiteSpace(clientId)
                        ? "device-client:" + clientId
                        : "device-ip:" + (httpContext.Connection.RemoteIpAddress?.ToString()
                            ?? "unknown");
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partition,
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = Math.Max(1, rateLimit.DeviceInformationPermitLimit),
                            Window = TimeSpan.FromSeconds(
                                Math.Max(1, rateLimit.DeviceInformationWindowSeconds)),
                            QueueLimit = 0,
                            AutoReplenishment = true,
                        });
                }

                // Administrative surfaces (management API, SCIM) were entirely
                // unthrottled. Bulk endpoints get their own bucket so a
                // provisioning run and ordinary calls cannot starve each other.
                if (IdentityRateLimitPolicy.IsAdministrativeEndpoint(
                    httpContext.Request.Path,
                    managementRoutePrefix))
                {
                    var administrativeIp =
                        httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var isBulk = IdentityRateLimitPolicy.IsBulkEndpoint(
                        httpContext.Request.Path,
                        managementRoutePrefix);
                    return RateLimitPartition.GetFixedWindowLimiter(
                        IdentityRateLimitPolicy.GetAdministrativePartitionKey(
                            httpContext.Request.Path,
                            managementRoutePrefix,
                            administrativeIp),
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = Math.Max(1, isBulk
                                ? rateLimit.AdministrativeBulkPermitLimit
                                : rateLimit.AdministrativePermitLimit),
                            Window = TimeSpan.FromSeconds(Math.Max(1, isBulk
                                ? rateLimit.AdministrativeBulkWindowSeconds
                                : rateLimit.AdministrativeWindowSeconds)),
                            QueueLimit = 0,
                            AutoReplenishment = true,
                        });
                }

                if (!IdentityRateLimitPolicy.IsCredentialEndpoint(
                    httpContext.Request.Path,
                    httpContext.Request.Method))
                {
                    return RateLimitPartition.GetNoLimiter("unrestricted");
                }

                var clientIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                if (IdentityRateLimitPolicy.IsPushedAuthorizationEndpoint(
                    httpContext.Request.Path,
                    httpContext.Request.Method))
                {
                    return RateLimitPartition.GetFixedWindowLimiter(
                        IdentityRateLimitPolicy.GetCredentialPartitionKey(
                            httpContext.Request.Path,
                            httpContext.Request.Method,
                            clientIp),
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = Math.Max(1, rateLimit.PushedAuthorizationPermitLimit),
                            Window = pushedAuthorizationWindow,
                            QueueLimit = 0,
                            AutoReplenishment = true,
                        });
                }

                return RateLimitPartition.GetFixedWindowLimiter(
                    IdentityRateLimitPolicy.GetCredentialPartitionKey(
                        httpContext.Request.Path,
                        httpContext.Request.Method,
                        clientIp),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = Math.Max(1, rateLimit.PermitLimit),
                        Window = credentialWindow,
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    });
            });

            options.AddPolicy("device-information", httpContext =>
            {
                var clientId = httpContext.User.FindFirst("client_id")?.Value
                    ?? httpContext.User.FindFirst("azp")?.Value;
                var partition = !string.IsNullOrWhiteSpace(clientId)
                    ? "client:" + clientId
                    : "ip:" + (httpContext.Connection.RemoteIpAddress?.ToString()
                        ?? "unknown");
                return RateLimitPartition.GetFixedWindowLimiter(
                    partition,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = Math.Max(1, rateLimit.DeviceInformationPermitLimit),
                        Window = TimeSpan.FromSeconds(
                            Math.Max(1, rateLimit.DeviceInformationWindowSeconds)),
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    });
            });
        });

        return services;
    }
}
