using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.Server;

internal static class IdentityRateLimitPolicy
{
    internal static bool IsPushedAuthorizationEndpoint(
        PathString path,
        string method) =>
        HttpMethods.IsPost(method)
        && path.Equals("/connect/par", StringComparison.OrdinalIgnoreCase);

    internal static bool IsOAuthProtocolEndpoint(PathString path) =>
        path.StartsWithSegments("/connect", StringComparison.OrdinalIgnoreCase)
        || path.StartsWithSegments(
            "/bc-authorize",
            StringComparison.OrdinalIgnoreCase);

    internal static string GetCredentialPartitionKey(
        PathString path,
        string method,
        string clientIp) =>
        IsPushedAuthorizationEndpoint(path, method)
            ? "par-ip:" + clientIp
            : "credential-ip:" + clientIp;

    internal static async ValueTask WriteRejectionResponseAsync(
        HttpContext httpContext,
        int retryAfterSeconds,
        CancellationToken cancellationToken)
    {
        var response = httpContext.Response;
        response.StatusCode = StatusCodes.Status429TooManyRequests;
        response.Headers.RetryAfter = retryAfterSeconds.ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";

        if (!IsOAuthProtocolEndpoint(httpContext.Request.Path))
        {
            return;
        }

        response.ContentType = "application/json;charset=UTF-8";
        await response.WriteAsJsonAsync(new
        {
            error = OpenIddictConstants.Errors.TemporarilyUnavailable,
            error_description = "The authorization server is temporarily unable to handle the request due to rate limiting.",
        }, cancellationToken);
    }
}
