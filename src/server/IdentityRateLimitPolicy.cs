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

    /// <summary>
    /// Interactive credential-validation endpoints: every POST under
    /// <c>/connect/*</c> (token, authorize consent, endsession, introspection,
    /// revocation, PAR, device verify, CIBA completion, DCR), the CIBA
    /// initiation endpoint <c>/bc-authorize</c>, and the account credential
    /// surfaces (login, forgot/reset password, register, external-login
    /// callback, passkeys).
    /// </summary>
    /// <remarks>
    /// Covering the whole <c>/connect/</c> prefix rather than an explicit list
    /// is deliberate: a new protocol endpoint can never be silently left
    /// unthrottled — the class of bug that bit when the original limiter covered
    /// only <c>/connect/token</c>. GETs (discovery, userinfo, the authorize
    /// challenge) are not credential-validation surfaces and stay unrestricted.
    /// </remarks>
    internal static bool IsCredentialEndpoint(PathString path, string method)
    {
        if (!HttpMethods.IsPost(method))
        {
            return false;
        }

        var value = path.Value ?? string.Empty;

        if (value.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // CIBA initiation lives outside /connect/ as defined by the OpenID
        // Connect CIBA Core 1.0 specification (RFC 9126 defines PAR, not CIBA).
        if (value.StartsWith("/bc-authorize", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return value.StartsWith("/account/login", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/account/forgotpassword", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/account/resetpassword", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/account/register", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/account/externallogincallback", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("/account/passkeys", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Anonymous device-information lookup (<c>GET /connect/device/info</c>),
    /// which gets its own bucket so enumeration cannot drain the credential one.
    /// </summary>
    internal static bool IsDeviceInformationEndpoint(PathString path, string method) =>
        HttpMethods.IsGet(method)
        && path.StartsWithSegments(
            "/connect/device/info",
            StringComparison.OrdinalIgnoreCase);

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

    /// <summary>
    /// Administrative surfaces: the management API and SCIM. Both were
    /// completely unthrottled — the limiter covered <c>/connect/*</c> and
    /// <c>/account/*</c> only — so a looping or hostile caller holding a valid
    /// operator token could drive unbounded database work, including the audit
    /// writes that a refusal produces.
    /// </summary>
    internal static bool IsAdministrativeEndpoint(
        PathString path,
        string routePrefix) =>
        path.StartsWithSegments(
            "/" + routePrefix.Trim('/'),
            StringComparison.OrdinalIgnoreCase)
        || path.StartsWithSegments("/scim", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whole-collection operations: applying a provisioning manifest (which
    /// creates or updates every client and scope it declares in a single
    /// request) and revoking every session of a user.
    /// </summary>
    /// <remarks>
    /// These get their own bucket rather than being exempt or being folded
    /// into the general one, because their cost profile is the opposite of a
    /// normal call: one request, a great deal of server work. Sharing a bucket
    /// would let a provisioning run exhaust the budget for ordinary operations
    /// (and vice versa) even though neither is misbehaving — the failure the
    /// caller would see is a 429 caused by unrelated legitimate traffic.
    /// Separating them means a bulk command is limited by how expensive it is,
    /// not by how chatty something else was.
    /// </remarks>
    internal static bool IsBulkEndpoint(PathString path, string routePrefix)
    {
        var prefix = "/" + routePrefix.Trim('/');
        if (path.StartsWithSegments(
                prefix + "/provisioning",
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // DELETE {prefix}/sessions/users/{userId} revokes every session a user
        // holds, across every device.
        return path.StartsWithSegments(
            prefix + "/sessions/users",
            StringComparison.OrdinalIgnoreCase);
    }

    internal static string GetAdministrativePartitionKey(
        PathString path,
        string routePrefix,
        string clientIp) =>
        IsBulkEndpoint(path, routePrefix)
            ? "admin-bulk-ip:" + clientIp
            : "admin-ip:" + clientIp;

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
