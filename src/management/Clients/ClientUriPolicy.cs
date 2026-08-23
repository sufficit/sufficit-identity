using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// Rules governing the URIs a client may register: where an authorization
/// response may be delivered, and where logout notifications may be sent.
/// </summary>
/// <remarks>
/// Extracted from <c>ClientManagementService</c>. These are the rules that
/// keep a registered client from becoming an open redirect or a token
/// delivery point an attacker controls, so they belong somewhere they can be
/// read and tested as a unit. Behavior is unchanged — reason codes and
/// messages are part of the API contract and are reproduced exactly.
/// </remarks>
internal static class ClientUriPolicy
{
    /// <summary>
    /// Validates redirect (or post-logout redirect) URIs. Each must be
    /// absolute, carry no fragment, and use HTTPS — with plain HTTP allowed
    /// only for loopback, which is how native and CLI clients legitimately
    /// receive a code on the user's own machine. Duplicates collapse.
    /// </summary>
    internal static IReadOnlyList<Uri> ValidateRedirectUris(
        IReadOnlyList<string>? values,
        string field)
    {
        var result = new List<Uri>();

        foreach (var raw in values ?? [])
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var redirect))
            {
                throw new ManagementValidationException(
                    "redirect_uri_invalid",
                    $"{field} must contain only absolute URIs: {raw}",
                    field);
            }

            // A fragment never reaches the server and cannot be matched
            // reliably, so allowing one would weaken exact-match comparison.
            if (redirect.Fragment.Length > 0)
            {
                throw new ManagementValidationException(
                    "redirect_uri_fragment",
                    $"{field} cannot contain a fragment: {redirect}",
                    field);
            }

            var isLoopback = redirect.IsLoopback
                || string.Equals(
                    redirect.Host,
                    "localhost",
                    StringComparison.OrdinalIgnoreCase);
            if (!string.Equals(
                    redirect.Scheme,
                    Uri.UriSchemeHttps,
                    StringComparison.OrdinalIgnoreCase)
                && !isLoopback)
            {
                throw new ManagementValidationException(
                    "redirect_uri_https_required",
                    $"{field} must use https (http is only allowed for loopback): {redirect}",
                    field);
            }

            result.Add(redirect);
        }

        return result
            .DistinctBy(uri => uri.AbsoluteUri, StringComparer.Ordinal)
            .ToArray();
    }

    internal static Uri? ValidateLogoutUri(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return ValidateRedirectUris([value], field)[0];
    }

    /// <summary>
    /// Origin comparison used to tie a front-channel logout URI to the client
    /// that registered it: scheme, host and port must all match.
    /// </summary>
    internal static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port;

    /// <summary>
    /// Checks the logout configuration as a whole: a session-specific channel
    /// needs a URI to notify, and a front-channel logout URI must share an
    /// origin with a registered redirect URI so a client cannot direct logout
    /// traffic at a host it never proved it controls.
    /// </summary>
    internal static void ValidateLogoutConfiguration(
        IReadOnlyList<Uri> redirectUris,
        Uri? frontchannelLogoutUri,
        bool frontchannelSessionRequired,
        Uri? backchannelLogoutUri,
        bool backchannelSessionRequired)
    {
        if (frontchannelSessionRequired && frontchannelLogoutUri is null)
        {
            throw new ManagementValidationException(
                "frontchannel_logout_uri_required",
                "frontchannelLogoutUri is required when session-specific front-channel logout is requested.",
                "frontchannelLogoutUri");
        }
        if (backchannelSessionRequired && backchannelLogoutUri is null)
        {
            throw new ManagementValidationException(
                "backchannel_logout_uri_required",
                "backchannelLogoutUri is required when session-specific back-channel logout is requested.",
                "backchannelLogoutUri");
        }
        if (frontchannelLogoutUri is not null &&
            !redirectUris.Any(redirect => SameOrigin(redirect, frontchannelLogoutUri)))
        {
            throw new ManagementValidationException(
                "frontchannel_logout_origin_mismatch",
                "frontchannelLogoutUri must use the same scheme, host and port as a redirect URI.",
                "frontchannelLogoutUri");
        }
    }
}
