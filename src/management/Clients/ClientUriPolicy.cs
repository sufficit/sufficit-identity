using Sufficit.Identity.Application.Accounts;
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

    /// <summary>
    /// Validates the native callbacks a client registers to be brought back to
    /// the foreground with once a grant completes. Unlike a redirect URI these
    /// receive no code and no token, which is why a private-use URI scheme
    /// (RFC 8252, section 7.1) is acceptable here and nowhere else. Values are
    /// kept verbatim: RFC 8252 section 8.1 matches them by simple string
    /// comparison, and canonicalization would break that.
    /// </summary>
    /// <summary>
    /// Validates the device close fallback URL a client wants to register.
    /// Null (not provided) and an explicit empty string (clear) both map to
    /// <c>null</c>; anything else must satisfy
    /// <see cref="DeviceCloseFallbackPolicy.TryValidateRegistration"/>.
    /// </summary>
    internal static string? ValidateDeviceCloseFallback(
        string? value,
        string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!DeviceCloseFallbackPolicy.TryValidateRegistration(
                value,
                out var normalized,
                out var reasonCode,
                out var reasonMessage))
        {
            throw new ManagementValidationException(
                reasonCode!,
                reasonMessage!,
                field);
        }

        return normalized;
    }

    internal static IReadOnlyList<string> ValidateNativeReturnUris(
        IReadOnlyList<string>? values,
        string field)
    {
        var result = new List<string>();

        foreach (var raw in values ?? [])
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            if (!NativeReturnUriPolicy.TryValidateRegistration(
                    raw,
                    out var normalized,
                    out var reasonCode,
                    out var reasonMessage))
            {
                throw new ManagementValidationException(
                    reasonCode!,
                    reasonMessage!,
                    field);
            }

            result.Add(normalized!);
        }

        var distinct = result
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (distinct.Length > NativeReturnUriPolicy.MaximumRegistrations)
        {
            throw new ManagementValidationException(
                "native_return_uri_limit",
                $"{field} accepts at most {NativeReturnUriPolicy.MaximumRegistrations} entries.",
                field);
        }

        return distinct;
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
