using System.Text.RegularExpressions;

namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Deployment-neutral rules for the native callback a client may be sent back
/// to once a server-side grant is complete. The callback carries no code and no
/// token; it only brings the polling client back to the foreground.
/// </summary>
/// <remarks>
/// This type validates shape only and never names a concrete application.
/// Which callbacks are acceptable is per-client registration data — the rule
/// RFC 6749 (section 3.1.2.2) applies to every redirection endpoint — and a
/// candidate is accepted only by simple string comparison against that
/// registration, as RFC 8252 (section 8.1) requires. Private-use URI schemes
/// are the mechanism RFC 8252 (section 7.1) defines for native applications;
/// the scheme is always supplied by the client record, never by this server.
/// </remarks>
public static partial class NativeReturnUriPolicy
{
    /// <summary>Scheme production from RFC 3986, section 3.1.</summary>
    [GeneratedRegex("^[A-Za-z][A-Za-z0-9+.-]*:")]
    private static partial Regex SchemePrefix();

    /// <summary>
    /// Extension client-metadata name (RFC 7591, section 2) carrying the
    /// registered callbacks, both in registration payloads and in the
    /// management API.
    /// </summary>
    public const string MetadataName = "native_return_uris";

    /// <summary>
    /// Key holding <see cref="MetadataName"/> in the client record property
    /// bag.
    /// </summary>
    public const string PropertyKey = "identity:client:native-return-uris";

    /// <summary>Registrations accepted per client.</summary>
    public const int MaximumRegistrations = 8;

    /// <summary>
    /// Longest accepted callback. Bounded because the value is echoed into a
    /// redirect and stored in a property bag read on every device request.
    /// </summary>
    public const int MaximumLength = 512;

    /// <summary>
    /// Schemes never accepted: they either execute in the browser or read
    /// local state, so registering one would turn the completion page into a
    /// script or file-disclosure sink.
    /// </summary>
    private static readonly string[] DeniedSchemes =
    [
        "javascript",
        "data",
        "vbscript",
        "file",
        "blob",
        "about",
        "view-source",
    ];

    /// <summary>
    /// Validates a callback a client wants to register. On success
    /// <paramref name="normalized"/> carries the exact string later matched
    /// against — trimmed, but otherwise untouched, because a private-use URI
    /// such as <c>myapp://done</c> does not survive URI canonicalization
    /// intact and RFC 8252 matches these by simple string comparison anyway.
    /// </summary>
    public static bool TryValidateRegistration(
        string? candidate,
        out string? normalized,
        out string? reasonCode,
        out string? reasonMessage)
    {
        normalized = null;
        reasonCode = null;
        reasonMessage = null;

        if (string.IsNullOrWhiteSpace(candidate))
        {
            reasonCode = "native_return_uri_invalid";
            reasonMessage = "A native return URI cannot be empty.";
            return false;
        }

        var trimmed = candidate.Trim();
        if (trimmed.Length > MaximumLength)
        {
            reasonCode = "native_return_uri_too_long";
            reasonMessage =
                $"A native return URI cannot exceed {MaximumLength} characters.";
            return false;
        }

        if (trimmed.Any(character => char.IsControl(character)
            || char.IsWhiteSpace(character)))
        {
            reasonCode = "native_return_uri_invalid";
            reasonMessage =
                $"A native return URI cannot contain whitespace or control characters: {trimmed}";
            return false;
        }

        // Require an explicit scheme before parsing. On Unix, Uri.TryCreate
        // happily reads "/etc/passwd" as an absolute file URI, so a relative
        // path would otherwise be reported as a denied scheme rather than as
        // the malformed value it is.
        if (!SchemePrefix().IsMatch(trimmed))
        {
            reasonCode = "native_return_uri_invalid";
            reasonMessage =
                $"A native return URI must start with a scheme: {trimmed}";
            return false;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            reasonCode = "native_return_uri_invalid";
            reasonMessage = $"A native return URI must be absolute: {trimmed}";
            return false;
        }

        // A fragment never reaches the server and cannot be matched reliably,
        // so allowing one would weaken the exact-match comparison.
        if (uri.Fragment.Length > 0)
        {
            reasonCode = "native_return_uri_fragment";
            reasonMessage =
                $"A native return URI cannot contain a fragment: {trimmed}";
            return false;
        }

        if (DeniedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            reasonCode = "native_return_uri_scheme_denied";
            reasonMessage =
                $"The {uri.Scheme} scheme cannot be used as a native return URI: {trimmed}";
            return false;
        }

        // Web callbacks are allowed — a browser-hosted client legitimately
        // returns to itself — but only under the same transport rule the
        // redirection endpoints follow: https, or plain http on loopback,
        // which is how a native client receives a response on the user's own
        // machine (RFC 8252, section 7.3).
        if (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !uri.IsLoopback
            && !string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            reasonCode = "native_return_uri_https_required";
            reasonMessage =
                $"A http native return URI is only allowed for loopback: {trimmed}";
            return false;
        }

        normalized = trimmed;
        return true;
    }

    /// <summary>
    /// Resolves a candidate against the callbacks registered for a client and
    /// returns the registered string, or <c>null</c> when nothing matches.
    /// Comparison is ordinal and exact (RFC 8252, section 8.1) — no prefix,
    /// suffix or wildcard matching.
    /// </summary>
    public static string? Match(
        IEnumerable<string>? registered,
        string? candidate)
    {
        if (registered is null || string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        var trimmed = candidate.Trim();
        return registered.FirstOrDefault(value =>
            string.Equals(value, trimmed, StringComparison.Ordinal));
    }
}
