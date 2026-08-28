using System.Text.Json;

namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Deployment-neutral rules for the web destination a client registers as the
/// close fallback of its device flow: where the browser tab the user approved
/// goes when script cannot close it (OS-opened tabs). One URL per client —
/// the client knows its own site; the deployment and this server never do.
/// </summary>
/// <remarks>
/// This type validates shape only and never names a concrete destination.
/// Which URL is acceptable is per-client registration data stored in the
/// client record's property bag, exactly like the native return callbacks.
/// </remarks>
public static class DeviceCloseFallbackPolicy
{
    /// <summary>
    /// Extension client-metadata name (RFC 7591, section 2) carrying the
    /// registered fallback URL, both in registration payloads and in the
    /// management API.
    /// </summary>
    public const string MetadataName = "device_close_fallback_url";

    /// <summary>
    /// Key holding <see cref="MetadataName"/> in the client record property
    /// bag.
    /// </summary>
    public const string PropertyKey = "identity:client:device-close-fallback-url";

    /// <summary>
    /// Longest accepted URL. Bounded because the value is echoed into the
    /// approved terminal page and stored in the property bag read on device
    /// requests.
    /// </summary>
    public const int MaximumLength = 512;

    /// <summary>
    /// Validates a URL a client wants to register. On success
    /// <paramref name="normalized"/> carries the trimmed string to store.
    /// Only browser destinations apply: absolute https, no fragment (never
    /// sent to the server, so it cannot round-trip), no userinfo.
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
            reasonCode = "device_close_fallback_invalid";
            reasonMessage = "A device close fallback URL cannot be empty.";
            return false;
        }

        var trimmed = candidate.Trim();
        if (trimmed.Length > MaximumLength)
        {
            reasonCode = "device_close_fallback_too_long";
            reasonMessage =
                $"A device close fallback URL cannot exceed {MaximumLength} characters.";
            return false;
        }

        if (trimmed.Any(character => char.IsControl(character)
            || char.IsWhiteSpace(character)))
        {
            reasonCode = "device_close_fallback_invalid";
            reasonMessage =
                $"A device close fallback URL cannot contain whitespace or control characters: {trimmed}";
            return false;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            reasonCode = "device_close_fallback_https_required";
            reasonMessage =
                $"A device close fallback URL must be an absolute https URL: {trimmed}";
            return false;
        }

        if (uri.Fragment.Length > 0)
        {
            reasonCode = "device_close_fallback_fragment";
            reasonMessage =
                $"A device close fallback URL cannot contain a fragment: {trimmed}";
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            reasonCode = "device_close_fallback_userinfo";
            reasonMessage =
                $"A device close fallback URL cannot carry credentials: {trimmed}";
            return false;
        }

        normalized = trimmed;
        return true;
    }

    /// <summary>
    /// Reads the registered fallback URL out of a client property bag,
    /// returning <c>null</c> when nothing (or something that no longer
    /// satisfies the policy) is registered — a tightened rule retroactively
    /// disables a stale registration instead of trusting it.
    /// </summary>
    public static string? Read(IReadOnlyDictionary<string, JsonElement>? properties)
    {
        if (properties is null
            || !properties.TryGetValue(PropertyKey, out var value)
            || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        var url = value.GetString();
        return TryValidateRegistration(url, out var normalized, out _, out _)
            ? normalized
            : null;
    }
}

/// <summary>
/// Reads the close fallback URL a client registered with this deployment.
/// </summary>
public interface IClientDeviceCloseFallbackResolver
{
    /// <summary>
    /// The registered fallback URL for <paramref name="clientId"/>, or
    /// <c>null</c> when the client is unknown or registered none.
    /// </summary>
    Task<string?> ResolveAsync(
        string? clientId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Turns a fallback URL validated against a client registration into an
/// opaque, expiring ticket, and back.
/// </summary>
/// <remarks>
/// The approved terminal page is reached after a redirect that no longer
/// carries the device transaction, so it cannot re-check a raw URL against
/// the client record. Handing it a ticket the server minted keeps the
/// decision on the server — the page redirects only to a value this
/// deployment already accepted, and a tampered query string resolves to
/// nothing.
/// </remarks>
public interface IDeviceCloseFallbackTicketService
{
    /// <summary>Protects an already-validated URL for the browser round trip.</summary>
    string Protect(string url);

    /// <summary>
    /// Recovers the URL from a ticket, or <c>null</c> when the ticket is
    /// missing, tampered with or expired.
    /// </summary>
    string? Unprotect(string? ticket);
}
