namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Transport for the per-request Content-Security-Policy nonce between the
/// module that emits the CSP header and the module that renders the HTML.
/// </summary>
/// <remarks>
/// The nonce is produced by the STS security-headers middleware and consumed by
/// whichever UI renders the host page. Passing it through the request item bag,
/// with the key and accessor defined in this dependency-free contract project,
/// keeps the UI from referencing the STS assembly just to read one string — the
/// same boundary discipline the rest of the composition follows.
/// <para>Declared as <c>IDictionary&lt;object, object?&gt;</c> rather than
/// <c>HttpContext</c> because this project deliberately carries no ASP.NET Core
/// framework reference; callers pass <c>HttpContext.Items</c>, which already has
/// that shape.</para>
/// </remarks>
public static class CspNonce
{
    /// <summary>Request-item key carrying the nonce for the current request.</summary>
    public const string ItemKey = "Sufficit.Identity.Csp.Nonce";

    /// <summary>
    /// Reads the nonce for the current request, or <c>null</c> when nonce-based
    /// CSP is disabled.
    /// </summary>
    /// <remarks>
    /// A null result is the normal disabled state, not an error: the emitted
    /// policy then still carries <c>'unsafe-inline'</c>, so a host page that
    /// omits the attribute renders correctly. Razor drops an attribute whose
    /// value is null, so <c>nonce="@CspNonce.From(...)"</c> is safe to write
    /// unconditionally.
    /// </remarks>
    public static string? From(IDictionary<object, object?>? items) =>
        items is not null && items.TryGetValue(ItemKey, out var value)
            ? value as string
            : null;
}
