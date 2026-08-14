namespace Sufficit.Identity.Application.Branding;

/// <summary>
/// Immutable presentation projection of the active identity-provider theme.
/// Persistence identity and timestamps deliberately stay inside the runtime.
/// </summary>
/// <remarks>
/// <para>
/// <b>Render-safe by construction (eval 2026-08-14, finding F-1 / A1).</b>
/// Every URL- and color-bearing field is sanitized inside the constructor, so
/// NO construction path — the caching provider, a test stub, a future
/// composition host, or a hand-built record — can produce an instance that is
/// dangerous to render. Values that fail validation silently become
/// <see langword="null"/>, which the UI treats as "use the hardcoded default";
/// the management API already rejects these values at write time, so a null
/// here means the row was written outside the API (direct DB edit) and the
/// safe default is the correct degradation.
/// </para>
/// <para>
/// Validation mirrors, and is deliberately stricter than, the management-side
/// write validation: colors must be exact <c>#RRGGBB</c> hex; attribute URLs
/// (favicon/logo/header icon) accept absolute <c>http(s)</c> or a root-relative
/// path; the CSS background URL accepts absolute <c>https</c> or a
/// root-relative path (CSS <c>url()</c> contexts get no HTML-encoding help, so
/// plain-http is rejected there). Quotes, parentheses, backslashes, angle
/// brackets and control characters are rejected everywhere.
/// </para>
/// <para>
/// <see cref="AvatarUrlTemplate"/> is intentionally NOT sanitized here: it is
/// not a render value — it is consumed by <see cref="IUserAvatarUrlResolver"/>,
/// which validates it and URL-escapes the substituted user id before any
/// URL is produced. Text fields (<see cref="Name"/>, <see cref="Title"/>,
/// <see cref="BrandName"/>, <see cref="BrandSubtitle"/>) render as Razor text
/// nodes and rely on ordinary HTML encoding.
/// </para>
/// </remarks>
public sealed record BrandingTheme
{
    private static readonly System.Text.RegularExpressions.Regex HexColorRegex =
        new("^#[0-9a-fA-F]{6}$",
            System.Text.RegularExpressions.RegexOptions.Compiled
            | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    // Characters that can escape a CSS url("...") token, break out of an HTML
    // attribute even after encoding edge cases, or smuggle a header into the
    // response: quotes, parens, backslash, angle brackets, CR/LF and all
    // other C0 controls.
    private static readonly char[] ForbiddenUrlCharacters =
        ['"', '\'', '\\', '(', ')', '<', '>'];

    public BrandingTheme(
        string name,
        string? logoUrl,
        string? faviconUrl,
        string? headerIconUrl,
        string? backgroundImageUrl,
        string? brandColor,
        string? brandHoverColor,
        string? brandSoftColor,
        string? themeColor,
        string? title,
        string? brandName,
        string? brandSubtitle,
        string? avatarUrlTemplate)
    {
        Name = name;
        LogoUrl = SafeAttributeUrl(logoUrl);
        FaviconUrl = SafeAttributeUrl(faviconUrl);
        HeaderIconUrl = SafeAttributeUrl(headerIconUrl);
        BackgroundImageUrl = SafeCssUrl(backgroundImageUrl);
        BrandColor = SafeHexColor(brandColor);
        BrandHoverColor = SafeHexColor(brandHoverColor);
        BrandSoftColor = SafeHexColor(brandSoftColor);
        ThemeColor = SafeHexColor(themeColor);
        Title = title;
        BrandName = brandName;
        BrandSubtitle = brandSubtitle;
        AvatarUrlTemplate = avatarUrlTemplate;
    }

    public string Name { get; }

    public string? LogoUrl { get; }

    public string? FaviconUrl { get; }

    public string? HeaderIconUrl { get; }

    public string? BackgroundImageUrl { get; }

    public string? BrandColor { get; }

    public string? BrandHoverColor { get; }

    public string? BrandSoftColor { get; }

    public string? ThemeColor { get; }

    public string? Title { get; }

    public string? BrandName { get; }

    public string? BrandSubtitle { get; }

    public string? AvatarUrlTemplate { get; }

    private static string? SafeHexColor(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && HexColorRegex.IsMatch(value)
            ? value
            : null;

    private static string? SafeAttributeUrl(string? value) =>
        SafeUrl(value, allowHttp: true);

    private static string? SafeCssUrl(string? value) =>
        SafeUrl(value, allowHttp: false);

    private static string? SafeUrl(string? value, bool allowHttp)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        foreach (var character in value)
        {
            if (char.IsControl(character)
                || ForbiddenUrlCharacters.Contains(character))
            {
                return null;
            }
        }

        // Uri.TryCreate treats "/path" as an implicit file:// absolute URI, so
        // a successful parse with a non-http(s) scheme must FALL THROUGH to the
        // root-relative branch instead of being rejected outright — otherwise
        // every root-relative theme asset would be silently dropped.
        if (Uri.TryCreate(value, UriKind.Absolute, out var absolute)
            && (absolute.Scheme == Uri.UriSchemeHttps
                || (allowHttp && absolute.Scheme == Uri.UriSchemeHttp)))
        {
            return absolute.AbsoluteUri;
        }

        // Root-relative paths only. Protocol-relative ("//host") is rejected:
        // it inherits the page scheme and is a classic exfiltration vector.
        return value[0] == '/'
            && !value.StartsWith("//", StringComparison.Ordinal)
                ? value
                : null;
    }
}

/// <summary>
/// Provides the runtime-owned active theme to presentation adapters.
/// </summary>
public interface IBrandingThemeProvider
{
    Task<BrandingTheme?> GetActiveAsync(
        CancellationToken cancellationToken = default);

    void Invalidate();
}

/// <summary>
/// Resolves a user's avatar URL without exposing theme persistence or template
/// substitution to a UI.
/// </summary>
public interface IUserAvatarUrlResolver
{
    Task<string?> ResolveAsync(
        string? userId,
        CancellationToken cancellationToken = default);
}
