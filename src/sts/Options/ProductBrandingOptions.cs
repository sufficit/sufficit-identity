namespace Sufficit.Identity.STS;

/// <summary>
/// Vendor-facing naming used in outbound messages
/// (<c>Sufficit:Identity:Branding</c>).
/// </summary>
/// <remarks>
/// This exists because a message subject is the one place a generic authorization
/// server leaks whose deployment it is. Hard-coding a company name there makes
/// the binary unusable by anyone else, so the name is configuration with a
/// deliberately neutral default.
/// </remarks>
public sealed class ProductBrandingOptions
{
    /// <summary>
    /// Product name shown to end users in email subjects and message bodies.
    /// </summary>
    public string ProductName { get; init; } = "Identity";
}
