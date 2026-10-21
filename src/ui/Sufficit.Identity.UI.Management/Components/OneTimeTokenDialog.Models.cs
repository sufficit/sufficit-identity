namespace Sufficit.Identity.UI.Management.Components;

/// <summary>
/// What <see cref="OneTimeTokenDialog"/> shows, already localized: any value
/// shown once (token, client secret, service-account secret).
/// </summary>
public sealed record OneTimeTokenRequest(
    string Token,
    string Description,
    string AriaLabel,
    string? ExpiresLabel = null,
    string? Detail = null,
    string? CopyLabel = null);
