namespace Sufficit.Identity.UI.Management.Components;

/// <summary>What <see cref="OneTimeTokenDialog"/> shows, already localized.</summary>
public sealed record OneTimeTokenRequest(
    string Token,
    string Description,
    string AriaLabel,
    string? ExpiresLabel = null,
    string? Detail = null);
