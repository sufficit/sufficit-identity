using Sufficit.Blazor.UI.Components;

namespace Sufficit.Identity.UI.Management.Configuration;

/// <summary>
/// Temporary consumer-side adapter for domain helpers that still expose a
/// textual tone. New UI code should use <see cref="SUITone"/> directly.
/// </summary>
internal static class IdentitySuiTone
{
    public static SUITone From(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "success" => SUITone.Success,
        "warning" => SUITone.Warning,
        "danger" or "error" => SUITone.Danger,
        "info" => SUITone.Info,
        _ => SUITone.Neutral,
    };
}
