namespace Sufficit.Blazor.UI.Themes;

public sealed record SUIPalette
{
    public string Primary { get; init; } = "#2563eb";
    public string PrimaryContrast { get; init; } = "#ffffff";
    public string PrimarySoft { get; init; } = "color-mix(in srgb, #2563eb 14%, transparent)";
    public string Secondary { get; init; } = "#64748b";
    public string SecondaryContrast { get; init; } = "#ffffff";
    public string Info { get; init; } = "#0ea5e9";
    public string Success { get; init; } = "#16a34a";
    public string Warning { get; init; } = "#d97706";
    public string Error { get; init; } = "#dc2626";
    public string Dark { get; init; } = "#1e293b";
    public string Light { get; init; } = "#f8fafc";
    public string Surface { get; init; } = "#ffffff";
    public string Surface2 { get; init; } = "#f1f5f9";
    public string Surface3 { get; init; } = "#e2e8f0";
    public string TextPrimary { get; init; } = "#0f172a";
    public string TextSecondary { get; init; } = "#475569";
    public string TextDisabled { get; init; } = "#94a3b8";
    public string Border { get; init; } = "#e2e8f0";
    public string BorderStrong { get; init; } = "#cbd5e1";
    public string Overlay { get; init; } = "rgba(15, 23, 42, .45)";

    public static SUIPalette Default { get; } = new();
}
