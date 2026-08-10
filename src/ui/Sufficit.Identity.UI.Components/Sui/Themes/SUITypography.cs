namespace Sufficit.Blazor.UI.Themes;

public sealed record SUITypography
{
    public string FontFamily { get; init; } =
        "-apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif";
    public string FontFamilyMono { get; init; } =
        "ui-monospace, SFMono-Regular, \"SF Mono\", Menlo, Consolas, monospace";
    public string FsH1 { get; init; } = "2.5rem";
    public string FsH2 { get; init; } = "2rem";
    public string FsH3 { get; init; } = "1.6rem";
    public string FsH4 { get; init; } = "1.35rem";
    public string FsH5 { get; init; } = "1.15rem";
    public string FsH6 { get; init; } = "1rem";
    public string FsSubtitle1 { get; init; } = "1rem";
    public string FsSubtitle2 { get; init; } = ".875rem";
    public string FsBody1 { get; init; } = "1rem";
    public string FsBody2 { get; init; } = ".875rem";
    public string FsButton { get; init; } = ".875rem";
    public string FsCaption { get; init; } = ".75rem";
    public string FsOverline { get; init; } = ".6875rem";

    public static SUITypography Default { get; } = new();
}
