namespace Sufficit.Blazor.UI.Themes;

public interface ISUITheme
{
    SUIPalette Palette { get; }
    SUITypography Typography { get; }
    SUILayout Layout { get; }
    bool IsDark { get; }
}
