namespace Sufficit.Blazor.UI.Themes;

public sealed class DefaultSUITheme : ISUITheme
{
    public static DefaultSUITheme Instance { get; } = new();

    public SUIPalette Palette => SUIPalette.Default;
    public SUITypography Typography => SUITypography.Default;
    public SUILayout Layout => SUILayout.Default;
    public bool IsDark => false;
}
