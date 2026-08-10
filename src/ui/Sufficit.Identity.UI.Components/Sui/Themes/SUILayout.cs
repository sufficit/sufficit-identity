namespace Sufficit.Blazor.UI.Themes;

public sealed record SUILayout
{
    public string RadiusSm { get; init; } = "4px";
    public string Radius { get; init; } = "8px";
    public string RadiusLg { get; init; } = "14px";
    public string RadiusFull { get; init; } = "9999px";
    public string Space1 { get; init; } = "4px";
    public string Space2 { get; init; } = "8px";
    public string Space3 { get; init; } = "12px";
    public string Space4 { get; init; } = "16px";
    public string Space5 { get; init; } = "24px";
    public string Space6 { get; init; } = "32px";
    public string Shadow1 { get; init; } = "0 1px 2px rgba(15,23,42,.06)";
    public string Shadow2 { get; init; } = "0 4px 10px rgba(15,23,42,.08)";
    public string Shadow3 { get; init; } = "0 12px 28px rgba(15,23,42,.14)";
    public string Transition { get; init; } = "160ms cubic-bezier(.4, 0, .2, 1)";
    public string TransitionSlow { get; init; } = "280ms cubic-bezier(.4, 0, .2, 1)";
    public string ControlHSm { get; init; } = "28px";
    public string ControlHMd { get; init; } = "36px";
    public string ControlHLg { get; init; } = "44px";
    public string ControlPxSm { get; init; } = "10px";
    public string ControlPxMd { get; init; } = "14px";
    public string ControlPxLg { get; init; } = "18px";

    public static SUILayout Default { get; } = new();
}
