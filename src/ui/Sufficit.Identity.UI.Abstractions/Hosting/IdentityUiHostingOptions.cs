namespace Sufficit.Identity.UI.Abstractions.Hosting;

/// <summary>
/// Hosting modes that are operationally supported by the current runtime.
/// Remote is deliberately not exposed until its HTTP interaction contract is
/// implemented and conformance-tested.
/// </summary>
public enum IdentityUiHostingMode
{
    None = 0,
    Embedded = 1,
}

/// <summary>
/// Selects whether each independently deployable presentation surface is
/// composed into the current process.
/// </summary>
public sealed class IdentityUiHostingOptions
{
    public const string SectionName = "Sufficit:Identity:UI";

    public IdentityUiSurfaceHostingOptions Public { get; set; } = new();

    public IdentityUiSurfaceHostingOptions Management { get; set; } = new();

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(Public);
        ArgumentNullException.ThrowIfNull(Management);

        Public.Validate(nameof(Public));
        Management.Validate(nameof(Management));
    }
}

public sealed class IdentityUiSurfaceHostingOptions
{
    /// <summary>
    /// Embedded remains the compatibility default. None leaves the runtime
    /// surface unmapped so it can be hosted without a UI implementation.
    /// </summary>
    public IdentityUiHostingMode Mode { get; set; } =
        IdentityUiHostingMode.Embedded;

    public bool IsEmbedded => Mode == IdentityUiHostingMode.Embedded;

    internal void Validate(string surface)
    {
        if (!Enum.IsDefined(Mode))
        {
            throw new InvalidOperationException(
                $"{IdentityUiHostingOptions.SectionName}:{surface}:Mode " +
                $"contains the unsupported value '{Mode}'.");
        }
    }
}
