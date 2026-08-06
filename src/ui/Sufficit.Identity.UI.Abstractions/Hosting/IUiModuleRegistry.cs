namespace Sufficit.Identity.UI.Abstractions.Hosting;

/// <summary>
/// Accumulates <see cref="UiModuleDescriptor"/>s during DI registration so the
/// host can validate the composition at startup. Each <c>AddSufficitIdentity*UI</c>
/// method registers its descriptor here.
/// </summary>
public interface IUiModuleRegistry
{
    /// <summary>Registers a module descriptor. Throws on duplicate Id.</summary>
    void Register(UiModuleDescriptor descriptor);

    /// <summary>All registered descriptors.</summary>
    IReadOnlyList<UiModuleDescriptor> Modules { get; }

    /// <summary>True if a module for the given surface has been registered.</summary>
    bool HasSurface(UiSurface surface);
}
