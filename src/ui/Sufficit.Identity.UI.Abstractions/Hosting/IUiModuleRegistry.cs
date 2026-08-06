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

/// <summary>
/// Default <see cref="IUiModuleRegistry"/> implementation. Singleton — one
/// registry per host, accumulated during <c>ConfigureServices</c>.
/// </summary>
public sealed class UiModuleRegistry : IUiModuleRegistry
{
    private readonly List<UiModuleDescriptor> _modules = [];
    private readonly HashSet<string> _ids = new(StringComparer.Ordinal);

    public IReadOnlyList<UiModuleDescriptor> Modules => _modules;

    public void Register(UiModuleDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!_ids.Add(descriptor.Id))
        {
            throw new InvalidOperationException(
                $"UI module '{descriptor.Id}' is already registered. " +
                "Each UI module can only be composed once per host.");
        }
        _modules.Add(descriptor);
    }

    public bool HasSurface(UiSurface surface) =>
        _modules.Any(m => m.Surface == surface);
}

/// <summary>
/// Thrown when the UI composition is invalid at startup (duplicate module,
/// incompatible version, missing dependency, or surface requested without a
/// module).
/// </summary>
public sealed class UiCompositionException(string message) : Exception(message);
