namespace Sufficit.Identity.UI.Abstractions.Hosting;

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
