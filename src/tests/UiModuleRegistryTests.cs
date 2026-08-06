using Sufficit.Identity.UI.Abstractions.Hosting;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Phase 2: UI module registry and composition validation tests.
/// </summary>
public sealed class UiModuleRegistryTests
{
    [Fact]
    public void Registry_accepts_distinct_modules()
    {
        var registry = new UiModuleRegistry();
        registry.Register(new UiModuleDescriptor("public-ui", UiSurface.Public, new Version(0, 4, 0), new Version(0, 4, 0)));
        registry.Register(new UiModuleDescriptor("management-ui", UiSurface.Management, new Version(0, 4, 0), new Version(0, 4, 0)));

        Assert.Equal(2, registry.Modules.Count);
        Assert.True(registry.HasSurface(UiSurface.Public));
        Assert.True(registry.HasSurface(UiSurface.Management));
    }

    [Fact]
    public void Registry_rejects_duplicate_module_id()
    {
        var registry = new UiModuleRegistry();
        registry.Register(new UiModuleDescriptor("public-ui", UiSurface.Public, new Version(0, 4, 0), new Version(0, 4, 0)));

        Assert.Throws<InvalidOperationException>(() =>
            registry.Register(new UiModuleDescriptor("public-ui", UiSurface.Public, new Version(0, 5, 0), new Version(0, 4, 0))));
    }

    [Fact]
    public void HasSurface_returns_false_for_unregistered_surface()
    {
        var registry = new UiModuleRegistry();
        registry.Register(new UiModuleDescriptor("public-ui", UiSurface.Public, new Version(0, 4, 0), new Version(0, 4, 0)));

        Assert.False(registry.HasSurface(UiSurface.Management));
    }
}
