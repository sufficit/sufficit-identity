using Microsoft.Extensions.Configuration;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityUiHostingOptionsTests
{
    [Fact]
    public void Embedded_is_the_compatible_default_for_both_surfaces()
    {
        var options = new IdentityUiHostingOptions();

        options.Validate();

        Assert.Equal(IdentityUiHostingMode.Embedded, options.Public.Mode);
        Assert.Equal(IdentityUiHostingMode.Embedded, options.Management.Mode);
        Assert.True(options.Public.IsEmbedded);
        Assert.True(options.Management.IsEmbedded);
    }

    [Fact]
    public void Configuration_can_disable_each_surface_independently()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:UI:Public:Mode"] = "None",
                ["Sufficit:Identity:UI:Management:Mode"] = "Embedded",
            })
            .Build();

        var options = configuration
            .GetSection(IdentityUiHostingOptions.SectionName)
            .Get<IdentityUiHostingOptions>();

        Assert.NotNull(options);
        options.Validate();
        Assert.False(options.Public.IsEmbedded);
        Assert.True(options.Management.IsEmbedded);
    }

    [Fact]
    public void Unsupported_numeric_modes_fail_closed()
    {
        var options = new IdentityUiHostingOptions
        {
            Public = new()
            {
                Mode = (IdentityUiHostingMode)999,
            },
        };

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.Contains(
            "Sufficit:Identity:UI:Public:Mode",
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Hosting_abstractions_have_no_runtime_or_ui_implementation_dependency()
    {
        var project = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "ui",
            "Sufficit.Identity.UI.Abstractions",
            "Sufficit.Identity.UI.Abstractions.csproj"));

        Assert.DoesNotContain("ProjectReference", project, StringComparison.Ordinal);
        Assert.DoesNotContain("PackageReference", project, StringComparison.Ordinal);
        Assert.DoesNotContain("OpenIddict", project, StringComparison.Ordinal);
        Assert.DoesNotContain("EntityFramework", project, StringComparison.Ordinal);
    }

    [Fact]
    public void Composition_host_guards_registration_and_mapping_by_surface_mode()
    {
        var program = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "server",
            "Program.cs"));

        Assert.Contains(
            "if (uiHostingOptions.Public.IsEmbedded)",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            "if (uiHostingOptions.Management.IsEmbedded)",
            program,
            StringComparison.Ordinal);
        Assert.Equal(
            1,
            Count(program, "builder.Services.AddSufficitIdentityUI"));
        Assert.Equal(1, Count(program, "app.UseSufficitIdentityUI"));
        Assert.Equal(
            1,
            Count(program, "builder.Services.AddSufficitIdentityManagementUI"));
        Assert.Equal(1, Count(program, "app.UseSufficitIdentityManagementUI"));
    }

    private static int Count(string source, string value)
    {
        var count = 0;
        var index = 0;
        while ((index = source.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }

        return count;
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null
               && !File.Exists(Path.Combine(
                   directory.FullName,
                   "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException(
                "Could not locate the Sufficit Identity repository root.");
    }
}

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
