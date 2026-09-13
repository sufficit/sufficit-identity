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
        Assert.Equal(IdentityUiHostingMode.Embedded, options.Vault.Mode);
        Assert.True(options.Public.IsEmbedded);
        Assert.True(options.Management.IsEmbedded);
        Assert.True(options.Vault.IsEmbedded);
    }

    [Fact]
    public void Configuration_can_disable_each_surface_independently()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:UI:Public:Mode"] = "None",
                ["Sufficit:Identity:UI:Management:Mode"] = "Embedded",
                ["Sufficit:Identity:UI:Vault:Mode"] = "None",
            })
            .Build();

        var options = configuration
            .GetSection(IdentityUiHostingOptions.SectionName)
            .Get<IdentityUiHostingOptions>();

        Assert.NotNull(options);
        options.Validate();
        Assert.False(options.Public.IsEmbedded);
        Assert.True(options.Management.IsEmbedded);
        Assert.False(options.Vault.IsEmbedded);
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
        Assert.Equal(
            1,
            Count(program, "builder.Services.AddSufficitIdentityUI"));
        Assert.Equal(1, Count(program, "app.UseSufficitIdentityUI"));

        // The management console and the Vault UI are modules: each guards
        // its own enablement and registers and maps itself exactly once, and
        // the host neither registers nor maps them directly.
        var managementUiModule = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(), "src", "ui",
            "Sufficit.Identity.UI.Management", "ManagementUiIdentityModule.cs"));
        var vaultUiModule = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(), "src", "ui",
            "Sufficit.Identity.UI.Vault", "VaultUiIdentityModule.cs"));
        Assert.Contains("uiHostingOptions.Management.IsEmbedded", managementUiModule, StringComparison.Ordinal);
        Assert.Equal(1, Count(managementUiModule, "services.AddSufficitIdentityManagementUI"));
        Assert.Equal(1, Count(managementUiModule, "app.UseSufficitIdentityManagementUI"));
        Assert.Contains("Vault.IsEmbedded", vaultUiModule, StringComparison.Ordinal);
        Assert.Equal(1, Count(vaultUiModule, "services.AddSufficitIdentityVaultUI"));
        Assert.Equal(1, Count(vaultUiModule, "app.UseSufficitIdentityVaultUI"));
        Assert.Equal(0, Count(program, "AddSufficitIdentityManagementUI"));
        Assert.Equal(0, Count(program, "UseSufficitIdentityManagementUI"));
        Assert.Equal(0, Count(program, "AddSufficitIdentityVaultUI"));
        Assert.Equal(0, Count(program, "UseSufficitIdentityVaultUI"));
        Assert.Contains("new ManagementUiIdentityModule()", program, StringComparison.Ordinal);
        Assert.Contains("new VaultUiIdentityModule()", program, StringComparison.Ordinal);
        Assert.Contains(
            "context.User.Identity?.IsAuthenticated == true",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"/account/forgotpassword\"",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"/account/register\"",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            "context.Response.Redirect(\"/manage\")",
            program,
            StringComparison.Ordinal);
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
