using Microsoft.Extensions.Configuration;
using Sufficit.Identity.Hosting;
using Sufficit.Identity.Management;
using Sufficit.Identity.Scim;
using Sufficit.Identity.Server;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A7: one binary, two planes. The profile narrows what the configuration
/// enables so the three nodes can share one settings file and still run
/// different processes — the unit chooses the profile, the settings say what
/// exists. A profile never turns a module on.
/// </summary>
public sealed class IdentityHostProfileTests
{
    [Fact]
    public void The_default_profile_composes_whatever_configuration_enables()
    {
        var catalog = Compose(IdentityHostProfile.All, EverythingEnabled());

        Assert.Contains(ManagementIdentityModule.ModuleId, Ids(catalog));
        Assert.Contains(ScimIdentityModule.ModuleId, Ids(catalog));
        Assert.Contains(PublicUiIdentityModule.ModuleId, Ids(catalog));
    }

    [Fact]
    public void The_sts_profile_drops_the_administration_plane()
    {
        var catalog = Compose(IdentityHostProfile.Sts, EverythingEnabled());

        var ids = Ids(catalog);
        Assert.Contains(PublicUiIdentityModule.ModuleId, ids);
        Assert.DoesNotContain(ManagementIdentityModule.ModuleId, ids);
        Assert.DoesNotContain(ManagementUiIdentityModule.ModuleId, ids);
        Assert.DoesNotContain(VaultUiIdentityModule.ModuleId, ids);
        Assert.DoesNotContain(ScimIdentityModule.ModuleId, ids);
    }

    [Fact]
    public void The_admin_profile_drops_the_public_sign_in_surface()
    {
        var catalog = Compose(IdentityHostProfile.Admin, EverythingEnabled());

        var ids = Ids(catalog);
        Assert.Contains(ManagementIdentityModule.ModuleId, ids);
        Assert.Contains(ScimIdentityModule.ModuleId, ids);
        Assert.DoesNotContain(PublicUiIdentityModule.ModuleId, ids);
    }

    [Fact]
    public void A_profile_never_enables_what_configuration_disabled()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Management:Enabled"] = "false",
                ["Sufficit:Identity:Scim:Enabled"] = "false",
            })
            .Build();

        var catalog = Compose(IdentityHostProfile.Admin, configuration);

        Assert.DoesNotContain(ManagementIdentityModule.ModuleId, Ids(catalog));
        Assert.DoesNotContain(ScimIdentityModule.ModuleId, Ids(catalog));
    }

    [Fact]
    public void What_the_profile_leaves_out_is_reportable()
    {
        var excluded = IdentityHostProfilePolicy.Excluded(
            IdentityHostProfile.Sts,
            [ManagementIdentityModule.ModuleId, PublicUiIdentityModule.ModuleId]);

        Assert.Equal([ManagementIdentityModule.ModuleId], excluded);
        Assert.Empty(IdentityHostProfilePolicy.Excluded(
            IdentityHostProfile.All,
            [ManagementIdentityModule.ModuleId]));
    }

    [Theory]
    [InlineData(null, IdentityHostProfile.All)]
    [InlineData("", IdentityHostProfile.All)]
    [InlineData("sts", IdentityHostProfile.Sts)]
    [InlineData("Admin", IdentityHostProfile.Admin)]
    public void The_profile_is_read_from_configuration(string? value, IdentityHostProfile expected)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [IdentityHostProfilePolicy.SettingName] = value,
            })
            .Build();

        Assert.Equal(expected, IdentityHostProfilePolicy.Resolve(configuration));
    }

    [Fact]
    public void An_unknown_profile_is_refused_by_name()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [IdentityHostProfilePolicy.SettingName] = "gateway",
            })
            .Build();

        var error = Assert.Throws<InvalidOperationException>(
            () => IdentityHostProfilePolicy.Resolve(configuration));
        Assert.Contains("gateway", error.Message, StringComparison.Ordinal);
    }

    private static IdentityModuleCatalog Compose(
        IdentityHostProfile profile,
        IConfiguration configuration) =>
        IdentityModuleCatalog.Create(
            configuration,
            IdentityHostProfilePolicy.AdmittedModules(profile),
            new ManagementIdentityModule(),
            new ManagementUiIdentityModule(),
            new VaultUiIdentityModule(),
            new PublicUiIdentityModule(),
            new ScimIdentityModule());

    private static IConfiguration EverythingEnabled() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Management:Enabled"] = "true",
                ["Sufficit:Identity:Scim:Enabled"] = "true",
            })
            .Build();

    private static string[] Ids(IdentityModuleCatalog catalog) =>
        catalog.Enabled.Select(module => module.Id).ToArray();
}
