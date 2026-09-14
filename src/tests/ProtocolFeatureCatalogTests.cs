using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Features;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The STS protocol feature registry (A8): each feature owns its composition,
/// and the central composition files no longer test those features' options.
/// </summary>
public sealed class ProtocolFeatureCatalogTests
{
    private static readonly string[] CentralCompositionFiles =
    [
        "ServiceCollectionExtensions.cs",
        "ServiceCollectionExtensions.ProtocolFeatures.cs",
        "ServiceCollectionExtensions.Validation.cs",
        "OpenIddictServerConfiguration.cs",
        "OpenIddictServerConfiguration.Discovery.cs",
        "OpenIddictServerConfiguration.Credentials.cs",
        "RuntimeCapabilityCatalog.cs",
    ];

    private static readonly string[] MigratedFeatureOptions =
    [
        "options.Ciba.",
        "options.Jarm.",
        "options.SharedSignals.",
        "options.IdentityAssertions.",
        "options.BackchannelLogout.",
        "options.FrontchannelLogout.",
        "options.Dpop.",
        "options.Jar.",
        "options.Mtls.",
        "options.Fapi2.",
        "options.Mcp.Dcr.",
        "options.Mcp.ClientIdMetadataDocuments.",
    ];

    [Fact]
    public void Feature_names_are_unique()
    {
        var names = ProtocolFeatureCatalog.All.Select(feature => feature.Name).ToArray();
        Assert.Equal(names.Length, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Central_composition_files_leave_migrated_features_to_the_catalog()
    {
        var sts = Path.Combine(ResolveRepositoryRoot(), "src", "sts");
        foreach (var file in CentralCompositionFiles)
        {
            var text = File.ReadAllText(Path.Combine(sts, file));
            foreach (var option in MigratedFeatureOptions)
            {
                Assert.False(
                    text.Contains(option, StringComparison.Ordinal),
                    $"{file} tests {option} directly; move it into the feature under src/sts/Features.");
            }
        }
    }

    [Fact]
    public void Enablement_and_capabilities_follow_the_options()
    {
        var enabled = new SufficitIdentityOptions
        {
            Ciba = new CibaOptions { Enabled = true },
            Jarm = new JarmOptions { Enabled = true },
        };

        Assert.True(ProtocolFeatureCatalog.All.Single(f => f.Name == "ciba").IsEnabled(enabled));
        Assert.True(ProtocolFeatureCatalog.All.Single(f => f.Name == "jarm").IsEnabled(enabled));
        Assert.False(ProtocolFeatureCatalog.All.Single(f => f.Name == "shared-signals")
            .IsEnabled(new SufficitIdentityOptions()));
        Assert.Contains(
            Sufficit.Identity.Management.ManagementRuntimeCapabilities.Ciba,
            ProtocolFeatureCatalog.RuntimeCapabilities(enabled));
        Assert.Empty(ProtocolFeatureCatalog.RuntimeCapabilities(new SufficitIdentityOptions()));
    }

    [Fact]
    public void Feature_validation_still_rejects_invalid_options()
    {
        var invalid = new SufficitIdentityOptions
        {
            Jarm = new JarmOptions { Enabled = true, LifetimeSeconds = 0 },
        };

        Assert.Throws<InvalidOperationException>(() => ProtocolFeatureCatalog.Validate(invalid));
    }

    private static string ResolveRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
