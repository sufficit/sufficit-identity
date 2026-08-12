using System.Globalization;
using System.Resources;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Components;
using Sufficit.Identity.UI.Management.Resources;
using Xunit;
using ManagementUiResource =
    Sufficit.Identity.UI.Management.Resources.ManagementResource;

namespace Sufficit.Identity.Tests;

public sealed class ManagementCapabilityPresentationTests
{
    private static readonly ResourceManager Resources =
        new(typeof(ManagementUiResource));

    [Theory]
    [InlineData("pt-BR")]
    [InlineData("en-US")]
    public void Every_management_capability_has_complete_localized_help(
        string cultureName)
    {
        var culture = CultureInfo.GetCultureInfo(cultureName);

        foreach (var capability in ManagementCapabilities.All)
        {
            Assert.True(
                ManagementCapabilityPresentation.HasExplicitCopy(capability),
                $"Missing presentation mapping for {capability}.");

            var keys = ManagementCapabilityPresentation.GetResourceKeys(
                capability);
            var label = Required(keys.Label, culture);
            var title = Required(keys.Title, culture);
            var description = Required(keys.Description, culture);

            Assert.False(string.IsNullOrWhiteSpace(label));
            Assert.False(string.IsNullOrWhiteSpace(title));
            Assert.True(
                description.Length >= 90,
                $"Help text for {capability} in {cultureName} is too short.");
        }
    }

    [Theory]
    [InlineData("pt-BR", "Redefinir senha", "Informações sobre {0}")]
    [InlineData("en-US", "Reset password", "Information about {0}")]
    public void User_reset_and_accessible_label_are_localized(
        string cultureName,
        string expectedLabel,
        string expectedAriaTemplate)
    {
        var culture = CultureInfo.GetCultureInfo(cultureName);
        var keys = ManagementCapabilityPresentation.GetResourceKeys(
            ManagementCapabilities.UsersReset);

        Assert.Equal(expectedLabel, Required(keys.Label, culture));
        Assert.Equal(
            expectedAriaTemplate,
            Required("Capability.Help.AriaLabel", culture));
    }

    private static string Required(string key, CultureInfo culture) =>
        Resources.GetString(key, culture)
        ?? throw new InvalidOperationException(
            $"Missing Management resource '{key}' for {culture.Name}.");
}
