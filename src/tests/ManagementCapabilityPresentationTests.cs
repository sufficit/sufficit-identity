using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Components;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementCapabilityPresentationTests
{
    [Fact]
    public void Every_management_capability_has_explicit_contextual_help()
    {
        foreach (var capability in ManagementCapabilities.All)
        {
            Assert.True(
                ManagementCapabilityPresentation.HasExplicitCopy(capability),
                $"Missing presentation for {capability}.");

            var copy = ManagementCapabilityPresentation.Get(capability);
            Assert.False(string.IsNullOrWhiteSpace(copy.Label));
            Assert.False(string.IsNullOrWhiteSpace(copy.HelpTitle));
            Assert.True(
                copy.HelpText.Length >= 100,
                $"Help text for {capability} is too short to explain its use.");
        }
    }

    [Fact]
    public void User_reset_uses_a_human_label_instead_of_the_identifier_suffix()
    {
        var copy = ManagementCapabilityPresentation.Get(
            ManagementCapabilities.UsersReset);

        Assert.Equal("Redefinir senha", copy.Label);
    }
}
