using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    // These surfaces take every control from Sufficit.Blazor.UI: a raw
    // button, field, select or table brought back here would be styled by
    // the page instead of the library.
    [Theory]
    [InlineData("Pages", "ClientDraft.razor")]
    [InlineData("Pages", "ClientRegistrations.razor")]
    [InlineData("Pages", "Provisioning.razor")]
    [InlineData(null, "RegistrationTokenPanel.razor")]
    [InlineData(null, "OneTimeTokenDialog.razor")]
    public void Client_registration_and_provisioning_surfaces_use_only_sui_controls(string? folder, string file)
    {
        var components = Path.Combine(ResolveManagementUiSource(), "Components");
        var page = File.ReadAllText(folder is null
            ? Path.Combine(components, file)
            : Path.Combine(components, folder, file));

        Assert.DoesNotMatch(new Regex(@"<(button|input|select|textarea|table)\b", RegexOptions.IgnoreCase), page);
        Assert.DoesNotContain("class=\"button ", page, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"form-control", page, StringComparison.Ordinal);
        Assert.DoesNotContain("inline-notice", page, StringComparison.Ordinal);
    }
}
