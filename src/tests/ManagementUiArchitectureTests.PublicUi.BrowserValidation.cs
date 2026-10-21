using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    // The browser writes constraint-validation messages in its own UI
    // language; the host page carries them in the selected culture and
    // identity.js swaps them in on "invalid".
    [Fact]
    public void Host_page_localizes_browser_validation_messages()
    {
        var ui = Path.Combine(
            ResolveIdentityRepository(), "src", "ui", "Sufficit.Identity.UI");
        var app = File.ReadAllText(Path.Combine(ui, "Components", "App.razor"));
        var script = File.ReadAllText(Path.Combine(ui, "wwwroot", "js", "identity.js"));

        Assert.Contains(
            "<meta name=\"sufficit-validation-messages\" content=\"@BrowserValidationMessages\" />",
            app,
            StringComparison.Ordinal);
        Assert.Contains(
            "meta[name=\"sufficit-validation-messages\"]",
            script,
            StringComparison.Ordinal);
        Assert.Contains("document.addEventListener('invalid'", script, StringComparison.Ordinal);

        var keys = Regex.Matches(app, "L\\[\"(Validation\\.Browser\\.[A-Za-z]+)\"\\]")
            .Select(match => match.Groups[1].Value)
            .ToArray();
        Assert.Contains("Validation.Browser.Required", keys);

        foreach (var resource in new[] { "SharedResource.resx", "SharedResource.pt-BR.resx" })
        {
            var values = XDocument.Load(Path.Combine(ui, "Resources", resource))
                .Root!
                .Elements("data")
                .ToDictionary(
                    data => (string)data.Attribute("name")!,
                    data => (string?)data.Element("value"));
            foreach (var key in keys)
            {
                Assert.True(
                    values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value),
                    $"{resource} lacks {key}");
            }
        }
    }
}
