using System.Diagnostics;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// identity.js shows constraint-validation messages under the field, in the
/// page language, instead of the browser bubble.
/// </summary>
public sealed class InlineValidationBrowserTests
{
    [Trait("Category", "BrowserHost")]
    [Fact]
    public async Task Invalid_fields_show_the_page_language_message_under_the_field()
    {
        var script = BrowserHostScript.Resolve("IDENTITY_VALIDATION_BROWSER_SCRIPT");
        if (string.IsNullOrWhiteSpace(script)) return;
        var identityJs = Path.GetFullPath(Path.Combine(
            Path.GetDirectoryName(script)!, "..", "src", "ui", "Sufficit.Identity.UI",
            "wwwroot", "js", "identity.js"));
        var start = new ProcessStartInfo("node") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(identityJs);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        Assert.True(process.ExitCode == 0, await stdout + "\n" + await stderr);
    }
}
