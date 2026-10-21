namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Browser-host checks run a Playwright script (scripts/*.mjs) against a
/// Kestrel host with fixture services. Locally they skip when the script
/// variable is unset; the CI browser job sets
/// IDENTITY_BROWSER_HOST_REQUIRED=true so a missing variable fails instead of
/// passing silently.
/// </summary>
public static class BrowserHostScript
{
    public static string? Resolve(string variable)
    {
        var script = Environment.GetEnvironmentVariable(variable);
        if (!string.IsNullOrWhiteSpace(script))
            return script;
        if (string.Equals(
                Environment.GetEnvironmentVariable("IDENTITY_BROWSER_HOST_REQUIRED"),
                "true",
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"{variable} is not set but browser-host checks are required.");
        return null;
    }
}
