using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Pins the middleware and endpoint order of the composition host. Order in
/// this pipeline is a security property: forwarding must run before anything
/// reads the client address or scheme, CORS before authentication, and the
/// anonymous-only redirect after authentication. The module composition work
/// moves these calls around, so any reordering has to show up here first.
/// </summary>
public sealed class ProgramPipelineOrderTests
{
    private static readonly Regex PipelineCall = new(
        @"\bapp\.(?<name>(?:Use|Map)[A-Za-z]*(?:<[^>]+>)?)\(",
        RegexOptions.CultureInvariant);

    [Fact]
    public void Composition_host_keeps_the_established_pipeline_order()
    {
        var program = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(), "src", "server", "Program.cs"));

        var calls = PipelineCall.Matches(program)
            .Select(match => match.Groups["name"].Value)
            .ToArray();

        Assert.Equal(
        [
            "UseMtlsClientCertificateForwarding",
            "UseMiddleware<TrustedProxyForwardingMiddleware>",
            "UseHsts",
            "UseWhen",
            "UseSufficitSecurityHeaders",
            "UseRequestLocalization",
            "UseLowercasePaths",
            "UseRouting",
            "UseRateLimiter",
            "UseSufficitCors",
            "UseSwagger",
            "UseSwaggerUI",
            "UseBrowserAuthorizationErrors",
            "MapDeviceBrowserLaunch",
            "UseAuthenticationExceptStaticAssets",
            "UseAuthorization",
            "Use",
            "MapControllers",
            "MapHealthChecks",
            "MapHealthChecks",
            "UseSufficitIdentityManagementEndpoints",
            "UseSufficitIdentityManagementUI",
            "UseSufficitIdentityVaultUI",
            "UseSufficitIdentityUI",
        ],
            calls);
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Identity repository root was not found.");
    }
}
