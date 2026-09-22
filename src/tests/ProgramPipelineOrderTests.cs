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
        @"\bapp\.(?<name>(?:Use|Map)[A-Za-z]*(?:<[^>]+>)?)\(|(?<name>identityPipeline\.(?:ApplyStage|EnsureAllApplied))\(",
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
            // Module steps before authentication (public UI browser errors).
            "identityPipeline.ApplyStage",
            "UseAuthenticationExceptStaticAssets",
            "UseMiddleware<Sufficit.Identity.STS.MfaRecoveryNavigationMiddleware>",
            "UseAuthorization",
            "Use",
            "MapControllers",
            "MapHealthChecks",
            "MapHealthChecks",
            // Module endpoints in catalog order: management API, management
            // console, Vault UI, public UI (see
            // Module_endpoints_follow_the_catalog_order).
            "identityPipeline.ApplyStage",
            "identityPipeline.EnsureAllApplied",
        ],
            calls);
    }

    [Fact]
    public void Module_endpoints_follow_the_catalog_order()
    {
        var program = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(), "src", "server", "Program.cs"));

        var management = program.IndexOf("new ManagementIdentityModule()", StringComparison.Ordinal);
        var managementUi = program.IndexOf("new ManagementUiIdentityModule()", StringComparison.Ordinal);
        var vaultUi = program.IndexOf("new VaultUiIdentityModule()", StringComparison.Ordinal);
        var publicUi = program.IndexOf("new PublicUiIdentityModule()", StringComparison.Ordinal);
        var scim = program.IndexOf("new ScimIdentityModule()", StringComparison.Ordinal);

        // The public UI maps its Blazor endpoint after the other surfaces.
        Assert.True(management >= 0 && management < managementUi
            && managementUi < vaultUi && vaultUi < publicUi && publicUi < scim,
            "Modules must be listed as management API, management console, Vault UI, public UI, SCIM.");
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
