using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Trait("Category", "BrowserHost")]
    [Fact]
    public async Task One_time_token_dialog_browser_flow()
    {
        var script = BrowserHostScript.Resolve("IDENTITY_TOKEN_DIALOG_BROWSER_SCRIPT");
        if (string.IsNullOrWhiteSpace(script)) return;
        await using var app = await CreateHostAsync(
            useKestrel: true,
            services => services.AddSingleton<
                IProvisioningTokenManagementService,
                StubProvisioningTokenManagementService>());
        var start = new ProcessStartInfo("node") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(script);
        start.ArgumentList.Add(app.Urls.Single());
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        Assert.True(process.ExitCode == 0, await stdout + "\n" + await stderr);
    }

    private sealed class StubProvisioningTokenManagementService : IProvisioningTokenManagementService
    {
        public Task<ProvisioningTokenIssueResult> IssueAsync(
            ManagementRequestContext context,
            ProvisioningTokenIssueRequest? request = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ProvisioningTokenIssueResult(
                "stub-one-time-token-value",
                "Bearer",
                DateTimeOffset.UtcNow.AddMinutes(15),
                ["identity.provisioning"],
                ["identity.provisioning.preview", "identity.provisioning.apply"]));
    }
}
