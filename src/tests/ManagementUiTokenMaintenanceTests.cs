using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Maintenance;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Fact]
    [Trait("Category", "BrowserHost")]
    public async Task Token_maintenance_browser_flow()
    {
        var script = BrowserHostScript.Resolve("IDENTITY_MAINTENANCE_BROWSER_SCRIPT");
        if (string.IsNullOrWhiteSpace(script)) return;
        await using var app = await CreateHostAsync(useKestrel: true,
            services => services.AddSingleton<ITokenMaintenanceManagementService, MaintenanceFixture>());
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

    private sealed class MaintenanceFixture : ITokenMaintenanceManagementService
    {
        private TokenMaintenanceOverview state = new(false, 30, 360, "initial", DateTime.UnixEpoch, false, null, []);
        public Task<TokenMaintenanceOverview> GetAsync(ManagementRequestContext context, CancellationToken ct = default) => Task.FromResult(state);
        public Task SaveAsync(SaveTokenMaintenance command, ManagementRequestContext context, CancellationToken ct = default)
        {
            if (command.Revision != state.Revision) throw new ManagementValidationException("maintenance_conflict", "Reload before saving.");
            state = state with { Enabled = command.Enabled, RetentionDays = command.RetentionDays,
                IntervalMinutes = command.IntervalMinutes, Revision = Guid.NewGuid().ToString("N") };
            return Task.CompletedTask;
        }
        public Task RequestRunAsync(string revision, ManagementRequestContext context, CancellationToken ct = default)
        {
            if (revision != state.Revision) throw new ManagementValidationException("maintenance_conflict", "Reload before saving.");
            state = state with { RunRequested = true, Revision = Guid.NewGuid().ToString("N"), Runs = [
                new("previous", DateTime.UtcNow.AddHours(-7), DateTime.UtcNow.AddHours(-6), "succeeded", 251, 1)] };
            return Task.CompletedTask;
        }
    }
}
