using System.Net;
using System.Net.Http.Json;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DatabaseMonitoringControllerTests
{
    [Fact]
    public async Task Endpoint_returns_privacy_safe_runtime_snapshot()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var response = await client.GetAsync("/api/database/connections");
        var snapshot = await response.Content
            .ReadFromJsonAsync<DatabaseRuntimeSnapshot>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(snapshot);
        Assert.True(snapshot.CapturedAtUtc <= DateTimeOffset.UtcNow);
        Assert.DoesNotContain(
            "connectionString",
            await response.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }
}
