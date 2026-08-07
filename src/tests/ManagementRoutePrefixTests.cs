using System.Net;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementRoutePrefixTests
{
    [Fact]
    public async Task Configured_prefix_relocates_management_controllers()
    {
        using var factory = ManagementTestFactory.CreateWithRoutePrefix(
            "management-api");
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var configured = await client.GetAsync(
            "/management-api/overview");
        using var legacy = await client.GetAsync("/api/overview");

        Assert.NotEqual(HttpStatusCode.NotFound, configured.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, legacy.StatusCode);
    }
}
