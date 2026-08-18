using System.Net;
using System.Net.Http.Json;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class DeviceFlowCloseReportTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public DeviceFlowCloseReportTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task Authenticated_close_diagnostic_is_accepted()
    {
        using var client = _factory.CreateClient();
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);

        using var response = await client.PostAsJsonAsync(
            "/security/device-flow-close-report",
            new
            {
                @event = "script-close-attempted",
                strategy = "direct",
                reason = (string?)null,
                hasOpener = false,
                historyLength = 3,
                userActivation = true,
                visibility = "visible",
                persisted = (bool?)null
            });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Theory]
    [InlineData("attacker-controlled-event", "direct")]
    [InlineData("script-close-attempted", "javascript:payload")]
    public async Task Arbitrary_close_diagnostic_values_are_rejected(
        string eventName,
        string strategy)
    {
        using var client = _factory.CreateClient();
        await TestOnlyEndpoints.SignInAsync(client, TestDataSeeder.DefaultUsername);

        using var response = await client.PostAsJsonAsync(
            "/security/device-flow-close-report",
            new
            {
                @event = eventName,
                strategy,
                hasOpener = false,
                historyLength = 1,
                userActivation = true,
                visibility = "visible"
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_close_diagnostic_does_not_reach_the_log_endpoint()
    {
        using var client = _factory.CreateClient(new()
        {
            AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync(
            "/security/device-flow-close-report",
            new
            {
                @event = "script-close-attempted",
                strategy = "direct",
                hasOpener = false,
                historyLength = 1,
                userActivation = true,
                visibility = "visible"
            });

        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Redirect,
            $"Unexpected anonymous status code: {response.StatusCode}");
    }
}
