using System.Net;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class HealthTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public HealthTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Health_liveness_endpoint_returns_200_healthy()
    {
        // Rate limiting (30 req/min on POST /connect/token) is intentionally
        // NOT exercised here or anywhere else in this suite: driving the
        // fixed window to its limit would slow the whole run for a behavior
        // that's already a straightforward, already-reviewed configuration
        // (see Program.cs) rather than STS business logic.
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", body);
    }
}
