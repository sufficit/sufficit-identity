using System.Net;
using System.Net.Http;
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
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", body);
    }

    [Fact]
    public async Task Health_liveness_endpoint_responds_to_head_for_haproxy()
    {
        // HAProxy uses "HEAD /health" for backend health checks. ASP.NET Core's
        // MapHealthChecks registers both GET and HEAD, so this must return 200
        // with an empty body (HEAD never has a body).
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, "/health"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, response.Content.Headers.ContentLength ?? 0);
    }

    [Fact]
    public async Task Health_ready_endpoint_responds_to_head_for_haproxy()
    {
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, "/health/ready"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
