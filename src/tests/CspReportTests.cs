using System.Net;
using System.Text;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class CspReportTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public CspReportTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Legacy_browser_report_is_accepted_without_authentication()
    {
        using var client = _factory.CreateClient();
        using var content = new StringContent(
            """
            {
              "csp-report": {
                "document-uri": "https://identity.tests.local/account/login?secret=value",
                "blocked-uri": "https://cdn.tests.local/script.js?token=secret",
                "effective-directive": "script-src-elem",
                "source-file": "https://identity.tests.local/app.js",
                "line-number": 42,
                "column-number": 7
              }
            }
            """,
            Encoding.UTF8,
            "application/csp-report");

        using var response = await client.PostAsync("/security/csp-report", content);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Invalid_report_is_rejected()
    {
        using var client = _factory.CreateClient();
        using var content = new StringContent(
            "{\"unexpected\":true}",
            Encoding.UTF8,
            "application/json");

        using var response = await client.PostAsync("/security/csp-report", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
