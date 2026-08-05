using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class IntrospectionTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public IntrospectionTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Introspection_reports_the_token_active_and_surfaces_the_directive_claim()
    {
        // Dedicated, freshly-claimed user: keeps the `directive` value specific
        // to this test instead of relying on the shared seeded user.
        var username = $"introspect-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#3";
        const string directiveValue = "sufficit:test:introspect-directive";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password, directiveValue);
        }

        var client = _factory.CreateClient();

        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            // TestDataSeeder.ScopeName resources include the introspection
            // client, which is what makes it a trusted audience allowed to see
            // non-standard claims (e.g. `directive`) in the introspection
            // response below.
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);

        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        client.DefaultRequestHeaders.Authorization = BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);

        var (introspectStatus, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = accessToken!,
        });

        Assert.Equal(HttpStatusCode.OK, introspectStatus);
        Assert.True(introspectBody.GetProperty("active").GetBoolean());
        Assert.Equal(directiveValue, introspectBody.GetProperty(TestDataSeeder.DirectiveClaimType).GetString());
    }

    internal static AuthenticationHeaderValue BasicAuthFor(string clientId, string clientSecret) =>
        new("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes($"{clientId}:{clientSecret}")));
}
