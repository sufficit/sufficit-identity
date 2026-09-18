using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// RFC 6750 section 2.3 discourages carrying an access token in the query
/// string — the URL reaches proxy logs, browser history and the Referer header
/// — and FAPI 2.0 forbids it (conformance: DisallowAccessTokenInQuery).
/// </summary>
[Collection(StsCollection.Name)]
public sealed class UserInfoTransportTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public UserInfoTransportTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task UserInfo_refuses_an_access_token_in_the_query_string()
    {
        var accessToken = await IssueAccessTokenAsync();

        using var response = await _factory.CreateClient().GetAsync(
            QueryHelpers.AddQueryString(
                "/connect/userinfo",
                "access_token",
                accessToken));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task UserInfo_answers_the_same_token_in_the_authorization_header()
    {
        var accessToken = await IssueAccessTokenAsync();

        var client = _factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<string> IssueAccessTokenAsync()
    {
        var username = $"userinfo-transport-{Guid.NewGuid():N}";
        using (var scope = _factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(
                users,
                username,
                TestDataSeeder.DefaultPassword);
        }

        var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client,
            challenge,
            "openid profile");

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = verifier,
            });
        Assert.Equal(HttpStatusCode.OK, status);

        return body.GetProperty("access_token").GetString()!;
    }
}
