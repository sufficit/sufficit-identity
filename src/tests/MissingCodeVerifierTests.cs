using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// RFC 7636 section 4.6 compares the verifier with the stored challenge and
/// calls a mismatch invalid_grant; a request carrying no verifier cannot match
/// either. OpenIddict answered invalid_request, which the OpenID conformance
/// suite rejects (fapi2-...-ensure-pkce-code-verifier-required).
/// </summary>
[Collection(StsCollection.Name)]
public sealed class MissingCodeVerifierTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public MissingCodeVerifierTests(SufficitIdentityTestFactory factory) =>
        _factory = factory;

    [Fact]
    public async Task A_token_request_without_the_code_verifier_is_invalid_grant()
    {
        var username = $"pkce-missing-{Guid.NewGuid():N}";
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

        var (_, challenge) = Pkce.CreatePair();
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
                // code_verifier deliberately absent.
            });

        Assert.NotEqual(HttpStatusCode.OK, status);
        Assert.Equal(Errors.InvalidGrant, body.GetProperty("error").GetString());
    }
}
