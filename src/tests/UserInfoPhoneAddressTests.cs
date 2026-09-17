using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Discovery advertises the address scope and (since the OpenID conformance
/// run of 2026-09-17) the phone scope; UserInfo has to answer both, or the
/// scope grants nothing at all. ASP.NET Core Identity stores the phone number;
/// the address is a persisted claim and is returned as the JSON object
/// OIDC Core 5.1.1 requires.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class UserInfoPhoneAddressTests
{
    private const string ClientId = "phone-address-client";
    private const string RedirectUri = "https://phone-address.example.invalid/callback";
    private const string PhoneNumber = "+554799999000";

    private readonly SufficitIdentityTestFactory _factory;

    public UserInfoPhoneAddressTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Theory]
    [InlineData("""{"formatted":"Rua Um, 100","locality":"Blumenau","country":"BR"}""", true)]
    [InlineData("Rua Um, 100 - Blumenau", false)]
    public async Task UserInfo_returns_phone_and_address_for_their_scopes(
        string storedAddress,
        bool structured)
    {
        var username = $"phone-address-{Guid.NewGuid():N}";
        using (var scope = _factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(
                users,
                username,
                TestDataSeeder.DefaultPassword);
            Assert.True((await users.SetPhoneNumberAsync(user, PhoneNumber)).Succeeded);
            user.PhoneNumberConfirmed = true;
            Assert.True((await users.UpdateAsync(user)).Succeeded);
            Assert.True((await users.AddClaimAsync(
                user,
                new Claim(Claims.Address, storedAddress))).Succeeded);

            await EnsureClientAsync(scope.ServiceProvider);
        }

        var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        using var authorize = await client.GetAsync(QueryHelpers.AddQueryString(
            "/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = ClientId,
                ["redirect_uri"] = RedirectUri,
                ["scope"] = "openid phone address",
                ["state"] = Guid.NewGuid().ToString("N"),
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            }));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var redirectQuery = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.False(redirectQuery.ContainsKey("error"), redirectQuery.ToString());

        var (tokenStatus, tokenBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = redirectQuery["code"].ToString(),
                ["redirect_uri"] = RedirectUri,
                ["client_id"] = ClientId,
                ["code_verifier"] = verifier,
            });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            tokenBody.GetProperty("access_token").GetString());
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var userinfo = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(PhoneNumber, userinfo.GetProperty("phone_number").GetString());
        Assert.True(userinfo.GetProperty("phone_number_verified").GetBoolean());

        var address = userinfo.GetProperty("address");
        Assert.Equal(JsonValueKind.Object, address.ValueKind);
        Assert.Equal(
            structured ? "Blumenau" : null,
            address.TryGetProperty("locality", out var locality)
                ? locality.GetString()
                : null);
        Assert.Equal(
            structured ? "Rua Um, 100" : storedAddress,
            address.GetProperty("formatted").GetString());
    }

    [Fact]
    public async Task Discovery_advertises_the_scopes_and_claims_it_answers()
    {
        var client = _factory.CreateClient();
        var discovery = await client.GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration");

        var scopes = discovery.GetProperty("scopes_supported")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToArray();
        var claims = discovery.GetProperty("claims_supported")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToArray();

        Assert.Contains(Scopes.Phone, scopes);
        Assert.Contains(Scopes.Address, scopes);
        Assert.Contains(Claims.PhoneNumber, claims);
        Assert.Contains(Claims.PhoneNumberVerified, claims);
        Assert.Contains(Claims.Address, claims);
    }

    private static async Task EnsureClientAsync(IServiceProvider services)
    {
        var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
        if (await applications.FindByClientIdAsync(ClientId) is not null)
        {
            return;
        }

        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = ClientId,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(RedirectUri) },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + Scopes.Phone,
                Permissions.Prefixes.Scope + Scopes.Address,
            },
            Requirements = { Requirements.Features.ProofKeyForCodeExchange },
        });
    }
}
