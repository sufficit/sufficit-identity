using System.Net;
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
/// The openid scope is what makes a request an OpenID Connect request, and
/// OpenIddict never requires a scp:openid permission for it. Filtering it like
/// any other scope silently turned an OIDC request into a plain OAuth one: the
/// token response carried no id_token (OIDCC-3.1.3.3). Found by the OpenID
/// conformance suite (conformance/, oidcc-scope-profile).
/// </summary>
[Collection(StsCollection.Name)]
public sealed class OpenIdScopePermissionTests
{
    private const string ClientId = "openid-without-scope-permission";
    private const string RedirectUri = "https://client.example/openid-callback";

    private readonly SufficitIdentityTestFactory _factory;

    public OpenIdScopePermissionTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Openid_is_granted_to_a_client_without_an_openid_scope_permission()
    {
        var username = $"openid-scope-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#7";

        using (var scope = _factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(users, username, password);

            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            if (await applications.FindByClientIdAsync(ClientId) is null)
            {
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
                        // Deliberately no scp:openid.
                        Permissions.Prefixes.Scope + Scopes.Profile,
                    },
                    Requirements = { Requirements.Features.ProofKeyForCodeExchange },
                });
            }
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
                ["scope"] = "openid profile",
                ["state"] = Guid.NewGuid().ToString("N"),
                ["nonce"] = Guid.NewGuid().ToString("N"),
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            }));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var redirectQuery = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.False(redirectQuery.ContainsKey("error"), redirectQuery.ToString());

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = redirectQuery["code"].ToString(),
            ["redirect_uri"] = RedirectUri,
            ["client_id"] = ClientId,
            ["code_verifier"] = verifier,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains(
            Scopes.OpenId,
            body.GetProperty("scope").GetString()!.Split(' '),
            StringComparer.Ordinal);
        Assert.False(string.IsNullOrEmpty(body.GetProperty("id_token").GetString()));
    }
}
