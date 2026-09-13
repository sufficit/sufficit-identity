using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Grants;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Identity Assertion JWT Authorization Grant (ID-JAG) in both roles: issuing
/// a grant for a trusted authorization server, and redeeming a grant from a
/// trusted identity provider.
/// </summary>
public sealed class IdentityAssertionGrantTests
{
    private const string TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string ResourceServerIssuer = "https://ras.tests.example/";
    private const string TrustedIdpIssuer = "https://idp.tests.example/";
    private const string TrustedLoginProvider = "trusted-idp";

    private static readonly ECDsa IdpKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Discovery_advertises_both_roles_when_enabled()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();

        var metadata = await DiscoveryAsync(client);

        Assert.Equal(IdentityAssertionGrant.TokenType, metadata
            .GetProperty("identity_chaining_requested_token_types_supported")[0].GetString());
        Assert.Equal(IdentityAssertionGrant.GrantProfile, metadata
            .GetProperty("authorization_grant_profiles_supported")[0].GetString());
    }

    [Fact]
    public async Task Id_token_is_exchanged_for_a_grant_addressed_to_the_trusted_audience()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();
        var idToken = await IdTokenAsync(client);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["requested_token_type"] = IdentityAssertionGrant.TokenType,
            ["audience"] = "urn:tests:ras",
            ["scope"] = "chat.read",
            ["subject_token"] = idToken,
            ["subject_token_type"] = TokenTypeIdentifiers.IdentityToken,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(IdentityAssertionGrant.TokenType, body.GetProperty("issued_token_type").GetString());
        Assert.Equal("N_A", body.GetProperty("token_type").GetString());

        var grant = new JsonWebToken(body.GetProperty("access_token").GetString());
        Assert.Equal(IdentityAssertionGrant.JwtType, grant.Typ);
        Assert.Equal(ResourceServerIssuer, Assert.Single(grant.Audiences));
        Assert.Equal((await DiscoveryAsync(client)).GetProperty("issuer").GetString(), grant.Issuer);
        Assert.Equal("remote-client", grant.GetPayloadValue<string>("client_id"));
        Assert.Equal("chat.read", grant.GetPayloadValue<string>("scope"));
        Assert.Equal(await UserIdAsync(factory, TestDataSeeder.DefaultUsername), grant.Subject);
        Assert.False(string.IsNullOrEmpty(grant.Id));
    }

    [Fact]
    public async Task Untrusted_audience_is_rejected()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();

        var (status, body) = await RequestGrantAsync(client, await IdTokenAsync(client),
            TokenTypeIdentifiers.IdentityToken, "https://unknown.tests.example/",
            TestDataSeeder.PasswordClientId, TestDataSeeder.PasswordClientSecret);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_target", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Access_token_is_not_accepted_as_the_subject()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();
        var accessToken = (await PasswordTokenAsync(client, "openid " + TestDataSeeder.ScopeName))
            .GetProperty("access_token").GetString()!;

        var (status, body) = await RequestGrantAsync(client, accessToken,
            TokenTypeIdentifiers.AccessToken, ResourceServerIssuer,
            TestDataSeeder.PasswordClientId, TestDataSeeder.PasswordClientSecret);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Id_token_issued_to_another_client_is_rejected()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();

        var (status, body) = await RequestGrantAsync(client, await IdTokenAsync(client),
            TokenTypeIdentifiers.IdentityToken, ResourceServerIssuer,
            TestDataSeeder.TokenExchangeClientId, TestDataSeeder.TokenExchangeClientSecret);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Trusted_grant_is_redeemed_for_an_access_token_of_the_linked_user()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();
        var userId = await LinkExternalLoginAsync(factory, "U-1001");
        var issuer = (await DiscoveryAsync(client)).GetProperty("issuer").GetString()!;

        var (status, body) = await RedeemAsync(client,
            SignGrant(subject: "U-1001", audience: issuer, clientId: TestDataSeeder.ClientCredentialsClientId));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(body.TryGetProperty("refresh_token", out _));
        var introspection = await IntrospectAsync(factory, body.GetProperty("access_token").GetString()!);
        Assert.Equal(userId, introspection.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task Grant_for_another_audience_is_rejected()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();
        await LinkExternalLoginAsync(factory, "U-1002");

        var (status, body) = await RedeemAsync(client,
            SignGrant(subject: "U-1002", audience: "https://other.tests.example/",
                clientId: TestDataSeeder.ClientCredentialsClientId));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Grant_for_another_client_is_rejected()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();
        await LinkExternalLoginAsync(factory, "U-1003");
        var issuer = (await DiscoveryAsync(client)).GetProperty("issuer").GetString()!;

        var (status, body) = await RedeemAsync(client,
            SignGrant(subject: "U-1003", audience: issuer, clientId: "someone-else"));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Grant_for_an_unlinked_subject_is_rejected()
    {
        using var factory = await CreateFactoryAsync();
        var client = factory.CreateClient();
        var issuer = (await DiscoveryAsync(client)).GetProperty("issuer").GetString()!;

        var (status, body) = await RedeemAsync(client,
            SignGrant(subject: "not-linked", audience: issuer, clientId: TestDataSeeder.ClientCredentialsClientId));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    private static async Task<IdJagHost> CreateFactoryAsync()
    {
        var parent = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:IdentityAssertions:Issuance:Enabled"] = "true",
            ["Sufficit:Identity:IdentityAssertions:Issuance:Audiences:0:Issuer"] = ResourceServerIssuer,
            ["Sufficit:Identity:IdentityAssertions:Issuance:Audiences:0:Aliases:0"] = "urn:tests:ras",
            ["Sufficit:Identity:IdentityAssertions:Issuance:Audiences:0:ClientIdMap:" + TestDataSeeder.PasswordClientId] = "remote-client",
            ["Sufficit:Identity:IdentityAssertions:Redemption:Enabled"] = "true",
            ["Sufficit:Identity:IdentityAssertions:Redemption:TrustedIssuers:0:Issuer"] = TrustedIdpIssuer,
            ["Sufficit:Identity:IdentityAssertions:Redemption:TrustedIssuers:0:LoginProvider"] = TrustedLoginProvider,
        });
        await ((IAsyncLifetime)parent).InitializeAsync();
        var app = parent.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IIdentityAssertionKeyResolver>();
            services.AddSingleton<IIdentityAssertionKeyResolver>(new StaticKeyResolver());
        }));
        var host = new IdJagHost(parent, app);

        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        await AddPermissionAsync(applications, TestDataSeeder.PasswordClientId, Permissions.GrantTypes.TokenExchange);
        await AddPermissionAsync(applications, TestDataSeeder.PasswordClientId,
            Permissions.Prefixes.Audience + ResourceServerIssuer);
        await AddPermissionAsync(applications, TestDataSeeder.PasswordClientId,
            Permissions.Prefixes.Audience + "urn:tests:ras");
        await AddPermissionAsync(applications, TestDataSeeder.TokenExchangeClientId,
            Permissions.Prefixes.Audience + ResourceServerIssuer);
        await AddPermissionAsync(applications, TestDataSeeder.ClientCredentialsClientId,
            Permissions.Prefixes.GrantType + IdentityAssertionGrant.JwtBearerGrantType);
        return host;
    }

    /// <summary>
    /// The isolated factory seeds the database; the derived factory shares it
    /// and replaces the issuer key resolver with the test identity provider key.
    /// </summary>
    private sealed class IdJagHost(
        SufficitIdentityTestFactory parent,
        WebApplicationFactory<SufficitIdentityTestFactory> app) : IDisposable
    {
        public IServiceProvider Services => app.Services;

        public HttpClient CreateClient() => app.CreateClient();

        public void Dispose()
        {
            app.Dispose();
            parent.Dispose();
        }
    }

    private static async Task AddPermissionAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string permission)
    {
        var application = await applications.FindByClientIdAsync(clientId)
            ?? throw new InvalidOperationException($"Client '{clientId}' is missing.");
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application);
        descriptor.Permissions.Add(permission);
        await applications.UpdateAsync(application, descriptor);
    }

    private static async Task<JsonElement> DiscoveryAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/.well-known/openid-configuration");
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    private static async Task<JsonElement> PasswordTokenAsync(HttpClient client, string scope)
    {
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = scope,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        return body;
    }

    private static async Task<string> IdTokenAsync(HttpClient client) =>
        (await PasswordTokenAsync(client, "openid " + TestDataSeeder.ScopeName))
            .GetProperty("id_token").GetString()!;

    private static Task<(HttpStatusCode, JsonElement)> RequestGrantAsync(
        HttpClient client,
        string subjectToken,
        string subjectTokenType,
        string audience,
        string clientId,
        string clientSecret) =>
        client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrant,
            ["requested_token_type"] = IdentityAssertionGrant.TokenType,
            ["audience"] = audience,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = subjectTokenType,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
        });

    private static Task<(HttpStatusCode, JsonElement)> RedeemAsync(HttpClient client, string grant) =>
        client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = IdentityAssertionGrant.JwtBearerGrantType,
            ["assertion"] = grant,
            ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
            ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
        });

    private static string SignGrant(string subject, string audience, string clientId)
    {
        var now = DateTimeOffset.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            TokenType = IdentityAssertionGrant.JwtType,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(IdpKey) { KeyId = "idp-key" },
                SecurityAlgorithms.EcdsaSha256),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.AddMinutes(5).UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                ["iss"] = TrustedIdpIssuer,
                ["sub"] = subject,
                ["aud"] = audience,
                ["client_id"] = clientId,
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["scope"] = TestDataSeeder.ScopeName,
            },
        });
    }

    private static async Task<string> UserIdAsync(IdJagHost factory, string username)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        return (await users.FindByNameAsync(username))!.Id;
    }

    private static async Task<string> LinkExternalLoginAsync(
        IdJagHost factory,
        string providerKey)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(
            users, $"idjag-{Guid.NewGuid():N}", "Id-Jag!Passw0rd#31");
        Assert.True((await users.AddLoginAsync(user,
            new UserLoginInfo(TrustedLoginProvider, providerKey, "Trusted IdP"))).Succeeded);
        return user.Id;
    }

    private static async Task<JsonElement> IntrospectAsync(
        IdJagHost factory,
        string token)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (status, body) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = token,
        });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.True(body.GetProperty("active").GetBoolean());
        return body;
    }

    private sealed class StaticKeyResolver : IIdentityAssertionKeyResolver
    {
        public Task<IReadOnlyList<SecurityKey>> GetSigningKeysAsync(
            IdentityAssertionTrustedIssuer issuer,
            string? keyId,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SecurityKey>>(
                [new ECDsaSecurityKey(IdpKey) { KeyId = "idp-key" }]);
    }
}
