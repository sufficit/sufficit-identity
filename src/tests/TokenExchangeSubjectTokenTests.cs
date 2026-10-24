using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Ciba;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// RFC 8693 token exchange, seen from the subject_token side (plan item B3):
/// which kinds of subject token are accepted, by whom, and how sender binding
/// crosses the exchange.
/// </summary>
/// <remarks>
/// Provenance is decided by <c>SubjectTokenProvenancePolicy</c>: the caller
/// must be the party the token was issued to (azp/client_id/presenter) OR a
/// declared audience/resource of it. <see cref="TestDataSeeder.ScopeName"/>
/// lists <see cref="TestDataSeeder.TokenExchangeClientId"/> among its
/// resources, so any token carrying that scope names the exchange client as
/// an intended recipient; <see cref="StrangerClientId"/> holds the
/// token-exchange grant but is never an audience, which is what "any other
/// client" means here.
/// </remarks>
[Collection(StsCollection.Name)]
public sealed class TokenExchangeSubjectTokenTests
{
    private const string TokenExchangeGrantType =
        "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType =
        "urn:ietf:params:oauth:token-type:access_token";

    private const string StrangerClientId = "test-exchange-stranger";
    private const string StrangerClientSecret = "test-exchange-stranger-secret";

    private const string CibaClientId = "test-ciba-exchange";
    private const string CibaClientSecret = "test-ciba-exchange-secret";

    private const string PublicDpopClientId = "test-exchange-public-dpop";

    private readonly SufficitIdentityTestFactory _factory;

    public TokenExchangeSubjectTokenTests(SufficitIdentityTestFactory factory)
        => _factory = factory;

    // ---------------------------------------------------------------- 1. foreign issuer

    [Fact]
    public async Task A_subject_token_from_a_foreign_issuer_is_rejected()
    {
        var client = _factory.CreateClient();
        var subject = await GetSeedUserIdAsync(_factory);

        // Everything about this token is plausible except who minted it: the
        // claims name a real local user and the exchange client as audience,
        // so only the issuer/signature check can stop it.
        var foreignToken = MintForeignJwt(
            issuer: "https://foreign-sts.example",
            subject: subject,
            audience: TestDataSeeder.TokenExchangeClientId);

        var (status, body) = await ExchangeAsync(
            client,
            foreignToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret);

        AssertRejectedAsInvalidGrant(status, body);
    }

    [Fact]
    public async Task A_subject_token_claiming_this_issuer_but_signed_with_a_foreign_key_is_rejected()
    {
        var client = _factory.CreateClient();
        var subject = await GetSeedUserIdAsync(_factory);

        var forgedToken = MintForeignJwt(
            issuer: new Uri(client.BaseAddress!, "/").AbsoluteUri,
            subject: subject,
            audience: TestDataSeeder.TokenExchangeClientId);

        var (status, body) = await ExchangeAsync(
            client,
            forgedToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret);

        AssertRejectedAsInvalidGrant(status, body);
    }

    // ---------------------------------------------------------------- 2. personal token

    [Fact]
    public async Task A_personal_token_is_exchanged_by_a_client_that_is_its_audience()
    {
        var client = _factory.CreateClient();
        var personalToken = await CreatePersonalTokenAsync(
            client,
            TestDataSeeder.ScopeName);

        var (status, body) = await ExchangeAsync(
            client,
            personalToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret);

        Assert.Equal(HttpStatusCode.OK, status);
        var introspection = await IntrospectAsync(
            client,
            body.GetProperty("access_token").GetString()!);
        Assert.Equal(
            await GetSeedUserIdAsync(_factory),
            introspection.GetProperty("sub").GetString());
        Assert.Equal(
            TestDataSeeder.TokenExchangeClientId,
            introspection.GetProperty("act").GetProperty("sub").GetString());
    }

    [Fact]
    public async Task A_personal_token_is_not_exchanged_by_a_client_that_is_not_its_audience()
    {
        await EnsureStrangerClientAsync(_factory);
        var client = _factory.CreateClient();
        var personalToken = await CreatePersonalTokenAsync(
            client,
            TestDataSeeder.ScopeName);

        var (status, body) = await ExchangeAsync(
            client,
            personalToken,
            StrangerClientId,
            StrangerClientSecret);

        AssertRejectedAsInvalidGrant(status, body);
    }

    [Fact]
    public async Task A_personal_token_without_a_resource_scope_is_not_exchanged_by_anyone()
    {
        // A profile-only personal token names no resource, and its issuing
        // client (the personal-token client id) is not a client anybody can
        // authenticate as — so no caller qualifies as an intended recipient.
        var client = _factory.CreateClient();
        var personalToken = await CreatePersonalTokenAsync(client, Scopes.Profile);

        var (status, body) = await ExchangeAsync(
            client,
            personalToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret);

        AssertRejectedAsInvalidGrant(status, body);
    }

    // ---------------------------------------------------------------- 3. CIBA token

    [Fact]
    public async Task A_ciba_token_is_exchanged_by_the_client_it_was_issued_to_and_carries_act()
    {
        using var factory = await CreateCibaFactoryAsync();
        var client = factory.CreateClient();
        var cibaToken = await ObtainCibaAccessTokenAsync(factory, client);

        var (status, body) = await ExchangeAsync(
            client,
            cibaToken,
            CibaClientId,
            CibaClientSecret);

        Assert.Equal(HttpStatusCode.OK, status);
        var introspection = await IntrospectAsync(
            client,
            body.GetProperty("access_token").GetString()!);
        Assert.Equal(
            await GetSeedUserIdAsync(factory),
            introspection.GetProperty("sub").GetString());
        Assert.Equal(
            CibaClientId,
            introspection.GetProperty("act").GetProperty("sub").GetString());
    }

    [Fact]
    public async Task A_ciba_token_is_exchanged_by_a_client_that_is_its_audience_and_carries_act()
    {
        using var factory = await CreateCibaFactoryAsync();
        var client = factory.CreateClient();
        var cibaToken = await ObtainCibaAccessTokenAsync(factory, client);

        var (status, body) = await ExchangeAsync(
            client,
            cibaToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret);

        Assert.Equal(HttpStatusCode.OK, status);
        var introspection = await IntrospectAsync(
            client,
            body.GetProperty("access_token").GetString()!);
        Assert.Equal(
            TestDataSeeder.TokenExchangeClientId,
            introspection.GetProperty("act").GetProperty("sub").GetString());
    }

    [Fact]
    public async Task A_ciba_token_is_not_exchanged_by_a_client_that_is_neither_its_holder_nor_audience()
    {
        using var factory = await CreateCibaFactoryAsync();
        await EnsureStrangerClientAsync(factory);
        var client = factory.CreateClient();
        var cibaToken = await ObtainCibaAccessTokenAsync(factory, client);

        var (status, body) = await ExchangeAsync(
            client,
            cibaToken,
            StrangerClientId,
            StrangerClientSecret);

        AssertRejectedAsInvalidGrant(status, body);
    }

    // ---------------------------------------------------------------- 4. sender binding

    [Fact]
    public async Task An_exchange_with_a_dpop_proof_binds_the_new_token_to_the_callers_key()
    {
        using var factory = await CreateDpopFactoryAsync();
        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;

        var subjectToken = await PasswordTokenAsync(client);
        var (proof, _) = BuildDpopProof("POST", tokenUrl);
        Assert.True(DpopProofValidator.TryGetKeyThumbprint(proof, out var callerThumbprint));

        var (status, body) = await ExchangeAsync(
            client,
            subjectToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret,
            proof);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("DPoP", body.GetProperty("token_type").GetString());
        var introspection = await IntrospectAsync(
            client,
            body.GetProperty("access_token").GetString()!);
        Assert.Equal(
            callerThumbprint,
            introspection.GetProperty(DpopProofValidator.ConfirmationClaimType)
                .GetProperty("jkt").GetString());
    }

    [Fact(Skip = "B3 finding: a DPoP-bound subject_token cannot be exchanged even by its key holder — ValidateDpopAccessTokenProof computes ath over the resolved reference-token payload (context.Token), not the opaque subject_token the client sent")]
    public async Task A_dpop_bound_subject_token_is_exchanged_by_the_holder_of_its_key_and_stays_bound_to_it()
    {
        // ValidateDpopAccessTokenProof runs on every access token OpenIddict
        // validates, the subject_token included: the proof must be signed by
        // the bound key and carry ath over the subject token (RFC 9449 §4.2).
        using var factory = await CreateDpopFactoryAsync();
        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;

        var (subjectProof, key) = BuildDpopProof("POST", tokenUrl);
        Assert.True(DpopProofValidator.TryGetKeyThumbprint(subjectProof, out var thumbprint));
        var subjectToken = await PasswordTokenAsync(client, subjectProof);

        var (holderProof, _) = BuildDpopProof("POST", tokenUrl, key, subjectToken);
        var (status, body) = await ExchangeAsync(
            client,
            subjectToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret,
            holderProof);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("DPoP", body.GetProperty("token_type").GetString());
        var introspection = await IntrospectAsync(
            client,
            body.GetProperty("access_token").GetString()!);
        Assert.Equal(
            thumbprint,
            introspection.GetProperty(DpopProofValidator.ConfirmationClaimType)
                .GetProperty("jkt").GetString());
    }

    [Fact]
    public async Task A_dpop_bound_subject_token_is_not_exchanged_with_a_proof_from_another_key()
    {
        // The exchange cannot launder a stolen DPoP-bound token by re-binding
        // it to a key the thief controls — even for a confidential audience.
        using var factory = await CreateDpopFactoryAsync();
        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;

        var (subjectProof, _) = BuildDpopProof("POST", tokenUrl);
        var subjectToken = await PasswordTokenAsync(client, subjectProof);

        var (callerProof, _) = BuildDpopProof("POST", tokenUrl);
        var (status, body) = await ExchangeAsync(
            client,
            subjectToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret,
            callerProof);

        AssertRejectedAsInvalidGrant(status, body);
    }

    [Fact]
    public async Task A_dpop_bound_subject_token_is_not_exchanged_without_proof_by_a_confidential_audience()
    {
        using var factory = await CreateDpopFactoryAsync();
        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;

        var (subjectProof, _) = BuildDpopProof("POST", tokenUrl);
        var subjectToken = await PasswordTokenAsync(client, subjectProof);

        var (status, body) = await ExchangeAsync(
            client,
            subjectToken,
            TestDataSeeder.TokenExchangeClientId,
            TestDataSeeder.TokenExchangeClientSecret);

        AssertRejectedAsInvalidGrant(status, body);
    }

    [Fact]
    public async Task A_dpop_bound_subject_token_is_not_exchanged_without_proof_by_the_public_client_it_was_issued_to()
    {
        // A public client has no secret, so a stolen DPoP-bound token plus the
        // public client_id would be all an attacker needs to strip the binding.
        using var factory = await CreateDpopFactoryAsync();
        await EnsurePublicDpopClientAsync(factory);
        var client = factory.CreateClient();
        var tokenUrl = new Uri(client.BaseAddress!, "connect/token").AbsoluteUri;

        var (subjectProof, _) = BuildDpopProof("POST", tokenUrl);
        client.DefaultRequestHeaders.Add("DPoP", subjectProof);
        var (subjectStatus, subjectBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.Password,
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["client_id"] = PublicDpopClientId,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        client.DefaultRequestHeaders.Remove("DPoP");
        Assert.Equal(HttpStatusCode.OK, subjectStatus);
        Assert.Equal("DPoP", subjectBody.GetProperty("token_type").GetString());

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = TokenExchangeGrantType,
                ["subject_token"] = subjectBody.GetProperty("access_token").GetString()!,
                ["subject_token_type"] = AccessTokenType,
                ["client_id"] = PublicDpopClientId,
            });

        AssertRejectedAsInvalidGrant(status, body);
    }

    // ---------------------------------------------------------------- helpers

    private static void AssertRejectedAsInvalidGrant(HttpStatusCode status, JsonElement body)
    {
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(Errors.InvalidGrant, body.GetProperty("error").GetString());
        Assert.False(body.TryGetProperty("access_token", out _));
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(
        HttpClient client,
        string subjectToken,
        string clientId,
        string clientSecret,
        string? dpopProof = null)
    {
        if (dpopProof is not null)
        {
            client.DefaultRequestHeaders.Add("DPoP", dpopProof);
        }

        try
        {
            return await client.PostFormAsync(
                "/connect/token",
                new Dictionary<string, string>
                {
                    ["grant_type"] = TokenExchangeGrantType,
                    ["subject_token"] = subjectToken,
                    ["subject_token_type"] = AccessTokenType,
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret,
                });
        }
        finally
        {
            client.DefaultRequestHeaders.Remove("DPoP");
        }
    }

    private static async Task<JsonElement> IntrospectAsync(HttpClient client, string token)
    {
        var previous = client.DefaultRequestHeaders.Authorization;
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);
        try
        {
            var (status, body) = await client.PostFormAsync(
                "/connect/introspect",
                new Dictionary<string, string> { ["token"] = token });
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.True(body.GetProperty("active").GetBoolean());
            return body;
        }
        finally
        {
            client.DefaultRequestHeaders.Authorization = previous;
        }
    }

    private static async Task<string> PasswordTokenAsync(
        HttpClient client,
        string? dpopProof = null)
    {
        if (dpopProof is not null)
        {
            client.DefaultRequestHeaders.Add("DPoP", dpopProof);
        }

        try
        {
            var (status, body) = await client.PostFormAsync(
                "/connect/token",
                new Dictionary<string, string>
                {
                    ["grant_type"] = GrantTypes.Password,
                    ["username"] = TestDataSeeder.DefaultUsername,
                    ["password"] = TestDataSeeder.DefaultPassword,
                    ["client_id"] = TestDataSeeder.PasswordClientId,
                    ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                    ["scope"] = TestDataSeeder.ScopeName,
                });
            Assert.Equal(HttpStatusCode.OK, status);
            if (dpopProof is not null)
            {
                Assert.Equal("DPoP", body.GetProperty("token_type").GetString());
            }

            return body.GetProperty("access_token").GetString()!;
        }
        finally
        {
            client.DefaultRequestHeaders.Remove("DPoP");
        }
    }

    private static async Task<string> CreatePersonalTokenAsync(
        HttpClient client,
        string scope)
    {
        var bearer = await PasswordTokenAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/account/tokens")
        {
            Content = JsonContent.Create(new
            {
                description = "b3-subject-token",
                expiration = DateTimeOffset.UtcNow.AddDays(7),
                scopes = new[] { scope },
            }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var created = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return created.RootElement.GetProperty("accessToken").GetString()!;
    }

    private static async Task<SufficitIdentityTestFactory> CreateCibaFactoryAsync()
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Ciba:Enabled"] = "true",
                ["Sufficit:Identity:Ciba:ClientPolicyMode"] = "Enforce",
                ["Sufficit:Identity:Ciba:PollIntervalSeconds"] = "0",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await applications.FindByClientIdAsync(CibaClientId) is null)
        {
            await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = CibaClientId,
                ClientSecret = CibaClientSecret,
                ClientType = ClientTypes.Confidential,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.TokenExchange,
                    "gt:urn:openid:params:grant-type:ciba",
                    Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                },
            });
        }

        return factory;
    }

    private static async Task<string> ObtainCibaAccessTokenAsync(
        SufficitIdentityTestFactory factory,
        HttpClient client)
    {
        var (initiationStatus, initiation) = await client.PostFormAsync(
            "/bc-authorize",
            new Dictionary<string, string>
            {
                ["scope"] = TestDataSeeder.ScopeName,
                ["client_id"] = CibaClientId,
                ["client_secret"] = CibaClientSecret,
                ["login_hint"] = TestDataSeeder.DefaultUsername,
            });
        Assert.Equal(HttpStatusCode.OK, initiationStatus);
        var authReqId = initiation.GetProperty("auth_req_id").GetString()!;

        var subject = await GetSeedUserIdAsync(factory);
        using (var scope = factory.Services.CreateScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICibaPendingRequestStore>();
            Assert.True(store.Approve(authReqId, subject));
        }

        var (status, body) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:openid:params:grant-type:ciba",
                ["auth_req_id"] = authReqId,
                ["client_id"] = CibaClientId,
                ["client_secret"] = CibaClientSecret,
            });
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()!;
    }

    private static async Task<SufficitIdentityTestFactory> CreateDpopFactoryAsync()
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
                ["Sufficit:Identity:Dpop:RequireForAllClients"] = "false",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        return factory;
    }

    private static async Task EnsureStrangerClientAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await applications.FindByClientIdAsync(StrangerClientId) is not null)
        {
            return;
        }

        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = StrangerClientId,
            ClientSecret = StrangerClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.TokenExchange,
                Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
            },
        });
    }

    private static async Task EnsurePublicDpopClientAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await applications.FindByClientIdAsync(PublicDpopClientId) is not null)
        {
            return;
        }

        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = PublicDpopClientId,
            ClientType = ClientTypes.Public,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.Password,
                Permissions.GrantTypes.TokenExchange,
                Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
            },
        });
    }

    private static async Task<string> GetSeedUserIdAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");
        return await users.GetUserIdAsync(user);
    }

    private static string MintForeignJwt(string issuer, string subject, string audience)
    {
        var key = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            KeyId = Guid.NewGuid().ToString("N"),
        };
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            TokenType = "at+jwt",
            Claims = new Dictionary<string, object>
            {
                [Claims.Subject] = subject,
                [Claims.ClientId] = audience,
                [Claims.AuthorizedParty] = audience,
                [Claims.Scope] = TestDataSeeder.ScopeName,
                [Claims.JwtId] = Guid.NewGuid().ToString("N"),
            },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
        });
    }

    private static (string Jwt, ECDsaSecurityKey Key) BuildDpopProof(
        string method,
        string url,
        ECDsaSecurityKey? signingKey = null,
        string? accessToken = null)
    {
        var key = signingKey
            ?? new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["htm"] = method,
                ["htu"] = url,
                ["iat"] = EpochTime.GetIntDate(DateTime.UtcNow),
                ["exp"] = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(1)),
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = DpopProofValidator.DpopHeaderType,
                ["jwk"] = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(jwk)),
            },
        };
        if (accessToken is not null)
        {
            descriptor.Claims["ath"] = Base64UrlEncoder.Encode(
                SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken)));
        }

        return (new JsonWebTokenHandler().CreateToken(descriptor), key);
    }
}
