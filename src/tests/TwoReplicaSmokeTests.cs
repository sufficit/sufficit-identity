using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Ciba;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Plan D3: production runs several replicas behind HAProxy that share one
/// database and one Redis <see cref="IDistributedCache"/>. Each test here
/// starts TWO in-process hosts over the same SQLite file and the same cache
/// instance, creates protocol state on replica A and checks that replica B
/// honours it — or refuses it — exactly as a single host would.
/// </summary>
/// <remarks>
/// Where the state lives: DPoP replay is the shared cache (fast hint) followed
/// by a database unique key (authority); DPoP nonces are stateless,
/// data-protected with the key ring persisted to the database; CIBA requests
/// are database rows mirrored into the cache; passkey ceremony tickets are
/// database rows mirrored into the cache. The browser session and the
/// antiforgery tokens ride on the same database-persisted key ring.
/// </remarks>
public sealed class TwoReplicaSmokeTests
{
    private const string Origin = "http://localhost";
    private const string TokenUrl = Origin + "/connect/token";

    [Fact]
    public async Task Dpop_proof_accepted_by_one_replica_is_a_replay_on_the_other()
    {
        using var replicas = await Replicas.StartAsync(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
        });
        using var clientA = replicas.A.CreateClient();
        using var clientB = replicas.B.CreateClient();
        var (proof, _) = BuildDpopProof(TokenUrl);

        var (firstStatus, firstBody) = await PostTokenAsync(clientA, ClientCredentials(), proof);
        var (replayBStatus, replayBBody) = await PostTokenAsync(clientB, ClientCredentials(), proof);
        var (replayAStatus, replayABody) = await PostTokenAsync(clientA, ClientCredentials(), proof);

        Assert.Equal(HttpStatusCode.OK, firstStatus);
        Assert.Equal("DPoP", firstBody.GetProperty("token_type").GetString());
        Assert.NotEqual(HttpStatusCode.OK, replayBStatus);
        Assert.Equal("invalid_dpop_proof", replayBBody.GetProperty("error").GetString());
        Assert.False(replayBBody.TryGetProperty("access_token", out _));
        Assert.NotEqual(HttpStatusCode.OK, replayAStatus);
        Assert.Equal("invalid_dpop_proof", replayABody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Dpop_nonce_issued_by_one_replica_is_honoured_by_the_other()
    {
        using var replicas = await Replicas.StartAsync(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Dpop:Enabled"] = "true",
            ["Sufficit:Identity:Dpop:RequireForAllClients"] = "true",
            ["Sufficit:Identity:Dpop:RequireNonce"] = "true",
        });
        using var clientA = replicas.A.CreateClient();
        using var clientB = replicas.B.CreateClient();
        var (challengeProof, key) = BuildDpopProof(TokenUrl);

        using var challenge = await SendTokenAsync(clientA, ClientCredentials(), challengeProof);
        var challengeBody = await challenge.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("use_dpop_nonce", challengeBody.GetProperty("error").GetString());
        var nonce = challenge.Headers.GetValues("DPoP-Nonce").Single();

        // The client's retry lands on the other replica, as HAProxy may route it.
        var (retryProof, _) = BuildDpopProof(TokenUrl, nonce: nonce, signingKey: key);
        var (retryStatus, retryBody) = await PostTokenAsync(clientB, ClientCredentials(), retryProof);

        Assert.Equal(HttpStatusCode.OK, retryStatus);
        Assert.Equal("DPoP", retryBody.GetProperty("token_type").GetString());

        // And the nonce-carrying proof is single-use on the first replica too.
        var (replayStatus, replayBody) = await PostTokenAsync(clientA, ClientCredentials(), retryProof);
        Assert.NotEqual(HttpStatusCode.OK, replayStatus);
        Assert.Equal("invalid_dpop_proof", replayBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Ciba_request_from_one_replica_is_redeemed_exactly_once_across_both()
    {
        using var replicas = await Replicas.StartAsync(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Ciba:Enabled"] = "true",
            ["Sufficit:Identity:Ciba:ClientPolicyMode"] = "Enforce",
            ["Sufficit:Identity:Ciba:PollIntervalSeconds"] = "0",
        });
        await EnsureCibaClientAsync(replicas.A);
        using var clientA = replicas.A.CreateClient();
        using var clientB = replicas.B.CreateClient();

        var (initiationStatus, initiation) = await clientA.PostFormAsync(
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

        // Replica B knows the request before approval...
        var (pendingStatus, pendingBody) = await clientB.PostFormAsync("/connect/token", CibaPoll(authReqId));
        Assert.Equal(HttpStatusCode.BadRequest, pendingStatus);
        Assert.Equal("authorization_pending", pendingBody.GetProperty("error").GetString());

        // ...the user approves through replica A (same mechanism CibaTests use)...
        var subject = await GetSeedUserIdAsync(replicas.A);
        using (var scope = replicas.A.Services.CreateScope())
        {
            Assert.True(scope.ServiceProvider
                .GetRequiredService<ICibaPendingRequestStore>()
                .Approve(authReqId, subject));
        }

        // ...replica B redeems it, and neither replica redeems it again.
        var (tokenStatus, tokenBody) = await clientB.PostFormAsync("/connect/token", CibaPoll(authReqId));
        var (againBStatus, againBBody) = await clientB.PostFormAsync("/connect/token", CibaPoll(authReqId));
        var (againAStatus, againABody) = await clientA.PostFormAsync("/connect/token", CibaPoll(authReqId));

        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        Assert.False(string.IsNullOrEmpty(tokenBody.GetProperty("access_token").GetString()));
        Assert.Equal(HttpStatusCode.BadRequest, againBStatus);
        Assert.Equal("expired_token", againBBody.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, againAStatus);
        Assert.Equal("expired_token", againABody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Passkey_registration_started_on_one_replica_completes_on_the_other_once()
    {
        using var replicas = await Replicas.StartAsync(new Dictionary<string, string?>());
        var username = await CreateUserAsync(replicas.A);
        var browser = new Browser(replicas);
        await TestOnlyEndpoints.SignInAsync(browser.A, username);
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(browser.A);

        using var optionsResponse = await browser.A.PostAsync(
            "/account/passkeys/creation-options",
            Form(antiforgery));
        Assert.Equal(HttpStatusCode.OK, optionsResponse.StatusCode);
        var options = await optionsResponse.Content.ReadFromJsonAsync<JsonElement>();
        var ceremonyCookie = browser.CeremonyCookie();
        using var authenticator = new SoftwarePasskeyAuthenticator();
        var credential = authenticator.CreateAttestation(options, Origin);

        var completed = await RegisterAsync(browser.B, antiforgery, credential);
        Assert.True(completed.GetProperty("succeeded").GetBoolean(), completed.ToString());

        // Replay the captured ceremony on both replicas: the same credential,
        // and a different authenticator answering the same challenge.
        using var other = new SoftwarePasskeyAuthenticator();
        var otherCredential = other.CreateAttestation(options, Origin);
        foreach (var (client, payload) in new[]
        {
            (browser.A, credential),
            (browser.B, credential),
            (browser.A, otherCredential),
            (browser.B, otherCredential),
        })
        {
            browser.Restore(ceremonyCookie);
            var replay = await RegisterAsync(client, antiforgery, payload);
            Assert.False(replay.GetProperty("succeeded").GetBoolean(), replay.ToString());
            // The ceremony state itself is gone, on every replica — not a
            // signature, counter or antiforgery refusal.
            Assert.Equal(
                "passkey-ceremony-invalid",
                replay.GetProperty("errors")[0].GetProperty("code").GetString());
        }

        await using var scope = replicas.B.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var stored = Assert.Single(await users.GetPasskeysAsync(
            (await users.FindByNameAsync(username))!));
        Assert.Equal(authenticator.CredentialId, Base64UrlEncoder.Encode(stored.CredentialId));
    }

    [Fact]
    public async Task Passkey_sign_in_started_on_one_replica_completes_on_the_other_once()
    {
        using var replicas = await Replicas.StartAsync(new Dictionary<string, string?>());
        var username = await CreateUserAsync(replicas.A);
        using var authenticator = new SoftwarePasskeyAuthenticator();

        // Enrol on replica A.
        var enrolment = new Browser(replicas);
        await TestOnlyEndpoints.SignInAsync(enrolment.A, username);
        var enrolmentToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(enrolment.A);
        using var creation = await enrolment.A.PostAsync(
            "/account/passkeys/creation-options",
            Form(enrolmentToken));
        var creationOptions = await creation.Content.ReadFromJsonAsync<JsonElement>();
        var userHandle = creationOptions.GetProperty("user").GetProperty("id").GetString()!;
        var enrolled = await RegisterAsync(
            enrolment.A,
            enrolmentToken,
            authenticator.CreateAttestation(creationOptions, Origin));
        Assert.True(enrolled.GetProperty("succeeded").GetBoolean(), enrolled.ToString());

        // Sign in from a fresh browser: challenge from A, assertion to B.
        var browser = new Browser(replicas);
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(browser.A);
        using var request = await browser.A.PostAsync(
            $"/account/passkeys/request-options?username={Uri.EscapeDataString(username)}",
            Form(antiforgery));
        Assert.Equal(HttpStatusCode.OK, request.StatusCode);
        var requestOptions = await request.Content.ReadFromJsonAsync<JsonElement>();
        var ceremonyCookie = browser.CeremonyCookie();
        var assertion = authenticator.CreateAssertion(requestOptions, Origin, userHandle);

        var signedIn = await AuthenticateAsync(browser.B, antiforgery, assertion);
        Assert.True(signedIn.GetProperty("succeeded").GetBoolean(), signedIn.ToString());

        // Replay against both replicas: the captured assertion, and a freshly
        // signed one (higher counter) over the same challenge — the latter
        // can only be refused because the challenge itself is spent.
        var resigned = authenticator.CreateAssertion(requestOptions, Origin, userHandle);
        foreach (var (client, payload) in new[]
        {
            (browser.A, assertion),
            (browser.B, assertion),
            (browser.A, resigned),
            (browser.B, resigned),
        })
        {
            browser.Restore(ceremonyCookie);
            var replayToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
            var replay = await AuthenticateAsync(client, replayToken, payload);
            Assert.False(replay.GetProperty("succeeded").GetBoolean(), replay.ToString());
            // The ceremony state itself is gone, on every replica — not a
            // signature, counter or antiforgery refusal.
            Assert.Equal(
                "passkey-ceremony-invalid",
                replay.GetProperty("errors")[0].GetProperty("code").GetString());
        }
    }

    private const string CibaClientId = "test-ciba-replicas";
    private const string CibaClientSecret = "test-ciba-replicas-secret";

    private static Dictionary<string, string> ClientCredentials() => new()
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = TestDataSeeder.ClientCredentialsClientId,
        ["client_secret"] = TestDataSeeder.ClientCredentialsClientSecret,
        ["scope"] = TestDataSeeder.ScopeName,
    };

    private static Dictionary<string, string> CibaPoll(string authReqId) => new()
    {
        ["grant_type"] = "urn:openid:params:grant-type:ciba",
        ["auth_req_id"] = authReqId,
        ["client_id"] = CibaClientId,
        ["client_secret"] = CibaClientSecret,
    };

    private static async Task<HttpResponseMessage> SendTokenAsync(
        HttpClient client,
        Dictionary<string, string> form,
        string proof)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(form),
        };
        message.Headers.Add("DPoP", proof);
        return await client.SendAsync(message);
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> PostTokenAsync(
        HttpClient client,
        Dictionary<string, string> form,
        string proof)
    {
        using var response = await SendTokenAsync(client, form, proof);
        var text = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
        return (response.StatusCode, document.RootElement.Clone());
    }

    private static (string Jwt, ECDsaSecurityKey Key) BuildDpopProof(
        string url,
        string? nonce = null,
        ECDsaSecurityKey? signingKey = null)
    {
        var key = signingKey ?? new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256));
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        var claims = new Dictionary<string, object>
        {
            ["htm"] = "POST",
            ["htu"] = url,
            ["iat"] = EpochTime.GetIntDate(DateTime.UtcNow),
            ["exp"] = EpochTime.GetIntDate(DateTime.UtcNow.AddMinutes(1)),
            ["jti"] = Guid.NewGuid().ToString("N"),
        };
        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }

        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["typ"] = DpopProofValidator.DpopHeaderType,
                ["jwk"] = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(jwk)),
            },
        });
        return (token, key);
    }

    private static async Task EnsureCibaClientAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
        await applications.CreateAsync(new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
        {
            ClientId = CibaClientId,
            ClientSecret = CibaClientSecret,
            ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
            Permissions =
            {
                OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                "gt:urn:openid:params:grant-type:ciba",
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

    private static async Task<string> CreateUserAsync(SufficitIdentityTestFactory factory)
    {
        var username = $"replica-passkey-{Guid.NewGuid():N}";
        await using var scope = factory.Services.CreateAsyncScope();
        await TestDataSeeder.CreateUserAsync(
            scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>(),
            username,
            TestDataSeeder.DefaultPassword);
        return username;
    }

    private static async Task<JsonElement> RegisterAsync(
        HttpClient client,
        string antiforgery,
        string credentialJson)
    {
        using var response = await client.PostAsync(
            "/account/passkeys/register",
            Form(antiforgery, ("credentialJson", credentialJson), ("name", "replica")));
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static async Task<JsonElement> AuthenticateAsync(
        HttpClient client,
        string antiforgery,
        string credentialJson)
    {
        using var response = await client.PostAsync(
            "/account/passkeys/authenticate",
            Form(antiforgery, ("credentialJson", credentialJson)));
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static FormUrlEncodedContent Form(
        string token,
        params (string Key, string Value)[] values)
    {
        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
        };
        foreach (var (key, value) in values)
        {
            form[key] = value;
        }

        return new FormUrlEncodedContent(form);
    }

    /// <summary>Two hosts over one database file and one cache instance.</summary>
    private sealed class Replicas : IDisposable
    {
        private Replicas(SufficitIdentityTestFactory a, SufficitIdentityTestFactory b)
        {
            A = a;
            B = b;
        }

        public SufficitIdentityTestFactory A { get; }

        public SufficitIdentityTestFactory B { get; }

        public static async Task<Replicas> StartAsync(IReadOnlyDictionary<string, string?> configuration)
        {
            var cache = new MemoryDistributedCache(
                Options.Create(new MemoryDistributedCacheOptions()));
            var a = SufficitIdentityTestFactory.CreateReplica(null, cache, configuration);
            await ((IAsyncLifetime)a).InitializeAsync();

            // In production the key ring already exists when a replica joins;
            // materialise it on A so B loads it instead of minting its own.
            const string purpose = "two-replica-smoke";
            var sealedByA = a.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(purpose)
                .Protect("shared key ring");

            var b = SufficitIdentityTestFactory.CreateReplica(a.DatabasePath, cache, configuration);
            Assert.Same(cache, b.Services.GetRequiredService<IDistributedCache>());
            Assert.Same(cache, a.Services.GetRequiredService<IDistributedCache>());
            Assert.Equal(
                "shared key ring",
                b.Services.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector(purpose)
                    .Unprotect(sealedByA));
            return new Replicas(a, b);
        }

        public void Dispose()
        {
            B.Dispose();
            A.Dispose();
        }
    }

    /// <summary>
    /// One browser whose requests the load balancer spreads over both
    /// replicas: both clients share one cookie jar.
    /// </summary>
    private sealed class Browser
    {
        private readonly CookieContainer _cookies = new();

        public Browser(Replicas replicas)
        {
            A = replicas.A.CreateDefaultClient(new CookieContainerHandler(_cookies));
            B = replicas.B.CreateDefaultClient(new CookieContainerHandler(_cookies));
            // ASP.NET Identity checks the WebAuthn clientData origin against
            // the request's Origin header, which a browser always sends.
            A.DefaultRequestHeaders.Add("Origin", Origin);
            B.DefaultRequestHeaders.Add("Origin", Origin);
        }

        public HttpClient A { get; }

        public HttpClient B { get; }

        /// <summary>The ASP.NET Identity WebAuthn ceremony cookie, as captured now.</summary>
        public Cookie CeremonyCookie()
        {
            var cookie = _cookies.GetCookies(new Uri(Origin))
                .FirstOrDefault(candidate => candidate.Name.Contains(
                    "TwoFactorUserId",
                    StringComparison.Ordinal));
            Assert.NotNull(cookie);
            return new Cookie(cookie.Name, cookie.Value, cookie.Path, cookie.Domain);
        }

        /// <summary>Puts a captured ceremony cookie back, as an attacker replaying it would.</summary>
        public void Restore(Cookie cookie) =>
            _cookies.Add(new Uri(Origin), new Cookie(cookie.Name, cookie.Value, cookie.Path));
    }
}
