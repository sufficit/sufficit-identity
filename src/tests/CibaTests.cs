using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Ciba;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers OpenID Connect CIBA Core 1.0: initiation, polling, and the out-of-band
/// completion channel (<c>CibaController</c> + <c>ICibaPendingRequestStore</c>),
/// with polling at the standard token endpoint (<c>CibaGrantHandler</c>).
/// </summary>
/// <remarks>
/// The shared <see cref="StsCollection"/> fixture leaves CIBA disabled. These
/// tests use isolated factories with <c>Ciba.Enabled=true</c>, so the shared
/// suite is unaffected.
/// </remarks>
public sealed class CibaInitiationTests
{
    [Fact]
    public async Task Disabled_ciba_surface_returns_404_instead_of_activation_failure()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var initiation = await client.PostFormAsync(
            "/bc-authorize",
            new Dictionary<string, string>());
        using var completion = await client.GetAsync(
            "/connect/ciba/complete?auth_req_id=disabled");

        Assert.Equal(HttpStatusCode.NotFound, initiation.Status);
        Assert.Equal(HttpStatusCode.NotFound, completion.StatusCode);
    }

    [Fact]
    public async Task Bc_authorize_with_a_known_login_hint_returns_an_auth_req_id()
    {
        // Initiation: a confidential client posts login_hint (the seeded user's
        // username) and gets back { auth_req_id, expires_in, interval }.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/bc-authorize", new Dictionary<string, string>
        {
            ["scope"] = TestDataSeeder.ScopeName,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
            ["login_hint"] = TestDataSeeder.DefaultUsername,
            ["binding_message"] = "Approve login from kiosk-42",
        });

        Assert.Equal(HttpStatusCode.OK, status);
        var authReqId = body.GetProperty("auth_req_id").GetString();
        Assert.False(string.IsNullOrEmpty(authReqId));
        Assert.True(body.GetProperty("expires_in").GetInt32() > 0);
        Assert.True(body.GetProperty("interval").GetInt32() > 0);
    }

    [Fact]
    public async Task Bc_authorize_with_an_unknown_login_hint_does_not_leak_user_existence()
    {
        // M3 fix (eval M3): /bc-authorize no longer returns unknown_user (a
        // user-existence oracle). Instead it returns the same success response
        // (auth_req_id) regardless of whether the login_hint resolves — the
        // pending request just never gets approved, so the poll stays
        // authorization_pending until expiry. Indistinguishable from a real
        // pending request.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/bc-authorize", new Dictionary<string, string>
        {
            ["scope"] = TestDataSeeder.ScopeName,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
            ["login_hint"] = $"nobody-{Guid.NewGuid():N}",
        });

        // Same 200 + auth_req_id as a known user — no oracle.
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrEmpty(body.GetProperty("auth_req_id").GetString()));
    }

    [Fact]
    public async Task Initiation_refuses_an_initiator_that_did_not_authenticate()
    {
        // CIBA has no browser and no user present at the initiator: whoever
        // posts here is asking the server to interrupt someone. An anonymous
        // caller cannot be held to anything afterwards.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var (anonymous, anonymousBody) = await client.PostFormAsync(
            "/bc-authorize",
            new Dictionary<string, string>
            {
                ["scope"] = TestDataSeeder.ScopeName,
                ["login_hint"] = TestDataSeeder.DefaultUsername,
            });
        // A missing client_id is a malformed request, not a failed
        // authentication — nothing was claimed to authenticate.
        Assert.Equal(HttpStatusCode.BadRequest, anonymous);
        Assert.Equal("invalid_request", anonymousBody.GetProperty("error").GetString());

        // A real client id with the wrong secret is the same refusal: the
        // request must not proceed on the strength of naming a client.
        var (wrongSecret, wrongSecretBody) = await client.PostFormAsync(
            "/bc-authorize",
            new Dictionary<string, string>
            {
                ["scope"] = TestDataSeeder.ScopeName,
                ["client_id"] = "test-ciba",
                ["client_secret"] = "not-the-secret",
                ["login_hint"] = TestDataSeeder.DefaultUsername,
            });
        // Naming a real client and failing its secret is a failed
        // authentication (RFC 6749 5.2).
        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecret);
        Assert.Equal("invalid_client", wrongSecretBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Initiation_refuses_a_public_client()
    {
        // A public client keeps no secret, so nothing distinguishes it from
        // anyone who copied its client_id out of a redirect URL. Giving one
        // the power to push an approval prompt at a user is the whole risk.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(
            factory,
            clientId: "test-ciba-public",
            clientSecret: string.Empty,
            publicClient: true);

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync(
            "/bc-authorize",
            new Dictionary<string, string>
            {
                ["scope"] = TestDataSeeder.ScopeName,
                ["client_id"] = "test-ciba-public",
                ["login_hint"] = TestDataSeeder.DefaultUsername,
            });

        // Authenticated as far as it can be — it has no secret to fail — and
        // refused by the eligibility policy, which is unauthorized_client.
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Poll_before_approval_returns_authorization_pending()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var authReqId = await InitiateAsync(client);

        // CIBA Core 1.0 §10.1: polling is the standard token endpoint.
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("authorization_pending", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Poll_after_approval_emits_an_access_token_one_shot()
    {
        // End-to-end CIBA happy path: initiate → approve (via the store,
        // simulating the out-of-band completion channel) → poll → token.
        // The token is issued by the regular token pipeline. A second poll is
        // rejected (one-shot).
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var authReqId = await InitiateAsync(client);

        var subject = await GetSeedUserIdAsync(factory);
        using (var scope = factory.Services.CreateScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ICibaPendingRequestStore>();
            Assert.True(store.Approve(authReqId, subject));
        }

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
        });

        Assert.Equal(HttpStatusCode.OK, status);
        var accessToken = body.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal("test.scope", body.GetProperty("scope").GetString());
        Assert.False(body.TryGetProperty("refresh_token", out _));

        // One-shot: a second poll after issuance must NOT replay the token
        // (the store removed the auth_req_id on emission).
        var (replayStatus, _) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
        });
        Assert.Equal(HttpStatusCode.BadRequest, replayStatus);

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);
        var (_, active) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = accessToken! });
        Assert.True(active.GetProperty("active").GetBoolean());
        Assert.Equal(subject, active.GetProperty("sub").GetString());

        client.DefaultRequestHeaders.Authorization = null;
        var (revocationStatus, _) = await client.PostFormAsync(
            "/connect/revocation",
            new Dictionary<string, string>
            {
                ["token"] = accessToken!,
                ["token_type_hint"] = "access_token",
                ["client_id"] = "test-ciba",
                ["client_secret"] = "test-ciba-secret",
            });
        Assert.Equal(HttpStatusCode.OK, revocationStatus);

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);
        var (_, inactive) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = accessToken! });
        Assert.False(inactive.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Database_backed_ciba_consume_has_one_winner_under_concurrency()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();

        var store = factory.Services.GetRequiredService<ICibaPendingRequestStore>();
        var request = store.Create(
            "concurrent-client", "subject-1", [], null, TimeSpan.FromMinutes(1));
        Assert.True(store.Approve(request.AuthReqId, "subject-1"));

        var attempts = await Task.WhenAll(Enumerable.Range(0, 8).Select(index =>
            Task.Run(() => store.TryConsumeApproved(
                request.AuthReqId, out var consumed))));

        Assert.Single(attempts, result => result);
    }

    [Fact]
    public async Task A_request_created_by_the_previous_release_is_still_honoured()
    {
        // Rolling deployment: a replica still on the previous release creates
        // the pending request in the distributed cache alone. The user
        // approves, and the poll can land on any replica — including an
        // upgraded one, which reads the database. Without the import, the
        // approval would be invisible there and the flow would hang until the
        // request expired.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();

        var legacy = factory.Services
            .GetRequiredService<DistributedCibaPendingRequestStore>();
        var rolling = factory.Services.GetRequiredService<ICibaPendingRequestStore>();

        var previousRelease = legacy.Create(
            "rolling-client",
            "subject-rolling",
            [TestDataSeeder.ScopeName],
            "Approve from the old replica",
            TimeSpan.FromMinutes(1));

        // The upgraded replica sees it.
        var found = rolling.Find(previousRelease.AuthReqId);
        Assert.NotNull(found);
        Assert.Equal("rolling-client", found!.ClientId);
        Assert.Equal("Approve from the old replica", found.BindingMessage);

        // And carries it through approval and the one-shot consume.
        Assert.True(rolling.Approve(previousRelease.AuthReqId, "subject-rolling"));
        Assert.True(rolling.TryConsumeApproved(
            previousRelease.AuthReqId,
            out var consumed));
        Assert.Equal("subject-rolling", consumed.Subject);
        Assert.False(rolling.TryConsumeApproved(
            previousRelease.AuthReqId,
            out _));
    }

    [Fact]
    public async Task Poll_rejects_an_auth_req_id_issued_to_another_client()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);
        await EnsureCibaClientAsync(factory, "test-ciba-other", "test-ciba-other-secret");

        var client = factory.CreateClient();
        var authReqId = await InitiateAsync(client);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
            ["client_id"] = "test-ciba-other",
            ["client_secret"] = "test-ciba-other-secret",
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Poll_uses_the_token_endpoint_client_authentication()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var authReqId = await InitiateAsync(client);

        // client_secret_basic: only the token endpoint authenticates this way,
        // the dedicated poll endpoint read the secret from the form.
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            "test-ciba", "test-ciba-secret");
        var (pendingStatus, pendingBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
        });
        Assert.Equal(HttpStatusCode.BadRequest, pendingStatus);
        Assert.Equal("authorization_pending", pendingBody.GetProperty("error").GetString());

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            "test-ciba", "wrong-secret");
        var (rejectedStatus, rejectedBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
        });
        Assert.Equal(HttpStatusCode.Unauthorized, rejectedStatus);
        Assert.Equal("invalid_client", rejectedBody.GetProperty("error").GetString());

        client.DefaultRequestHeaders.Authorization = null;
        using var legacyPoll = await client.PostAsync(
            "/connect/ciba/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:openid:params:grant-type:ciba",
                ["auth_req_id"] = authReqId,
            }));
        Assert.Equal(HttpStatusCode.NotFound, legacyPoll.StatusCode);
    }

    [Fact]
    public async Task Discovery_advertises_ciba_poll_mode_only_when_enabled()
    {
        using var enabled = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)enabled).InitializeAsync();
        var metadata = await enabled.CreateClient()
            .GetFromJsonAsync<System.Text.Json.JsonElement>("/.well-known/openid-configuration");

        Assert.Contains(
            metadata.GetProperty("grant_types_supported").EnumerateArray(),
            value => value.GetString() == "urn:openid:params:grant-type:ciba");
        Assert.EndsWith("/bc-authorize",
            metadata.GetProperty("backchannel_authentication_endpoint").GetString());
        Assert.Equal(["poll"], metadata.GetProperty("backchannel_token_delivery_modes_supported")
            .EnumerateArray().Select(value => value.GetString()!).ToArray());

        using var disabled = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)disabled).InitializeAsync();
        var disabledMetadata = await disabled.CreateClient()
            .GetFromJsonAsync<System.Text.Json.JsonElement>("/.well-known/openid-configuration");
        Assert.False(disabledMetadata.TryGetProperty("backchannel_authentication_endpoint", out _));
        Assert.DoesNotContain(
            disabledMetadata.GetProperty("grant_types_supported").EnumerateArray(),
            value => value.GetString() == "urn:openid:params:grant-type:ciba");
    }

    [Fact]
    public async Task Initiation_rejects_a_scope_not_permitted_to_the_client()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/bc-authorize", new Dictionary<string, string>
        {
            ["scope"] = "roles",
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
            ["login_hint"] = TestDataSeeder.DefaultUsername,
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Enforced_client_policy_rejects_confidential_client_without_ciba_entitlement()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(
            factory,
            "test-ciba-unentitled",
            "test-ciba-unentitled-secret",
            includeGrantPermission: false);

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync(
            "/bc-authorize",
            new Dictionary<string, string>
            {
                ["scope"] = TestDataSeeder.ScopeName,
                ["client_id"] = "test-ciba-unentitled",
                ["client_secret"] = "test-ciba-unentitled-secret",
                ["login_hint"] = TestDataSeeder.DefaultUsername,
            });

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Initiation_accepts_private_key_jwt_once_and_rejects_foreign_keys()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var clientKey = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var signingKey = new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(clientKey) { KeyId = "ciba-client-key" };
        await EnsureJwksCibaClientAsync(factory, "test-ciba-jwt", signingKey);

        var client = factory.CreateClient();
        var assertion = ClientAssertion("test-ciba-jwt", "https://sts.tests.local", signingKey);
        var (status, body) = await client.PostFormAsync("/bc-authorize", AssertionForm(assertion));
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrEmpty(body.GetProperty("auth_req_id").GetString()));

        var (replayStatus, replayBody) = await client.PostFormAsync("/bc-authorize", AssertionForm(assertion));
        Assert.Equal(HttpStatusCode.Unauthorized, replayStatus);
        Assert.Equal("invalid_client", replayBody.GetProperty("error").GetString());

        using var foreignKey = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var forged = ClientAssertion("test-ciba-jwt", "https://sts.tests.local",
            new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(foreignKey) { KeyId = "ciba-client-key" });
        var (forgedStatus, _) = await client.PostFormAsync("/bc-authorize", AssertionForm(forged));
        Assert.Equal(HttpStatusCode.Unauthorized, forgedStatus);

        var wrongAudience = ClientAssertion("test-ciba-jwt", "https://other.example", signingKey);
        var (audienceStatus, _) = await client.PostFormAsync("/bc-authorize", AssertionForm(wrongAudience));
        Assert.Equal(HttpStatusCode.Unauthorized, audienceStatus);
    }

    [Fact]
    public async Task Initiation_accepts_client_secret_basic_and_refuses_two_methods()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabled());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            "test-ciba", "test-ciba-secret");
        var (status, _) = await client.PostFormAsync("/bc-authorize", new Dictionary<string, string>
        {
            ["scope"] = TestDataSeeder.ScopeName,
            ["login_hint"] = TestDataSeeder.DefaultUsername,
        });
        Assert.Equal(HttpStatusCode.OK, status);

        var (twoMethodsStatus, twoMethodsBody) = await client.PostFormAsync("/bc-authorize", new Dictionary<string, string>
        {
            ["scope"] = TestDataSeeder.ScopeName,
            ["client_secret"] = "test-ciba-secret",
            ["login_hint"] = TestDataSeeder.DefaultUsername,
        });
        Assert.Equal(HttpStatusCode.BadRequest, twoMethodsStatus);
        Assert.Equal("invalid_request", twoMethodsBody.GetProperty("error").GetString());
    }

    private static Dictionary<string, string> AssertionForm(string assertion) => new()
    {
        ["scope"] = TestDataSeeder.ScopeName,
        ["login_hint"] = TestDataSeeder.DefaultUsername,
        ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ["client_assertion"] = assertion,
    };

    private static string ClientAssertion(
        string clientId,
        string audience,
        Microsoft.IdentityModel.Tokens.SecurityKey key)
    {
        var now = DateTime.UtcNow;
        return new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(
            new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
            {
                Issuer = clientId,
                Audience = audience,
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(2),
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = clientId,
                    ["jti"] = Guid.NewGuid().ToString("N"),
                },
                SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                    key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256),
            });
    }

    private static async Task EnsureJwksCibaClientAsync(
        SufficitIdentityTestFactory factory,
        string clientId,
        Microsoft.IdentityModel.Tokens.ECDsaSecurityKey key)
    {
        using var scope = factory.Services.CreateScope();
        var appManager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
        var publicJwk = Microsoft.IdentityModel.Tokens.JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
            new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(
                System.Security.Cryptography.ECDsa.Create(key.ECDsa.ExportParameters(false)))
            { KeyId = key.KeyId });
        publicJwk.Use = "sig";
        var keySet = new Microsoft.IdentityModel.Tokens.JsonWebKeySet();
        keySet.Keys.Add(publicJwk);
        await appManager.CreateAsync(new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
            JsonWebKeySet = keySet,
            Permissions =
            {
                OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                "gt:urn:openid:params:grant-type:ciba",
            },
        });
    }

    private static IReadOnlyDictionary<string, string?> CibaEnabled() => new Dictionary<string, string?>
    {
        ["Sufficit:Identity:Ciba:Enabled"] = "true",
        ["Sufficit:Identity:Ciba:ClientPolicyMode"] = "Enforce",
    };

    private static IReadOnlyDictionary<string, string?> CibaEnabledWithShortInterval() => new Dictionary<string, string?>
    {
        ["Sufficit:Identity:Ciba:Enabled"] = "true",
        ["Sufficit:Identity:Ciba:ClientPolicyMode"] = "Enforce",
        // 0 interval so back-to-back polls in the same test don't trip slow_down.
        ["Sufficit:Identity:Ciba:PollIntervalSeconds"] = "0",
    };

    private static async Task EnsureCibaClientAsync(
        SufficitIdentityTestFactory factory,
        string clientId = "test-ciba",
        string clientSecret = "test-ciba-secret",
        bool includeGrantPermission = true,
        bool publicClient = false)
    {
        using var scope = factory.Services.CreateScope();
        var appManager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
        if (await appManager.FindByClientIdAsync(clientId) is null)
        {
            var descriptor = new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = publicClient ? null : clientSecret,
                ClientType = publicClient
                    ? OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Public
                    : OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
                Permissions =
                {
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Revocation,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                },
            };
            if (includeGrantPermission)
            {
                descriptor.Permissions.Add(
                    "gt:urn:openid:params:grant-type:ciba");
            }
            await appManager.CreateAsync(descriptor);
        }
    }

    private static async Task<string> GetSeedUserIdAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");
        return await userManager.GetUserIdAsync(user);
    }

    private static async Task<string> InitiateAsync(System.Net.Http.HttpClient client)
    {
        var (_, body) = await client.PostFormAsync("/bc-authorize", new Dictionary<string, string>
        {
            ["scope"] = TestDataSeeder.ScopeName,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
            ["login_hint"] = TestDataSeeder.DefaultUsername,
        });
        return body.GetProperty("auth_req_id").GetString()!;
    }
}

/// <summary>
/// Unit tests for <see cref="CibaIdentifier"/>: the auth_req_id is a bearer
/// credential during polling, so it must be high-entropy, URL-safe, and
/// unique — not a structured/timestamped GUID.
/// </summary>
public sealed class CibaIdentifierTests
{
    [Fact]
    public void Create_returns_urlsafe_high_entropy_identifier()
    {
        var id = CibaIdentifier.Create();

        // 32 bytes base64url (no padding) => 43 chars, URL-safe alphabet only.
        Assert.Equal(43, id.Length);
        Assert.DoesNotContain('+', id);
        Assert.DoesNotContain('/', id);
        Assert.DoesNotContain('=', id);
        Assert.Matches("^[A-Za-z0-9_-]+$", id);
    }

    [Fact]
    public void Create_is_unique_across_many_calls()
    {
        // Collisions in 256 bits of CSPRNG are astronomically unlikely; this
        // guards against an accidental static/seeded generator regression.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 10_000; i++)
        {
            Assert.True(seen.Add(CibaIdentifier.Create()));
        }
    }
}
