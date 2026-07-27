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
/// Covers CIBA (RFC 9126, item 3.5): initiation, polling, and the out-of-band
/// completion channel. OpenIddict 7.6 has no CIBA primitives, so this exercises
/// the from-scratch implementation (<c>CibaController</c> +
/// <c>ICibaPendingRequestStore</c> + the poll branch in
/// <c>AuthorizationController</c>).
/// </summary>
/// <remarks>
/// The shared <see cref="StsCollection"/> fixture leaves CIBA disabled. These
/// tests use isolated factories with <c>Ciba.Enabled=true</c>, so the shared
/// suite is unaffected. The poll uses a dedicated test endpoint because
/// OpenIddict's <c>/connect/token</c> pipeline rejects the unregistered CIBA
/// grant_type with <c>unsupported_grant_type</c> before the controller runs —
/// see <c>CibaController.Poll</c> for the rationale and the
/// <c>/connect/ciba/token</c> endpoint that bypasses that validation.
/// </remarks>
public sealed class CibaInitiationTests
{
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
    public async Task Poll_before_approval_returns_authorization_pending()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(CibaEnabledWithShortInterval());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureCibaClientAsync(factory);

        var client = factory.CreateClient();
        var authReqId = await InitiateAsync(client);

        // The dedicated CIBA poll endpoint (NOT /connect/token, which OpenIddict
        // rejects for the unregistered grant). Returns authorization_pending.
        var (status, body) = await client.PostFormAsync("/connect/ciba/token", new Dictionary<string, string>
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
        // The token is emitted by CibaAccessTokenGenerator (a hand-built JWT,
        // since OpenIddict forbids SignIn from the unregistered
        // /connect/ciba/token endpoint). A second poll is rejected (one-shot).
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

        var (status, body) = await client.PostFormAsync("/connect/ciba/token", new Dictionary<string, string>
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

        // The token is a self-contained JWT (typ=at+jwt). Decode the header to
        // confirm it is signed (not opaque) and carries the access-token type.
        var handler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(accessToken!);
        Assert.Equal("at+jwt", jwt.Typ);
        Assert.Equal(subject, jwt.GetClaim("sub").Value);

        // One-shot: a second poll after issuance must NOT replay the token
        // (the store removed the auth_req_id on emission).
        var (replayStatus, _) = await client.PostFormAsync("/connect/ciba/token", new Dictionary<string, string>
        {
            ["grant_type"] = "urn:openid:params:grant-type:ciba",
            ["auth_req_id"] = authReqId,
            ["client_id"] = "test-ciba",
            ["client_secret"] = "test-ciba-secret",
        });
        Assert.Equal(HttpStatusCode.BadRequest, replayStatus);
    }

    private static IReadOnlyDictionary<string, string?> CibaEnabled() => new Dictionary<string, string?>
    {
        ["Sufficit:Identity:Ciba:Enabled"] = "true",
    };

    private static IReadOnlyDictionary<string, string?> CibaEnabledWithShortInterval() => new Dictionary<string, string?>
    {
        ["Sufficit:Identity:Ciba:Enabled"] = "true",
        // 0 interval so back-to-back polls in the same test don't trip slow_down.
        ["Sufficit:Identity:Ciba:PollIntervalSeconds"] = "0",
    };

    private static async Task EnsureCibaClientAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var appManager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
        if (await appManager.FindByClientIdAsync("test-ciba") is null)
        {
            await appManager.CreateAsync(new OpenIddict.Abstractions.OpenIddictApplicationDescriptor
            {
                ClientId = "test-ciba",
                ClientSecret = "test-ciba-secret",
                ClientType = OpenIddict.Abstractions.OpenIddictConstants.ClientTypes.Confidential,
                Permissions =
                {
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddict.Abstractions.OpenIddictConstants.Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                },
            });
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
