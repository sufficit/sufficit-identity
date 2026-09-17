using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Tokens;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers refresh_token redemption (eval gap: "refresh/rotation/reuse — zero
/// test"). Obtains an initial refresh_token via the authorization_code +
/// PKCE flow (offline_access scope) against <see cref="TestDataSeeder.AuthorizationCodeClientId"/>,
/// exactly like <see cref="AuthorizationCodeFlowTests"/>.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class RefreshTokenTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public RefreshTokenTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Reuse_outside_leeway_revokes_the_chain_and_rejects_the_rotated_refresh_token()
    {
        using var parent = new SufficitIdentityTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = parent.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Configure<OpenIddictEntityFrameworkCoreOptions>(options => options.DisableBulkOperations = true)));
        var username = $"refresh-replay-{Guid.NewGuid():N}";
        string subject;
        using (var scope = factory.Services.CreateScope())
        {
            Assert.IsType<SufficitOpenIddictTokenStore>(scope.ServiceProvider
                .GetRequiredService<IOpenIddictTokenStore<OpenIddictEntityFrameworkCoreToken>>());
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(users, username, "Str0ng!Passw0rd#Replay");
            subject = user.Id;
        }

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);
        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(client, challenge, scope: "openid offline_access");
        var (initialStatus, initial) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId, ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, initialStatus);
        var original = initial.GetProperty("refresh_token").GetString()!;
        var (rotationStatus, rotation) = await RedeemAsync(original);
        Assert.Equal(HttpStatusCode.OK, rotationStatus);
        var rotated = rotation.GetProperty("refresh_token").GetString()!;

        // Age only this test's redeemed token beyond the real configured
        // leeway. Keep production protocol options and the shared clock intact.
        using (var scope = factory.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
            var leeway = scope.ServiceProvider.GetRequiredService<
                IOptionsMonitor<OpenIddict.Server.OpenIddictServerOptions>>().CurrentValue.RefreshTokenReuseLeeway;
            Assert.NotNull(leeway);
            var aged = 0;
            await foreach (var token in manager.FindBySubjectAsync(subject))
            {
                if (await manager.GetTypeAsync(token) != OpenIddictConstants.TokenTypeIdentifiers.RefreshToken ||
                    await manager.GetStatusAsync(token) != OpenIddictConstants.Statuses.Redeemed)
                    continue;
                var descriptor = new OpenIddictTokenDescriptor();
                await manager.PopulateAsync(descriptor, token);
                descriptor.RedemptionDate = DateTimeOffset.UtcNow - leeway.Value - TimeSpan.FromMinutes(1);
                await manager.UpdateAsync(token, descriptor);
                aged++;
            }
            Assert.Equal(1, aged);
        }

        var (replayStatus, replay) = await RedeemAsync(original);
        Assert.Equal(HttpStatusCode.BadRequest, replayStatus);
        Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, replay.GetProperty("error").GetString());
        var (revokedStatus, revoked) = await RedeemAsync(rotated);
        Assert.Equal(HttpStatusCode.BadRequest, revokedStatus);
        Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, revoked.GetProperty("error").GetString());

        Task<(HttpStatusCode, System.Text.Json.JsonElement)> RedeemAsync(string token) =>
            client.PostFormAsync("/connect/token", new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token", ["refresh_token"] = token,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            });
    }

    [Fact]
    public async Task Redeeming_a_refresh_token_rotates_to_a_new_distinct_refresh_token()
    {
        var username = $"refresh-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#9";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(client, challenge, scope: "openid offline_access");

        var (initialStatus, initialBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, initialStatus);

        var originalRefreshToken = initialBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrEmpty(originalRefreshToken));
        var initialSessionId = SessionId(initialBody.GetProperty("id_token").GetString());

        var (refreshStatus, refreshBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = originalRefreshToken!,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
        });

        Assert.Equal(HttpStatusCode.OK, refreshStatus);
        Assert.False(string.IsNullOrEmpty(refreshBody.GetProperty("access_token").GetString()));
        Assert.Equal(
            initialSessionId,
            SessionId(refreshBody.GetProperty("id_token").GetString()));

        var rotatedRefreshToken = refreshBody.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrEmpty(rotatedRefreshToken));

        // Rotation: OpenIddict's default behavior (AllowRefreshTokenFlow, no
        // rotation opt-out anywhere in ServiceCollectionExtensions.cs) issues
        // a brand-new, single-use refresh token on every redemption instead
        // of reissuing the same one.
        Assert.NotEqual(originalRefreshToken, rotatedRefreshToken);
    }

    [Fact]
    public async Task Refresh_preserves_management_scope_and_mfa_evidence()
    {
        var username = $"refresh-management-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Mfa";
        const string requestedScopes =
            "openid roles offline_access identity.management";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider
                .GetRequiredService<RoleManager<ApplicationRole>>();
            var user = await TestDataSeeder.CreateUserAsync(
                userManager,
                username,
                password);
            await TestDataSeeder.AddToRoleAsync(
                roleManager,
                userManager,
                user,
                "manager");
        }

        var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            withMfa: true);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(
            client,
            challenge,
            requestedScopes);

        var (initialStatus, initialBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] =
                    TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] =
                    TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = verifier,
            });
        Assert.Equal(HttpStatusCode.OK, initialStatus);
        Assert.Contains("mfa", AuthenticationMethods(initialBody));
        await AssertManagementAccessAsync(
            client,
            initialBody.GetProperty("access_token").GetString());

        var refreshToken = initialBody
            .GetProperty("refresh_token")
            .GetString();
        Assert.False(string.IsNullOrWhiteSpace(refreshToken));

        var (refreshStatus, refreshBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken!,
                ["client_id"] =
                    TestDataSeeder.AuthorizationCodeClientId,
                ["scope"] = requestedScopes,
            });

        Assert.Equal(HttpStatusCode.OK, refreshStatus);
        Assert.Contains("mfa", AuthenticationMethods(refreshBody));
        await AssertManagementAccessAsync(
            client,
            refreshBody.GetProperty("access_token").GetString());
    }

    private static string SessionId(string? idToken)
    {
        Assert.False(string.IsNullOrWhiteSpace(idToken));
        var value = new JsonWebTokenHandler()
            .ReadJsonWebToken(idToken)
            .GetClaim("sid")
            .Value;
        Assert.False(string.IsNullOrWhiteSpace(value));
        return value;
    }

    private static string[] AuthenticationMethods(
        System.Text.Json.JsonElement body)
    {
        var token = new JsonWebTokenHandler().ReadJsonWebToken(
            body.GetProperty("id_token").GetString());
        return token.Claims
            .Where(claim => claim.Type == "amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .ToArray();
    }

    private static async Task AssertManagementAccessAsync(
        HttpClient client,
        string? accessToken)
    {
        Assert.False(string.IsNullOrWhiteSpace(accessToken));
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/test-only/management-access");
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer",
                accessToken);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task Reusing_the_just_rotated_refresh_token_immediately_is_tolerated_within_the_reuse_leeway()
    {
        // OpenIddict deliberately tolerates retries within the reuse leeway.
        // OpenIddict's OpenIddictServerOptions.RefreshTokenReuseLeeway
        // defaults to 30 seconds and is never overridden in
        // ServiceCollectionExtensions.cs. Presenting an already-redeemed
        // refresh token again WITHIN that window is deliberately treated as
        // a legitimate client retry (RFC 6749 §10.4 anti-replay guidance),
        // NOT as token-theft reuse: the same tokens the redemption already
        // produced are reissued rather than the request being rejected.
        // True reuse-detection (an old, already-consumed refresh token being
        // rejected and its whole authorization chain revoked) only triggers
        // once that leeway window has elapsed. The separate outside-leeway
        // test ages the redeemed entry to exercise that path without sleeping
        // or changing the protocol options. This test pins
        // TODAY's actual, documented behavior (tolerated reuse) so a future
        // change to that default is a deliberate, visible diff instead of a
        // silent regression. Asserting outright rejection here would be
        // reliably WRONG under the current default, not merely flaky.
        var username = $"refresh-reuse-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#10";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizationCodeFlowTests.AuthorizeAsync(client, challenge, scope: "openid offline_access");

        var (initialStatus, initialBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });
        Assert.Equal(HttpStatusCode.OK, initialStatus);
        var originalRefreshToken = initialBody.GetProperty("refresh_token").GetString()!;

        // First redemption: rotates.
        var (firstStatus, _) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = originalRefreshToken,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
        });
        Assert.Equal(HttpStatusCode.OK, firstStatus);

        // Immediate reuse of the now-redeemed original token: tolerated
        // (see the NOTE above), not rejected.
        var (reuseStatus, reuseBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = originalRefreshToken,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
        });

        Assert.Equal(HttpStatusCode.OK, reuseStatus);
        Assert.False(string.IsNullOrEmpty(reuseBody.GetProperty("access_token").GetString()));
    }
}
