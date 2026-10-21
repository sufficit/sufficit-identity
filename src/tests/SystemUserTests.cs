using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.STS.Grants;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// System users: ordinary users to every application that never sign in
/// interactively. Their credential comes from an operator-issued, one-time
/// enrollment code redeemed by the client itself.
/// </summary>
public sealed class SystemUserTests
{
    private const string AgentClientId = "test-system-agent";
    private const string OtherClientId = "test-other-agent";
    private const string Password = "Syst3m!Passw0rd#9";

    [Fact]
    public async Task Enrollment_gives_a_bearer_credential_whose_tokens_name_the_system_user()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync();
        var code = await env.IssueCodeAsync(user.Id, AgentClientId);

        var (status, body) = await env.RedeemAsync(code, AgentClientId, key: null);

        Assert.True(status == HttpStatusCode.OK, body.ToString());
        Assert.False(string.IsNullOrEmpty(body.GetProperty("refresh_token").GetString()));
        var access = body.GetProperty("access_token").GetString()!;

        // Applications see an ordinary user: userinfo answers with the subject.
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access);
        using var userinfo = await env.Client.SendAsync(request);
        var profile = JsonDocument.Parse(await userinfo.Content.ReadAsStringAsync()).RootElement;
        Assert.True(userinfo.StatusCode == HttpStatusCode.OK, profile.ToString());
        Assert.Equal(user.Id, profile.GetProperty("sub").GetString());

        // The code is single-use.
        var (again, againBody) = await env.RedeemAsync(code, AgentClientId, key: null);
        Assert.Equal(HttpStatusCode.BadRequest, again);
        Assert.Equal("invalid_grant", againBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_dpop_bound_credential_refreshes_only_with_its_key_and_stops_when_disabled()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync();
        var key = NewKey();
        var code = await env.IssueCodeAsync(user.Id, AgentClientId);

        var (status, body) = await env.RedeemAsync(code, AgentClientId, key);
        Assert.True(status == HttpStatusCode.OK, body.ToString());
        Assert.Equal("DPoP", body.GetProperty("token_type").GetString());
        var refresh = body.GetProperty("refresh_token").GetString()!;

        var (noKey, _) = await env.RefreshAsync(refresh, AgentClientId, key: null);
        Assert.Equal(HttpStatusCode.BadRequest, noKey);
        var (otherKey, _) = await env.RefreshAsync(refresh, AgentClientId, NewKey());
        Assert.Equal(HttpStatusCode.BadRequest, otherKey);

        var (refreshed, refreshedBody) = await env.RefreshAsync(refresh, AgentClientId, key);
        Assert.True(refreshed == HttpStatusCode.OK, refreshedBody.ToString());
        var rotated = refreshedBody.GetProperty("refresh_token").GetString()!;

        await env.Store.SetDisabledAsync(user.Id, "operator-1");
        var (disabled, disabledBody) = await env.RefreshAsync(rotated, AgentClientId, key);
        Assert.Equal(HttpStatusCode.BadRequest, disabled);
        Assert.Equal("invalid_grant", disabledBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_code_works_only_for_its_client_and_only_while_valid()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync();

        var forAgent = await env.IssueCodeAsync(user.Id, AgentClientId);
        var (wrongClient, _) = await env.RedeemAsync(forAgent, OtherClientId, key: null);
        Assert.Equal(HttpStatusCode.BadRequest, wrongClient);
        // A refused attempt does not burn the code.
        var (rightClient, rightBody) = await env.RedeemAsync(forAgent, AgentClientId, key: null);
        Assert.True(rightClient == HttpStatusCode.OK, rightBody.ToString());

        var expired = await env.IssueCodeAsync(user.Id, AgentClientId, TimeSpan.FromSeconds(-1));
        var (expiredStatus, _) = await env.RedeemAsync(expired, AgentClientId, key: null);
        Assert.Equal(HttpStatusCode.BadRequest, expiredStatus);

        var revoked = await env.IssueCodeAsync(user.Id, AgentClientId);
        var record = (await env.Store.ListEnrollmentsAsync(user.Id)).First(x => x.RedeemedAtUtc is null && x.ExpiresAtUtc > DateTime.UtcNow);
        await env.Store.RevokeEnrollmentAsync(record.Id, "operator-1");
        var (revokedStatus, _) = await env.RedeemAsync(revoked, AgentClientId, key: null);
        Assert.Equal(HttpStatusCode.BadRequest, revokedStatus);

        var (garbage, _) = await env.RedeemAsync("sys_enroll_not-a-code", AgentClientId, key: null);
        Assert.Equal(HttpStatusCode.BadRequest, garbage);
    }

    [Fact]
    public async Task A_system_user_never_signs_in_even_with_a_password()
    {
        await using var env = await Environment.CreateAsync();
        var user = await env.CreateSystemUserAsync(withPassword: true);

        // Resource-owner password grant: the same answer as a wrong password.
        var (grant, grantBody) = await env.Client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = user.UserName!,
            ["password"] = Password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
        });
        Assert.Equal(HttpStatusCode.BadRequest, grant);
        Assert.Equal("invalid_grant", grantBody.GetProperty("error").GetString());

        // Interactive form: redirected back with the wrong-credential error.
        var browser = env.Host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(browser);
        using var login = await browser.PostAsync("/account/login/password", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = antiforgery,
                ["UserName"] = user.UserName!,
                ["Password"] = Password,
                ["ReturnUrl"] = "/",
            }));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Contains("error=invalid_credentials", login.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.False(login.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(value => value.Contains(".AspNetCore.Identity.Application=", StringComparison.Ordinal)));

        // Not signing in is not the same as not holding tokens: while enabled,
        // token issuance still accepts the user.
        await using var scope = env.Host.Services.CreateAsyncScope();
        var signIn = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();
        Assert.True(await signIn.CanSignInAsync(user));
    }

    private static ECDsaSecurityKey NewKey() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    private static string Proof(ECDsaSecurityKey key, string url)
    {
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.D = null;
        var now = DateTimeOffset.UtcNow;
        return new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(
            new SecurityTokenDescriptor
            {
                Claims = new Dictionary<string, object>
                {
                    ["htm"] = "POST",
                    ["htu"] = url,
                    ["iat"] = EpochTime.GetIntDate(now.UtcDateTime),
                    ["exp"] = EpochTime.GetIntDate(now.AddMinutes(1).UtcDateTime),
                    ["jti"] = Guid.NewGuid().ToString("N"),
                },
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    ["typ"] = DpopProofValidator.DpopHeaderType,
                    ["jwk"] = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(jwk)),
                },
            });
    }

    private sealed class Environment : IAsyncDisposable
    {
        private readonly SufficitIdentityTestFactory _factory;

        private Environment(SufficitIdentityTestFactory factory)
        {
            _factory = factory;
            Host = factory;
            Client = factory.CreateClient();
            Store = factory.Services.GetRequiredService<SystemUserStore>();
        }

        public WebApplicationFactory<SufficitIdentityTestFactory> Host { get; }

        public HttpClient Client { get; }

        public SystemUserStore Store { get; }

        public static async Task<Environment> CreateAsync()
        {
            var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Dpop:Enabled"] = "true",
            });
            await ((IAsyncLifetime)factory).InitializeAsync();
            await using (var scope = factory.Services.CreateAsyncScope())
            {
                var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                foreach (var clientId in new[] { AgentClientId, OtherClientId })
                {
                    await applications.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = clientId,
                        ClientType = ClientTypes.Public,
                        DisplayName = "Headless agent",
                        Permissions =
                        {
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.RefreshToken,
                            Permissions.Prefixes.GrantType + SystemUserEnrollmentGrant.GrantType,
                            Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                        },
                    });
                }
            }

            return new Environment(factory);
        }

        public async Task<ApplicationUser> CreateSystemUserAsync(bool withPassword = false)
        {
            await using var scope = Host.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = withPassword
                ? await TestDataSeeder.CreateUserAsync(users, $"system-{Guid.NewGuid():N}", Password)
                : await CreateWithoutPasswordAsync(users);
            await Store.AddAsync(new SystemUser
            {
                UserId = user.Id,
                CreatedBy = "operator-1",
                CreatedAtUtc = DateTime.UtcNow,
            });
            return user;
        }

        private static async Task<ApplicationUser> CreateWithoutPasswordAsync(UserManager<ApplicationUser> users)
        {
            var user = new ApplicationUser
            {
                UserName = $"system-{Guid.NewGuid():N}",
                Email = $"{Guid.NewGuid():N}@system.invalid",
            };
            var result = await users.CreateAsync(user);
            Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(e => e.Description)));
            return user;
        }

        public async Task<string> IssueCodeAsync(string userId, string clientId, TimeSpan? lifetime = null)
        {
            var (record, code) = SystemUserStore.CreateEnrollment(
                userId, clientId, "test agent", "operator-1", DateTime.UtcNow, lifetime ?? TimeSpan.FromHours(1));
            await Store.AddEnrollmentAsync(record);
            return code;
        }

        public Task<(HttpStatusCode Status, JsonElement Body)> RedeemAsync(
            string code, string clientId, ECDsaSecurityKey? key) =>
            PostAsync(new Dictionary<string, string>
            {
                ["grant_type"] = SystemUserEnrollmentGrant.GrantType,
                [SystemUserEnrollmentGrant.CodeParameter] = code,
                ["client_id"] = clientId,
                ["scope"] = TestDataSeeder.ScopeName,
            }, key);

        public Task<(HttpStatusCode Status, JsonElement Body)> RefreshAsync(
            string refreshToken, string clientId, ECDsaSecurityKey? key) =>
            PostAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = clientId,
            }, key);

        private async Task<(HttpStatusCode Status, JsonElement Body)> PostAsync(
            Dictionary<string, string> form, ECDsaSecurityKey? key)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
            {
                Content = new FormUrlEncodedContent(form),
            };
            if (key is not null)
            {
                request.Headers.Add("DPoP", Proof(key, new Uri(Client.BaseAddress!, "connect/token").AbsoluteUri));
            }

            using var response = await Client.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
            return (response.StatusCode, document.RootElement.Clone());
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            _factory.Dispose();
            await Task.CompletedTask;
        }
    }
}
