using System.Net;
using System.Security.Cryptography;
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

[Collection(StsCollection.Name)]
public sealed class AuthorizationReauthenticationIntegrationTests(
    SufficitIdentityTestFactory factory)
{
    private const string ClientId = "recent-authentication-client";
    private const string RedirectUri =
        "https://recent-authentication.example.invalid/callback";

    [Fact]
    public async Task Stale_session_is_sent_to_existing_two_factor_flow()
    {
        var username = $"recent-auth-{Guid.NewGuid():N}";
        string authenticatorKey;
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(
                users,
                username,
                TestDataSeeder.DefaultPassword);
            Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
            authenticatorKey = (await users.GetAuthenticatorKeyAsync(user))!;
            Assert.False(string.IsNullOrWhiteSpace(authenticatorKey));
            Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
            await EnsureClientAsync(scope.ServiceProvider);
        }

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            withMfa: true,
            authenticatedAt: DateTimeOffset.UtcNow.AddHours(-1));
        var requestUri = await PushAuthorizationRequestAsync(client);

        using var authorization = await client.GetAsync(AuthorizeUrl(requestUri));
        Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
        var confirmation = authorization.Headers.Location!;
        Assert.StartsWith(
            "/account/reauthenticate?",
            confirmation.OriginalString,
            StringComparison.Ordinal);

        using var begin = await client.GetAsync(confirmation);
        Assert.Equal(HttpStatusCode.Redirect, begin.StatusCode);
        var secondFactor = begin.Headers.Location!;
        Assert.StartsWith(
            "/account/loginwith2fa?",
            secondFactor.OriginalString,
            StringComparison.Ordinal);
        var absoluteSecondFactor = new Uri(
            new Uri("https://identity.tests.local"),
            secondFactor);
        var query = QueryHelpers.ParseQuery(absoluteSecondFactor.Query);
        Assert.Equal("True", query["rememberMe"].ToString());
        Assert.Contains("/connect/authorize", query["returnUrl"].ToString());

        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        var (status, _) = await client.PostFormAsync(
            "/account/login/2fa",
            new Dictionary<string, string>
            {
                ["Code"] = CurrentAuthenticatorCode(authenticatorKey),
                ["RememberMe"] = "true",
                ["RememberClient"] = "false",
                ["ReturnUrl"] = query["returnUrl"].ToString(),
                ["__RequestVerificationToken"] = antiforgery,
            });
        Assert.Equal(HttpStatusCode.Redirect, status);

        using var completed = await client.GetAsync(query["returnUrl"].ToString());
        Assert.Equal(HttpStatusCode.Redirect, completed.StatusCode);
        Assert.StartsWith(
            RedirectUri,
            completed.Headers.Location!.OriginalString,
            StringComparison.Ordinal);
        Assert.False(QueryHelpers.ParseQuery(completed.Headers.Location.Query)
            .ContainsKey("error"));
    }

    [Fact]
    public async Task Recent_session_completes_authorization_without_confirmation()
    {
        var username = $"recent-auth-current-{Guid.NewGuid():N}";
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(
                users,
                username,
                TestDataSeeder.DefaultPassword);
            await EnsureClientAsync(scope.ServiceProvider);
        }

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            withMfa: true);
        var requestUri = await PushAuthorizationRequestAsync(client);

        using var response = await client.GetAsync(AuthorizeUrl(requestUri));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(
            RedirectUri,
            response.Headers.Location!.OriginalString,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Prompt_none_returns_login_required_for_a_stale_session()
    {
        var username = $"recent-auth-silent-{Guid.NewGuid():N}";
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(
                users,
                username,
                TestDataSeeder.DefaultPassword);
            await EnsureClientAsync(scope.ServiceProvider);
        }

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            withMfa: true,
            authenticatedAt: DateTimeOffset.UtcNow.AddHours(-1));
        var requestUri = await PushAuthorizationRequestAsync(
            client,
            prompt: PromptValues.None);

        using var response = await client.GetAsync(AuthorizeUrl(requestUri));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var callback = response.Headers.Location!;
        Assert.StartsWith(
            RedirectUri,
            callback.OriginalString,
            StringComparison.Ordinal);
        Assert.Equal(
            Errors.LoginRequired,
            QueryHelpers.ParseQuery(callback.Query)["error"].ToString());
    }

    private static async Task EnsureClientAsync(IServiceProvider services)
    {
        var applications = services
            .GetRequiredService<IOpenIddictApplicationManager>();
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
                Permissions.Endpoints.PushedAuthorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + Scopes.OpenId,
                Permissions.Prefixes.Scope + Scopes.Profile,
            },
        });
    }

    private static async Task<string> PushAuthorizationRequestAsync(
        HttpClient client,
        string? prompt = null)
    {
        var (_, challenge) = Pkce.CreatePair();
        var form = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["scope"] = "openid profile",
            ["state"] = "s-" + Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["max_age"] = "900",
        };
        if (!string.IsNullOrWhiteSpace(prompt))
        {
            form["prompt"] = prompt;
        }

        var (status, body) = await client.PostFormAsync(
            "/connect/par",
            form);
        Assert.Equal(HttpStatusCode.Created, status);
        return body.GetProperty("request_uri").GetString()!;
    }

    private static string AuthorizeUrl(string requestUri) =>
        QueryHelpers.AddQueryString(
            "/connect/authorize",
            new Dictionary<string, string?>
            {
                ["client_id"] = ClientId,
                ["request_uri"] = requestUri,
            });

    private static string CurrentAuthenticatorCode(string sharedKey)
    {
        var key = DecodeBase32(sharedKey);
        var timeStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--)
        {
            counter[index] = (byte)(timeStep & 0xff);
            timeStep >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0f;
        var binaryCode = ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
        return (binaryCode % 1_000_000).ToString("D6");
    }

    private static byte[] DecodeBase32(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>((value.Length * 5 + 7) / 8);
        var buffer = 0;
        var bits = 0;
        foreach (var character in value.ToUpperInvariant())
        {
            var digit = alphabet.IndexOf(character, StringComparison.Ordinal);
            if (digit < 0)
            {
                continue;
            }

            buffer = (buffer << 5) | digit;
            bits += 5;
            if (bits < 8)
            {
                continue;
            }

            bits -= 8;
            output.Add((byte)(buffer >> bits));
            buffer &= (1 << bits) - 1;
        }

        return output.ToArray();
    }
}
