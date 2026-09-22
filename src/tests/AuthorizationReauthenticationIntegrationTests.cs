using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
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

    [Theory]
    [InlineData(900, true)]
    [InlineData(0, true)]
    [InlineData(0, false)]
    public async Task Stale_session_is_sent_to_existing_two_factor_flow(int maxAge, bool usePar)
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
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://identity.tests.local") });
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            withMfa: true,
            authenticatedAt: DateTimeOffset.UtcNow.AddHours(-1));
        var authorizeUrl = usePar
            ? AuthorizeUrl(await PushAuthorizationRequestAsync(client, maxAge: maxAge))
            : DirectAuthorizationUrl(maxAge);

        using var authorization = await client.GetAsync(authorizeUrl);
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
        using var mfaResponse = await client.PostAsync(
            "/account/login/2fa",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Code"] = CurrentAuthenticatorCode(authenticatorKey),
                ["RememberMe"] = "true",
                ["RememberClient"] = "false",
                ["ReturnUrl"] = query["returnUrl"].ToString(),
                ["__RequestVerificationToken"] = antiforgery,
            }));
        Assert.Equal(HttpStatusCode.Redirect, mfaResponse.StatusCode);

        if (maxAge == 0)
            Assert.Contains(mfaResponse.Headers.GetValues("Set-Cookie"), value => value.StartsWith(AuthorizationAuthenticationReceipt.CookieName + "="));

        var continuationLocation = mfaResponse.Headers.Location;
        Assert.NotNull(continuationLocation);
        Assert.StartsWith(
            "/account/authenticationcontinue?",
            continuationLocation.OriginalString,
            StringComparison.Ordinal);
        var continuationQuery = QueryHelpers.ParseQuery(
            new Uri(
                new Uri("https://identity.tests.local"),
                continuationLocation).Query);
        Assert.Equal(
            query["returnUrl"].ToString(),
            continuationQuery["returnUrl"].ToString());

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
    public async Task A_remembered_second_factor_is_challenged_and_then_proceeds()
    {
        // The whole point of running the ceremony here rather than letting the
        // relying party reject the token: this test asserts both halves, and
        // the second half is the one that proves there is no loop.
        var username = $"remembered-mfa-{Guid.NewGuid():N}";
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
            Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
            await EnsureClientAsync(scope.ServiceProvider);
        }

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("https://identity.tests.local"),
            });

        // A session whose second factor came from a trusted-device cookie:
        // recent, and carrying amr=mfa, so nothing else would challenge it.
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            rememberedMfa: true,
            authenticatedAt: DateTimeOffset.UtcNow);

        // The mark has to survive the cookie round trip and the
        // security-stamp validator's principal rebuild, which carries over an
        // explicit list of claim types and drops everything else.
        Assert.Contains(
            "identity:mfa_remembered",
            await client.GetStringAsync("/test-only/claims"));

        using var challenged = await client.GetAsync(PlainAuthorizationUrl());
        Assert.Equal(HttpStatusCode.Redirect, challenged.StatusCode);
        Assert.StartsWith(
            "/account/reauthenticate?",
            challenged.Headers.Location!.OriginalString,
            StringComparison.Ordinal);

        using var begin = await client.GetAsync(challenged.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, begin.StatusCode);
        var secondFactor = new Uri(
            new Uri("https://identity.tests.local"),
            begin.Headers.Location!);
        Assert.StartsWith(
            "/account/loginwith2fa?",
            begin.Headers.Location!.OriginalString,
            StringComparison.Ordinal);

        var query = QueryHelpers.ParseQuery(secondFactor.Query);
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var mfaResponse = await client.PostAsync(
            "/account/login/2fa",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Code"] = CurrentAuthenticatorCode(authenticatorKey),
                ["RememberMe"] = "true",
                ["RememberClient"] = "false",
                ["ReturnUrl"] = query["returnUrl"].ToString(),
                ["__RequestVerificationToken"] = antiforgery,
            }));
        Assert.Equal(HttpStatusCode.Redirect, mfaResponse.StatusCode);

        // Back to the same authorization request: the factor was presented in
        // this session now, so it goes through to the client instead of
        // arriving here again.
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
    public async Task An_acr_the_ceremony_cannot_reach_is_attempted_once_and_then_proceeds()
    {
        // The dangerous shape of a voluntary request: the client asks for an
        // assurance level this server cannot give it with a password and a
        // TOTP. Without a bound, the ceremony would be demanded, completed,
        // and demanded again on the very next pass — a loop the user could
        // never escape. The receipt is that bound, and this asserts it.
        var username = $"acr-unreachable-{Guid.NewGuid():N}";
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
            Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
            await EnsureClientAsync(scope.ServiceProvider);
        }

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("https://identity.tests.local"),
            });
        await TestOnlyEndpoints.SignInAsync(
            client,
            username,
            withMfa: true,
            authenticatedAt: DateTimeOffset.UtcNow);

        // loa3 against a password-plus-TOTP session: unreachable here.
        var authorizeUrl = AuthorizationUrlWithAcr("urn:identity:acr:loa3");

        using var challenged = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, challenged.StatusCode);
        Assert.StartsWith(
            "/account/reauthenticate?",
            challenged.Headers.Location!.OriginalString,
            StringComparison.Ordinal);

        using var begin = await client.GetAsync(challenged.Headers.Location);
        var secondFactor = new Uri(
            new Uri("https://identity.tests.local"),
            begin.Headers.Location!);
        var query = QueryHelpers.ParseQuery(secondFactor.Query);
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var mfaResponse = await client.PostAsync(
            "/account/login/2fa",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Code"] = CurrentAuthenticatorCode(authenticatorKey),
                ["RememberMe"] = "true",
                ["RememberClient"] = "false",
                ["ReturnUrl"] = query["returnUrl"].ToString(),
                ["__RequestVerificationToken"] = antiforgery,
            }));
        Assert.Equal(HttpStatusCode.Redirect, mfaResponse.StatusCode);

        // The session is still loa2 — the request asked for more than exists.
        // It proceeds anyway, and the token will say what actually happened.
        using var completed = await client.GetAsync(query["returnUrl"].ToString());
        Assert.Equal(HttpStatusCode.Redirect, completed.StatusCode);
        Assert.StartsWith(
            RedirectUri,
            completed.Headers.Location!.OriginalString,
            StringComparison.Ordinal);
        Assert.False(QueryHelpers.ParseQuery(completed.Headers.Location.Query)
            .ContainsKey("error"));
    }

    private static string AuthorizationUrlWithAcr(string acrValues)
    {
        var (_, challenge) = Pkce.CreatePair();
        return QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = Guid.NewGuid().ToString("N"),
            ["acr_values"] = acrValues,
        });
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
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://identity.tests.local") });
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
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://identity.tests.local") });
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

    /// <summary>
    /// prompt=login must reauthenticate however fresh the session is
    /// (OIDC Core 3.1.2.1); the conformance suite compares auth_time across two
    /// authorizations (oidcc-prompt-login).
    /// </summary>
    [Fact]
    public async Task Prompt_login_reauthenticates_a_recent_session()
    {
        var username = $"recent-auth-prompt-login-{Guid.NewGuid():N}";
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
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri("https://identity.tests.local") });
        await TestOnlyEndpoints.SignInAsync(client, username, withMfa: true);
        var requestUri = await PushAuthorizationRequestAsync(
            client,
            prompt: PromptValues.Login);

        using var response = await client.GetAsync(AuthorizeUrl(requestUri));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(
            "/account/reauthenticate?",
            response.Headers.Location!.OriginalString,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pending_mfa_recovery_preserves_interactive_and_silent_authorization(bool silent)
    {
        var username = $"mfa-recovery-authorization-{Guid.NewGuid():N}";
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(users, username, TestDataSeeder.DefaultPassword);
            Assert.True((await Sufficit.Identity.Core.Services.MfaRecoveryState.RequireAsync(users, user)).Succeeded);
            await EnsureClientAsync(scope.ServiceProvider);
        }

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false, BaseAddress = new Uri("https://identity.tests.local"),
        });
        await TestOnlyEndpoints.SignInAsync(client, username, withMfa: true);
        client.DefaultRequestHeaders.Accept.ParseAdd("text/html");
        var url = PlainAuthorizationUrl();
        if (silent) url = QueryHelpers.AddQueryString(url, "prompt", PromptValues.None);
        using var response = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        if (silent)
        {
            var callback = response.Headers.Location!;
            Assert.StartsWith(RedirectUri, callback.OriginalString, StringComparison.Ordinal);
            Assert.Equal(Errors.InteractionRequired, QueryHelpers.ParseQuery(callback.Query)["error"].ToString());
        }
        else Assert.Equal("/manage/twofactor", response.Headers.Location!.OriginalString);
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
        string? prompt = null, int maxAge = 900)
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
            ["max_age"] = maxAge.ToString(System.Globalization.CultureInfo.InvariantCulture),
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

    /// <summary>
    /// An ordinary authorization request: no <c>prompt</c>, no <c>max_age</c>.
    /// Nothing in it asks for a ceremony, so whatever challenges it came from
    /// the session itself.
    /// </summary>
    private static string PlainAuthorizationUrl()
    {
        var (_, challenge) = Pkce.CreatePair();
        return QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid profile",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = Guid.NewGuid().ToString("N"),
        });
    }

    private static string DirectAuthorizationUrl(int maxAge)
    {
        var (_, challenge) = Pkce.CreatePair();
        return QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId, ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code", ["scope"] = "openid profile",
            ["code_challenge"] = challenge, ["code_challenge_method"] = "S256",
            ["state"] = Guid.NewGuid().ToString("N"), ["prompt"] = "login",
            ["max_age"] = maxAge.ToString(System.Globalization.CultureInfo.InvariantCulture),
        });
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
