using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the authorization_code + PKCE flow (eval gap: "the flow the 26
/// legacy clients are expected to migrate to — zero test"), plus the
/// consent_decision=deny path on the same endpoint (#B3).
///
/// Drives /connect/authorize/​/connect/token over real HTTP against
/// <see cref="TestDataSeeder.AuthorizationCodeClientId"/> (a public client,
/// ConsentTypes.Implicit, PKCE required). The interactive login step is
/// stood in for by the factory's test-only "/test-only/signin" endpoint —
/// see <see cref="SufficitIdentityTestFactory"/>'s class doc — since the
/// real login UI lives in the embedded Sufficit.Identity.UI project.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class AuthorizationCodeFlowTests
{
    private const string LegacyAddressClaimType = "urn:sufficit:claim:address";

    private readonly SufficitIdentityTestFactory _factory;

    public AuthorizationCodeFlowTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Authorization_code_with_valid_PKCE_issues_tokens_carrying_the_users_claims()
    {
        var username = $"authcode-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#5";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizeAsync(client, challenge, scope: "openid profile offline_access");

        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });

        Assert.Equal(HttpStatusCode.OK, tokenStatus);

        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));
        // "openid" was granted -> an id_token is expected on the token response.
        var idToken = tokenBody.GetProperty("id_token").GetString();
        Assert.False(string.IsNullOrEmpty(idToken));
        var sessionId = new JsonWebTokenHandler()
            .ReadJsonWebToken(idToken)
            .GetClaim("sid")
            .Value;
        Assert.False(string.IsNullOrWhiteSpace(sessionId));
        // "offline_access" was granted -> a refresh_token is expected too.
        Assert.False(string.IsNullOrEmpty(tokenBody.GetProperty("refresh_token").GetString()));

        // Claims: reference access tokens (UseReferenceAccessTokens, the
        // default in this test config) are opaque, so assert the actual
        // claims via /connect/userinfo rather than trying to decode the
        // access token itself.
        using var userinfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userinfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var userinfoResponse = await client.SendAsync(userinfoRequest);

        Assert.Equal(HttpStatusCode.OK, userinfoResponse.StatusCode);
        var userinfo = await userinfoResponse.Content.ReadFromJsonAsync<JsonElement>();

        Assert.False(string.IsNullOrEmpty(userinfo.GetProperty("sub").GetString()));
        // "profile" was granted -> name claims must be present (GetDestinations gates them on it).
        Assert.Equal(username, userinfo.GetProperty("name").GetString());
    }

    [Fact]
    public async Task Consent_post_with_repeated_scope_fields_preserves_profile_and_offline_access()
    {
        var username = $"consent-scopes-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Consent";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);
            await userManager.AddClaimAsync(user, new Claim("name", "Consent Test User"));
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        var (verifier, challenge) = Pkce.CreatePair();

        var form = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"),
            new("client_id", TestDataSeeder.AuthorizationCodeClientId),
            new("redirect_uri", TestDataSeeder.AuthorizationCodeRedirectUri),
            new("scope", "openid"),
            new("scope", "profile"),
            new("scope", "offline_access"),
            new("state", Guid.NewGuid().ToString("N")),
            new("code_challenge", challenge),
            new("code_challenge_method", "S256"),
            new("consent_decision", "allow"),
            new("__RequestVerificationToken", antiforgeryToken),
        };

        using var authorizationResponse = await client.PostAsync(
            "/connect/authorize",
            new FormUrlEncodedContent(form));
        Assert.Equal(HttpStatusCode.Redirect, authorizationResponse.StatusCode);

        var location = authorizationResponse.Headers.Location
            ?? throw new InvalidOperationException("No redirect Location header.");
        var authorizationQuery = QueryHelpers.ParseQuery(location.Query);
        var code = authorizationQuery["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));

        var (tokenStatus, tokenBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = verifier,
            });

        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        Assert.False(string.IsNullOrWhiteSpace(tokenBody.GetProperty("refresh_token").GetString()));

        using var userinfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userinfoRequest.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            tokenBody.GetProperty("access_token").GetString());
        using var userinfoResponse = await client.SendAsync(userinfoRequest);

        Assert.Equal(HttpStatusCode.OK, userinfoResponse.StatusCode);
        var userinfo = await userinfoResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Consent Test User", userinfo.GetProperty("name").GetString());
    }

    [Fact]
    public async Task End_session_accepts_the_registered_post_logout_redirect_uri()
    {
        var username = $"endsession-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Logout";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizeAsync(client, challenge, scope: "openid profile");
        var (tokenStatus, tokenBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
                ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
                ["code_verifier"] = verifier,
            });

        Assert.Equal(HttpStatusCode.OK, tokenStatus);
        var idToken = tokenBody.GetProperty("id_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(idToken));

        var endSessionUri = QueryHelpers.AddQueryString(
            "/connect/endsession",
            new Dictionary<string, string?>
            {
                ["id_token_hint"] = idToken,
                ["post_logout_redirect_uri"] =
                    TestDataSeeder.AuthorizationCodePostLogoutRedirectUri,
                ["state"] = "logout-state",
            });

        using var response = await client.GetAsync(endSessionUri);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location?.OriginalString;
        Assert.StartsWith("/account/logout?", location, StringComparison.OrdinalIgnoreCase);

        var queryStart = location!.IndexOf('?');
        Assert.True(queryStart >= 0);
        var forwarded = QueryHelpers.ParseQuery(location[queryStart..]);
        Assert.Equal("/connect/endsession", forwarded["ReturnUrl"].ToString());
        Assert.False(forwarded.ContainsKey("id_token_hint"));
        Assert.Equal(
            TestDataSeeder.AuthorizationCodePostLogoutRedirectUri,
            forwarded["post_logout_redirect_uri"].ToString());
        Assert.Equal("logout-state", forwarded["state"].ToString());
        Assert.DoesNotContain(idToken!, location, StringComparison.Ordinal);
    }

    [Fact]
    public async Task End_session_post_is_idempotent_when_identity_cookie_is_missing()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var response = await client.PostAsync(
            "/connect/endsession",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["post_logout_redirect_uri"] =
                    TestDataSeeder.AuthorizationCodePostLogoutRedirectUri,
                ["state"] = "already-signed-out",
                ["__RequestVerificationToken"] = antiforgeryToken,
            }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(
            TestDataSeeder.AuthorizationCodePostLogoutRedirectUri
                + "?state=already-signed-out",
            response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task Authorization_code_remaps_a_legacy_string_address_claim()
    {
        var username = $"authcode-address-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#Address";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(userManager, username, password);

            var result = await userManager.AddClaimAsync(
                user,
                new Claim(Claims.Address, "Legacy address stored as plain text"));

            Assert.True(result.Succeeded);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (verifier, challenge) = Pkce.CreatePair();
        var code = await AuthorizeAsync(client, challenge, scope: $"openid profile {TestDataSeeder.ScopeName}");

        var (tokenStatus, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });

        Assert.Equal(HttpStatusCode.OK, tokenStatus);

        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(accessToken));

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);

        var (introspectionStatus, introspectionBody) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string> { ["token"] = accessToken! });

        Assert.Equal(HttpStatusCode.OK, introspectionStatus);
        Assert.True(introspectionBody.GetProperty("active").GetBoolean());
        Assert.Equal(
            "Legacy address stored as plain text",
            introspectionBody.GetProperty(LegacyAddressClaimType).GetString());
    }

    [Fact]
    public async Task Authorization_code_exchange_with_the_wrong_PKCE_verifier_is_rejected()
    {
        var username = $"authcode-badpkce-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#6";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (_, challenge) = Pkce.CreatePair();
        var code = await AuthorizeAsync(client, challenge, scope: "openid " + TestDataSeeder.ScopeName);

        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            // Deliberately does NOT match the code_challenge sent to /connect/authorize.
            ["code_verifier"] = "this-verifier-does-not-match-the-original-code-challenge-abc123",
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorization_code_exchange_with_a_missing_PKCE_verifier_is_rejected()
    {
        var username = $"authcode-nopkce-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#7";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (_, challenge) = Pkce.CreatePair();
        var code = await AuthorizeAsync(client, challenge, scope: "openid " + TestDataSeeder.ScopeName);

        // No code_verifier at all: the client requires PKCE
        // (Requirements.Features.ProofKeyForCodeExchange), so omitting it
        // entirely must be rejected too — OpenIddict's own request
        // validation catches this specific case (missing required
        // parameter) one layer earlier than a present-but-wrong verifier,
        // hence "invalid_request" rather than "invalid_grant" here.
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
        });

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_with_consent_decision_deny_yields_access_denied()
    {
        // #B3 P0 fix: consent_decision=deny must fail closed with
        // access_denied, closing the transaction, REGARDLESS of the client's
        // ConsentType (AuthorizationController checks the posted-back
        // consent_decision field before evaluating the consent-type switch
        // at all) — so the Implicit-consent client used for the happy path
        // above is a valid (and convenient) subject for this test too.
        //
        // #N1 CSRF hardening: the consent POST now requires a valid
        // antiforgery token, fetched after sign-in (mirrors DeviceFlowTests'
        // approval pattern). Without this the test would 400 instead of
        // exercising the deny branch.
        var username = $"authcode-deny-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#8";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);
        var antiforgeryToken = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        var (_, challenge) = Pkce.CreatePair();

        var form = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["scope"] = "openid " + TestDataSeeder.ScopeName,
            ["state"] = Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["consent_decision"] = "deny",
            ["__RequestVerificationToken"] = antiforgeryToken,
        };

        using var response = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location ?? throw new InvalidOperationException("No redirect Location header.");
        var query = QueryHelpers.ParseQuery(location.Query);

        Assert.Equal("access_denied", query["error"].ToString());
    }

    [Fact]
    public async Task Consent_post_without_antiforgery_token_is_rejected_with_400()
    {
        // #N1 regression guard: a malicious third-party page POSTing
        // consent_decision=allow|deny to /connect/authorize without a valid
        // antiforgery token must NOT be honored. Closes the consent-grant
        // CSRF hole that [IgnoreAntiforgeryToken] + "Blazor EditForm handles
        // it" left open on this API-only host. Mirrors the same protection
        // already present on DeviceController.Verify.
        var username = $"authcode-csrf-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#9";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);
        // Deliberately NOT fetching an antiforgery token.

        var (_, challenge) = Pkce.CreatePair();

        var form = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["scope"] = "openid " + TestDataSeeder.ScopeName,
            ["state"] = Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["consent_decision"] = "allow",
            // No __RequestVerificationToken — this is the attack vector.
        };

        using var response = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(form));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// Drives the GET /connect/authorize step for <see cref="TestDataSeeder.AuthorizationCodeClientId"/>
    /// and returns the issued authorization code, asserting the redirect carried no error.
    /// Internal (not private) so <see cref="RefreshTokenTests"/> can reuse it
    /// to obtain an initial authorization_code without duplicating this logic.
    /// </summary>
    internal static async Task<string> AuthorizeAsync(HttpClient client, string codeChallenge, string scope)
    {
        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["scope"] = scope,
            ["state"] = Guid.NewGuid().ToString("N"),
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
        };

        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", query));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var location = response.Headers.Location ?? throw new InvalidOperationException("/connect/authorize did not redirect.");
        var redirectQuery = QueryHelpers.ParseQuery(location.Query);

        Assert.False(
            redirectQuery.TryGetValue("error", out var error),
            $"/connect/authorize unexpectedly failed: {(error.Count > 0 ? error.ToString() : "")}");

        return redirectQuery["code"].ToString();
    }
}
