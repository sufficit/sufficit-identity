using System.Net;
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

/// <summary>
/// Reproduces the production ID2013 report (2026-09-09): a user lands on
/// <c>/account/login</c> with <c>returnUrl=/connect/authorize?...request_uri=...</c>,
/// is already authenticated, clicks "Continuar com esta conta" (a plain link to
/// the returnUrl) and receives <c>invalid_token</c> /
/// "The specified token has already been redeemed" (OpenIddict ID2013).
///
/// These tests pin the semantics of OpenIddict 7.6 PAR <c>request_uri</c>
/// consumption across the interactive login round-trip:
///  1. a <c>request_uri</c> presented at <c>/connect/authorize</c> that ends in
///     a login Challenge must still be usable when the browser comes back after
///     signing in — otherwise EVERY interactive PAR login (the flow the .NET 10
///     OIDC client of SufficitBlazorServer performs) would fail;
///  2. once the authorization code has been issued, re-presenting the same
///     <c>request_uri</c> must fail (single-use, RFC 9126 §6.1) — the stale
///     "Continuar com esta conta" click.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class ParLoginRoundTripTests
{
    private const string ClientId = "par-roundtrip-client";
    private const string RedirectUri = "https://par-client.example.invalid/callback";
    private const string RequestUriPreamble = "urn:ietf:params:oauth:request_uri:";

    private readonly SufficitIdentityTestFactory _factory;

    public ParLoginRoundTripTests(SufficitIdentityTestFactory factory) => _factory = factory;

    private static async Task<(string RequestUri, string Verifier)> PushAuthorizationRequestAsync(
        HttpClient client)
    {
        var (verifier, challenge) = Pkce.CreatePair();
        var (status, body) = await client.PostFormAsync("/connect/par", new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["scope"] = "openid profile",
            ["state"] = "s-" + Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });

        Assert.Equal(HttpStatusCode.Created, status);
        var requestUri = body.GetProperty("request_uri").GetString();
        Assert.False(string.IsNullOrEmpty(requestUri));
        Assert.StartsWith("urn:ietf:params:oauth:request_uri:", requestUri);
        return (requestUri!, verifier);
    }

    private static HttpRequestMessage AuthorizeGet(string requestUri) => new(
        HttpMethod.Get,
        QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["request_uri"] = requestUri,
        }));

    [Fact]
    public async Task Request_uri_survives_login_round_trip_and_rejects_replay()
    {
        var username = $"par-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#5";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);

            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            if (await applications.FindByClientIdAsync(ClientId) is null)
            {
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
        }

        using var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        // ------------------------------------------------------------------
        // 1st presentation, anonymous: must be challenged to the login page
        //    (this is where the browser is sent to /account/login with the
        //    request_uri embedded in ReturnUrl).
        // ------------------------------------------------------------------
        var (requestUri, _) = await PushAuthorizationRequestAsync(client);
        using (var first = await client.SendAsync(AuthorizeGet(requestUri)))
        {
            Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
            var login = first.Headers.Location!;
            var loginTarget = login.IsAbsoluteUri
                ? login.AbsolutePath + login.Query
                : login.OriginalString;
            Assert.Contains("/account/login", loginTarget);
            Assert.Contains("ReturnUrl=", loginTarget);
        }

        // The user signs in and the browser resumes /connect/authorize as a
        // fresh navigation, after the credential POST ends on the same-origin
        // authentication continuation page, with the SAME request_uri.
        await TestOnlyEndpoints.SignInAsync(client, username);

        // ------------------------------------------------------------------
        // 2nd presentation, authenticated: must issue the authorization code.
        //    If OpenIddict redeemed the token on the 1st (challenged)
        //    presentation, this is exactly the production ID2013 report.
        // ------------------------------------------------------------------
        using (var second = await client.SendAsync(AuthorizeGet(requestUri)))
        {
            Assert.Equal(HttpStatusCode.Redirect, second.StatusCode);
            var callback = second.Headers.Location!;
            Assert.StartsWith(RedirectUri, callback.OriginalString, StringComparison.Ordinal);

            var callbackQuery = QueryHelpers.ParseQuery(callback.Query);
            Assert.False(
                callbackQuery.TryGetValue("error", out var error),
                $"/connect/authorize returned an error after the login round trip: {error}");
            Assert.False(string.IsNullOrEmpty(callbackQuery["code"].ToString()));
        }

        // ------------------------------------------------------------------
        // 3rd presentation (replay): the flow already completed, so the same
        //    request_uri must be rejected — the "stale link" case, i.e. the
        //    production ID2013 incident. Machine clients get the raw protocol
        //    error; browser navigations get the humanized error page.
        // ------------------------------------------------------------------
        using (var machine = await client.SendAsync(AuthorizeGet(requestUri)))
        {
            Assert.Equal(HttpStatusCode.BadRequest, machine.StatusCode);
            var body = await machine.Content.ReadAsStringAsync();
            Assert.Contains("invalid_token", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("text/html", machine.Content.Headers.ContentType?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
        }

        using (var browserRequest = AuthorizeGet(requestUri))
        {
            browserRequest.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml");
            using var browser = await client.SendAsync(browserRequest);
            Assert.Equal(HttpStatusCode.BadRequest, browser.StatusCode);
            Assert.Equal("text/html", browser.Content.Headers.ContentType?.MediaType);
            var page = await browser.Content.ReadAsStringAsync();
            Assert.Contains("Não foi possível continuar este acesso", WebUtility.HtmlDecode(page));
            Assert.DoesNotContain(requestUri, page);
        }
    }
}
