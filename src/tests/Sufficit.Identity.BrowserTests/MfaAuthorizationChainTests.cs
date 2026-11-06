using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using NUnit.Framework;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;

namespace Sufficit.Identity.BrowserTests;

/// <summary>Real Chromium WebAuthn → cookie → PKCE → API → refresh chain, isolated SQLite/Kestrel.</summary>
[NonParallelizable]
public sealed class MfaAuthorizationChainTests
{
    [TestCase(true)]
    [TestCase(false)]
    public async Task Verified_passkey_controls_management_and_scim(bool verified)
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Issuer"] = $"http://localhost:{port}",
            ["Sufficit:Identity:PublicUrl"] = $"http://localhost:{port}",
            ["Sufficit:Identity:Management:Enabled"] = "true",
            ["Sufficit:Identity:Management:RequiredScope"] = TestDataSeeder.ScopeName,
            ["Sufficit:Identity:Management:Authorization:FullAdministratorRoles:0"] = "test-administrator",
            ["Sufficit:Identity:Scim:Enabled"] = "true",
            ["Sufficit:Identity:Scim:RequiredScope"] = TestDataSeeder.ScopeName,
            ["Sufficit:Identity:Scim:AllowedClientIds:0"] = TestDataSeeder.AuthorizationCodeClientId,
            ["Sufficit:Identity:Passkeys:RequireUserVerification"] = "false",
            ["Sufficit:Identity:Passkeys:RelyingPartyId"] = "localhost",
        });
        factory.UseKestrel(port);
        await ((Xunit.IAsyncLifetime)factory).InitializeAsync();
        using var hostClient = factory.CreateClient();
        var origin = $"http://localhost:{port}";
        var redirectUri = origin + "/test-only/claims";
        using (var scope = factory.Services.CreateScope())
        {
            var apps = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>();
            var app = (await apps.FindByClientIdAsync(TestDataSeeder.AuthorizationCodeClientId))!;
            var descriptor = new OpenIddict.Abstractions.OpenIddictApplicationDescriptor();
            await apps.PopulateAsync(descriptor, app);
            descriptor.RedirectUris.Add(new Uri(redirectUri));
            await apps.UpdateAsync(app, descriptor);
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            Assert.That((await roles.CreateAsync(new ApplicationRole { Name = "test-administrator" })).Succeeded, Is.True);
            Assert.That((await users.AddToRoleAsync((await users.FindByNameAsync(TestDataSeeder.DefaultUsername))!, "test-administrator")).Succeeded, Is.True);
        }
        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new() { Headless = true });
        await using var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();
        page.RequestFailed += (_, request) => TestContext.Progress.WriteLine("Failed request: " + request.Url);
        await page.GotoAsync(origin + "/health");
        // Bootstrap enrollment only; tested sign-in below uses Chromium's signed assertion.
        await Post(page, "/test-only/signin", new() { ["username"] = TestDataSeeder.DefaultUsername, ["mfa"] = "true" });
        var cdp = await context.NewCDPSessionAsync(page);
        await cdp.SendAsync("WebAuthn.enable");
        var added = await cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object> { ["options"] = new
        {
            protocol = "ctap2", transport = "internal", hasResidentKey = true,
            hasUserVerification = true, isUserVerified = true, automaticPresenceSimulation = true
        }});
        var authenticatorId = added!.Value.GetProperty("authenticatorId").GetString();
        var csrf = (await page.EvaluateAsync<JsonElement>("async () => (await fetch('/test-only/antiforgery')).json()"))
            .GetProperty("requestToken").GetString()!;
        var options = await Post(page, "/account/passkeys/creation-options", new() { ["__RequestVerificationToken"] = csrf });
        var credential = await page.EvaluateAsync<string>("""
            async json => {
              const options = JSON.parse(json);
              const decode = x => Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
              options.challenge = decode(options.challenge); options.user.id = decode(options.user.id);
              if(options.excludeCredentials) options.excludeCredentials.forEach(c => c.id = decode(c.id));
              return JSON.stringify((await navigator.credentials.create({publicKey: options})).toJSON());
            }
            """, options.GetRawText());
        var enrolled = await Post(page, "/account/passkeys/register", new()
        {
            ["__RequestVerificationToken"] = csrf, ["credentialJson"] = credential, ["name"] = "browser-test"
        });
        Assert.That(enrolled.GetProperty("succeeded").GetBoolean(), Is.True, enrolled.ToString());
        await context.ClearCookiesAsync();
        await cdp.SendAsync("WebAuthn.setUserVerified", new Dictionary<string, object> { ["authenticatorId"] = authenticatorId!, ["isUserVerified"] = verified });
        csrf = (await page.EvaluateAsync<JsonElement>("async () => (await fetch('/test-only/antiforgery')).json()"))
            .GetProperty("requestToken").GetString()!;
        options = await Post(page, "/account/passkeys/request-options?username=" + TestDataSeeder.DefaultUsername,
            new() { ["__RequestVerificationToken"] = csrf });
        credential = await Assertion(page, options, verified);
        var corrupted = System.Text.Json.Nodes.JsonNode.Parse(credential)!;
        corrupted["response"]!["signature"] = "AAAA";
        var refusal = await page.EvaluateAsync<int>(
            "async a => (await fetch('/account/passkeys/authenticate',{method:'POST',body:new URLSearchParams(a)})).status",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = csrf, ["credentialJson"] = corrupted.ToJsonString() });
        Assert.That(refusal, Is.GreaterThanOrEqualTo(400));
        var anonymous = await page.EvaluateAsync<JsonElement>("async () => (await fetch('/test-only/claims')).json()");
        Assert.That(anonymous.GetArrayLength(), Is.Zero, "A failed signature must not issue a session.");
        options = await Post(page, "/account/passkeys/request-options?username=" + TestDataSeeder.DefaultUsername,
            new() { ["__RequestVerificationToken"] = csrf });
        credential = await Assertion(page, options, verified);
        var signedIn = await Post(page, "/account/passkeys/authenticate", new()
        {
            ["__RequestVerificationToken"] = csrf, ["credentialJson"] = credential
        });
        Assert.That(signedIn.GetProperty("succeeded").GetBoolean(), Is.True, signedIn.ToString());
        var claims = await page.EvaluateAsync<JsonElement>("async () => (await fetch('/test-only/claims')).json()");
        Assert.That(claims.EnumerateArray().Any(c => c.GetProperty("type").GetString() == "amr" && c.GetProperty("value").GetString() == "mfa"), Is.EqualTo(verified));
        var verifier = new string('a', 64);
        var challenge = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));
        await page.GotoAsync(origin + "/connect/authorize?" + string.Join('&', new Dictionary<string, string>
        {
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId, ["response_type"] = "code",
            ["redirect_uri"] = redirectUri, ["scope"] = "openid roles offline_access " + TestDataSeeder.ScopeName,
            ["code_challenge"] = challenge, ["code_challenge_method"] = "S256"
        }.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value))));
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(page.Url).Query);
        Assert.That(query.ContainsKey("code"), Is.True, page.Url);
        var code = query["code"].ToString();
        await page.GotoAsync(origin + "/health");
        var tokens = await Post(page, "/connect/token", new()
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["code_verifier"] = verifier,
            ["redirect_uri"] = redirectUri, ["client_id"] = TestDataSeeder.AuthorizationCodeClientId
        });
        await CheckApis(page, tokens.GetProperty("access_token").GetString()!, verified);
        var refreshed = await Post(page, "/connect/token", new()
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId
        });
        await CheckApis(page, refreshed.GetProperty("access_token").GetString()!, verified);
    }

    private static Task<string> Assertion(IPage page, JsonElement options, bool verified) =>
        page.EvaluateAsync<string>("""
            async a => {
              const options = JSON.parse(a.options);
              const decode = x => Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
              options.challenge = decode(options.challenge);
              options.userVerification = a.verified ? 'required' : 'discouraged';
              if(options.allowCredentials) options.allowCredentials.forEach(c => c.id = decode(c.id));
              return JSON.stringify((await navigator.credentials.get({publicKey: options})).toJSON());
            }
            """, new { options = options.GetRawText(), verified });

    private static Task<JsonElement> Post(IPage page, string path, Dictionary<string, string> form) =>
        page.EvaluateAsync<JsonElement>("async a => { const r = await fetch(a.path, {method:'POST', body:new URLSearchParams(a.form)}); const t=await r.text(); if(!r.ok) throw Error(r.status+': '+t); return t ? JSON.parse(t) : {}; }", new { path, form });

    private static async Task CheckApis(IPage page, string token, bool allowed)
    {
        foreach (var path in new[] { "/api/users", "/scim/v2/users" })
        {
            var status = await page.EvaluateAsync<int>("async a => (await fetch(a.path,{headers:{Authorization:'Bearer '+a.token}})).status", new { path, token });
            Assert.That(status, Is.EqualTo(allowed ? 200 : 403), path);
        }
    }
}
