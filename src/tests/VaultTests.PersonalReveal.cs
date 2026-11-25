using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.STS;
using Sufficit.Identity.UI.Vault;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class VaultTests
{
    [Fact]
    public async Task Browser_reveal_requires_totp_and_expires_without_sliding_or_leaking_namespaces()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.UtcNow);
        await using var app = await CreateRevealHostAsync(clock);
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://vault.tests.local");

        using var anonymous = await PostAsync(client, "example/password", null);
        Assert.False(anonymous.IsSuccessStatusCode);

        var (session, key) = await SignInAsync(app, client, "owner", enableTotp: true);
        var token = await TokenFromVaultAsync(client, session);
        using var noCsrf = await PostAsync(client, "example/password", null, session);
        Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);

        using var challenge = await PostAsync(client, "example/password", token, session);
        await AssertStatusAsync(challenge, "Challenge");
        Assert.False(challenge.Headers.Contains("Set-Cookie"));

        using var invalid = await PostAsync(client, "example/password", token, session, code: "ABCDEF");
        await AssertStatusAsync(invalid, "InvalidCode");
        Assert.False(invalid.Headers.Contains("Set-Cookie"));

        var code = AccountTwoFactorServiceTests.CurrentAuthenticatorCode(key!);
        using var revealed = await PostAsync(client, "example/password", token, session, code: code);
        var value = await AssertStatusAsync(revealed, "Revealed");
        Assert.Equal("fixture\nsecret <&>", value.GetProperty("value").GetString());
        Assert.Equal(900_000, value.GetProperty("remainingMs").GetInt64());

        var header = Assert.Single(revealed.Headers.GetValues("Set-Cookie"));
        Assert.StartsWith("__Secure-Sufficit.Vault.Reveal=", header, StringComparison.Ordinal);
        Assert.Contains("httponly", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure;", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/vault/reveal", header, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("max-age=900", header, StringComparison.OrdinalIgnoreCase);
        var grant = header.Split(';')[0];

        using var connected = await PostAsync(client, "integrations/example", token, session, grant);
        await AssertStatusAsync(connected, "NotFound");
        using var global = await PostAsync(client, "example/global", token, session, grant);
        await AssertStatusAsync(global, "NotFound");
        using var otherOwner = await PostAsync(client, "example/other-owner", token, session, grant);
        await AssertStatusAsync(otherOwner, "NotFound");

        var (newSession, _) = await SignInAsync(app, client, "owner");
        var newToken = await TokenFromVaultAsync(client, newSession);
        using var crossSession = await PostAsync(client, "example/password", newToken, newSession, grant);
        await AssertStatusAsync(crossSession, "Challenge");

        clock.Advance(TimeSpan.FromMinutes(15) - TimeSpan.FromSeconds(1));
        using var reused = await PostAsync(client, "example/password", token, session, grant);
        value = await AssertStatusAsync(reused, "Revealed");
        Assert.Equal(1_000, value.GetProperty("remainingMs").GetInt64());
        Assert.False(reused.Headers.Contains("Set-Cookie"));

        clock.Advance(TimeSpan.FromSeconds(1));
        using var expired = await PostAsync(client, "example/password", token, session, grant);
        await AssertStatusAsync(expired, "Challenge");

        var (noTotp, _) = await SignInAsync(app, client, "visitor");
        var visitorToken = await TokenFromVaultAsync(client, noTotp);
        using var unenrolled = await PostAsync(client, "example/password", visitorToken, noTotp, grant);
        await AssertStatusAsync(unenrolled, "AuthenticatorRequired");
    }

    private static async Task<WebApplication> CreateRevealHostAsync(TimeProvider clock)
    {
        var options = new VaultOptions { Enabled = true };
        var (vault, database) = CreateRealVault(options);
        await using (var db = await database.CreateDbContextAsync())
        {
            var connection = (SqliteConnection)db.Database.GetDbConnection();
            connection.CreateFunction("UTC_TIMESTAMP", () => DateTime.UtcNow);
            connection.CreateFunction<int, DateTime>("UTC_TIMESTAMP", _ => DateTime.UtcNow);
        }
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddScoped<AppDbContext>(_ => database.CreateDbContext());
        builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();
        builder.Services.AddAntiforgery();
        builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        builder.Services.AddSingleton(clock);
        builder.Services.AddScoped<IPersonalVaultReveal, PersonalVaultReveal>();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<IVaultNamedSecretStore>(new VaultBackedSecretStore(database, vault, options));
        builder.Services.AddScoped<IUserVaultService, UserVaultPersonalSecretService>();
        builder.Services.AddScoped<IUserVaultOverviewService, UserVaultOverviewService>();
        builder.Services.AddSufficitIdentityVaultUI(builder.Configuration);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseSufficitIdentityVaultUI();
        app.MapPost("/test-signin/{name}", async (HttpContext context, string name,
            UserManager<ApplicationUser> users, IUserClaimsPrincipalFactory<ApplicationUser> principals) =>
        {
            var user = (await users.FindByNameAsync(name))!;
            var principal = await principals.CreateAsync(user);
            ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim("sid", Guid.NewGuid().ToString("N")));
            await context.SignInAsync(IdentityConstants.ApplicationScheme, principal);
        });
        await app.StartAsync();
        return app;
    }

    private static async Task<(string Cookie, string? Key)> SignInAsync(
        WebApplication app, HttpClient client, string name, bool enableTotp = false)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(name);
        string? key = null;
        if (user is null)
        {
            user = new ApplicationUser { Id = Guid.NewGuid().ToString(), UserName = name };
            Assert.True((await users.CreateAsync(user)).Succeeded);
            if (enableTotp)
            {
                Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
                Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
                key = await users.GetAuthenticatorKeyAsync(user);
                var store = services.GetRequiredService<IVaultNamedSecretStore>();
                var personal = services.GetRequiredService<IUserVaultService>();
                await personal.PutAsync(user.Id, "personal", "example/password", new("fixture\nsecret <&>"));
                await store.PutAsync("integrations/example", "fixture integration", user.Id,
                    UserVaultPersonalSecretService.ContextFor(user.Id));
                await store.PutAsync("personal/example/global", "fixture global", user.Id);
                await store.PutAsync("personal/example/other-owner", "fixture unrelated", user.Id,
                    UserVaultPersonalSecretService.ContextFor(Guid.NewGuid().ToString()));
            }
        }

        using var response = await client.PostAsync($"/test-signin/{name}", null);
        response.EnsureSuccessStatusCode();
        return (Assert.Single(response.Headers.GetValues("Set-Cookie")).Split(';')[0], key);
    }

    private static async Task<(string Request, string Cookie)> TokenFromVaultAsync(HttpClient client, string session)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/vault");
        request.Headers.Add("Cookie", session);
        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("fixture", html, StringComparison.Ordinal);
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"");
        Assert.True(token.Success, "The Vault dialog must render an antiforgery token.");
        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie")).Split(';')[0];
        return (WebUtility.HtmlDecode(token.Groups[1].Value), cookie);
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string name,
        (string Request, string Cookie)? token, string? session = null, string? grant = null, string code = "")
    {
        var fields = new Dictionary<string, string> { ["name"] = name, ["code"] = code };
        if (token is { } csrf)
            fields["__RequestVerificationToken"] = csrf.Request;
        using var request = new HttpRequestMessage(HttpMethod.Post, "/vault/reveal")
        {
            Content = new FormUrlEncodedContent(fields)
        };
        var cookies = string.Join("; ", new[] { session, token?.Cookie, grant }.OfType<string>());
        if (cookies.Length > 0)
            request.Headers.Add("Cookie", cookies);
        return await client.SendAsync(request);
    }

    private static async Task<JsonElement> AssertStatusAsync(HttpResponseMessage response, string status)
    {
        response.EnsureSuccessStatusCode();
        Assert.True(response.Headers.CacheControl?.NoStore);
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(status, result.GetProperty("status").GetString());
        if (status != "Revealed")
            Assert.Equal(JsonValueKind.Null, result.GetProperty("value").ValueKind);
        Assert.False(result.TryGetProperty("grant", out _));
        return result;
    }
}
