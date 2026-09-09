using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.STS.Controllers;
using Sufficit.Identity.STS.Integrations;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IntegrationOAuthCompletionTests
{
    private const string Provider = "google-workspace";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task Popup_callback_replaces_old_revision_and_refresh_preserves_new_revision()
    {
        var fixture = new Fixture();
        fixture.StoreToken("old-consent");
        var ticket = await fixture.Begin("popup");
        Assert.Equal("old-consent", (await fixture.Status()).AuthorizationRevision);

        var result = Assert.IsType<ContentResult>(await fixture.Callback(ticket));
        Assert.Contains("Conta conectada", result.Content);
        if (Environment.GetEnvironmentVariable("GENIUS_INTEGRATION_EVIDENCE") is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "completion.html"), result.Content);
        }
        Assert.Contains("window.close()", result.Content);
        Assert.Contains("manualmente", result.Content);
        Assert.DoesNotContain("provider-secret", result.Content);
        Assert.Equal("no-store", fixture.Controller.Response.Headers.CacheControl);
        var status = await fixture.Status();
        Assert.True(status.Connected);
        Assert.NotNull(status.AuthorizationRevision);
        Assert.NotEqual("old-consent", status.AuthorizationRevision);

        // Callback issued an already-expiring token: Access must perform refresh.
        var access = Assert.IsType<IntegrationOAuthAccess>(Assert.IsType<OkObjectResult>(
            await fixture.Controller.Access(Provider, default)).Value);
        Assert.Equal("Bearer refreshed-provider-secret", access.Headers["Authorization"]);
        Assert.Equal(status.AuthorizationRevision, access.AuthorizationRevision);
        Assert.Equal(status.AuthorizationRevision, (await fixture.Status()).AuthorizationRevision);
    }

    [Fact]
    public async Task Native_callback_still_returns_to_registered_app_without_tokens()
    {
        var fixture = new Fixture();
        var ticket = await fixture.Begin("app");
        var result = Assert.IsType<RedirectResult>(await fixture.Callback(ticket));
        Assert.Equal("test-app://auth-complete?integration=google-workspace&status=connected", result.Url);
        Assert.DoesNotContain("secret", result.Url);
    }

    [Fact]
    public async Task Provider_denial_does_not_change_the_old_grant_or_autoclose_the_error()
    {
        var fixture = new Fixture();
        fixture.StoreToken("old-consent");
        var ticket = await fixture.Begin("popup");
        var result = Assert.IsType<ContentResult>(await fixture.Callback(ticket, "access_denied"));
        Assert.Contains("Conexão não concluída", result.Content);
        Assert.DoesNotContain("setTimeout", result.Content);
        Assert.Equal("old-consent", (await fixture.Status()).AuthorizationRevision);
    }

    [Fact]
    public async Task Popup_mode_does_not_bypass_return_registration()
    {
        var fixture = new Fixture();
        var result = await fixture.Controller.Authorize(Provider, "evil://return", default, "popup");
        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Empty(fixture.Vault.Values);
    }

    [Fact]
    public async Task Tampered_ticket_cannot_complete_authorization()
    {
        var fixture = new Fixture();
        var ticket = await fixture.Begin("popup");
        Assert.IsType<BadRequestObjectResult>(await fixture.Callback("tampered" + ticket));
        Assert.False((await fixture.Status()).Connected);
    }

    private sealed class Fixture
    {
        public MemoryVault Vault { get; } = new();
        public IntegrationOAuthController Controller { get; }
        private readonly string scope;
        public Fixture()
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:ExternalProviders:Google:Enabled"] = "true",
                ["Sufficit:Identity:ExternalProviders:Google:ClientId"] = "test-client",
                ["Sufficit:Identity:ExternalProviders:Google:ClientSecret"] = "test-secret",
            }).Build();
            var registry = new IntegrationOAuthProviderRegistry(configuration, new TestSecretStore(configuration));
            scope = string.Join(' ', registry.Find(Provider)!.Scopes);
            var authentication = new FakeAuthentication(scope);
            Controller = new IntegrationOAuthController(registry, Vault, new EphemeralDataProtectionProvider(),
                new RefreshHttpClient(), new ReturnResolver(), null!);
            Controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "test-subject")], "test")),
                    RequestServices = new ServiceCollection().AddSingleton<IAuthenticationService>(authentication)
                        .BuildServiceProvider(),
                },
            };
            Controller.Request.Scheme = "https";
            Controller.Request.Host = new HostString("identity.example.test");
        }
        public void StoreToken(string revision) => Vault.Values["integrations/oauth/tokens/" + Provider] =
            JsonSerializer.Serialize(new IntegrationOAuthToken("old-provider-secret", "refresh-secret", "Bearer",
                DateTimeOffset.UtcNow.AddHours(1), scope, null, null, revision), Json);
        public async Task<string> Begin(string launchMode)
        {
            var result = Assert.IsType<IntegrationOAuthAuthorization>(Assert.IsType<OkObjectResult>(
                await Controller.Authorize(Provider, null, default, launchMode)).Value);
            return QueryHelpers.ParseQuery(new Uri(result.AuthorizationUrl).Query)["ticket"].ToString();
        }
        public Task<IActionResult> Callback(string ticket, string? error = null) =>
            Controller.Callback(Provider, ticket, null, null, error, default);
        public async Task<IntegrationOAuthStatus> Status() => Assert.IsType<IntegrationOAuthStatus>(
            Assert.IsType<OkObjectResult>(await Controller.Status(Provider, default)).Value);
    }

    private sealed class FakeAuthentication(string scope) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            var properties = new AuthenticationProperties();
            properties.Items["LoginProvider"] = "Google";
            properties.StoreTokens([
                new() { Name = "access_token", Value = "provider-secret" },
                new() { Name = "refresh_token", Value = "refresh-secret" },
                new() { Name = "scope", Value = scope },
                new() { Name = "expires_at", Value = DateTimeOffset.UtcNow.ToString("O") },
            ]);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(), properties, "Google")));
        }
        public Task ChallengeAsync(HttpContext c, string? s, AuthenticationProperties? p) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext c, string? s, AuthenticationProperties? p) => Task.CompletedTask;
        public Task SignInAsync(HttpContext c, string? s, ClaimsPrincipal u, AuthenticationProperties? p) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext c, string? s, AuthenticationProperties? p) => Task.CompletedTask;
    }
    private sealed class ReturnResolver : IClientNativeReturnUriResolver
    {
        public Task<IReadOnlyList<string>> ListAsync(string? clientId, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<string>>(["test-app://auth-complete"]);
        public Task<string?> ResolveAsync(string? clientId, string? candidate, CancellationToken ct = default) =>
            Task.FromResult(candidate is null or "test-app://auth-complete" ? "test-app://auth-complete" : null);
    }
    private sealed class RefreshHttpClient : HttpMessageHandler, IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(this, disposeHandler: false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new { access_token = "refreshed-provider-secret", expires_in = 3600 }),
            });
    }
    private sealed class MemoryVault : IVaultNamedSecretStore
    {
        public Dictionary<string, string> Values { get; } = [];
        public Task<string?> GetSecretAsync(string n, string c, CancellationToken ct = default) => Task.FromResult(Values.GetValueOrDefault(n));
        public Task<string?> GetSecretAsync(string n, CancellationToken ct = default) => GetSecretAsync(n, "", ct);
        public Task<VaultSecretMetadata> PutAsync(string n, string v, string u, string c, DateTime? expires, CancellationToken ct = default)
        {
            Values[n] = v;
            return Task.FromResult(new VaultSecretMetadata(n, "test", c, u, DateTime.UtcNow, u, true, expires));
        }
        public Task<VaultSecretMetadata> PutAsync(string n, string v, string u, string c, CancellationToken ct = default) => PutAsync(n,v,u,c,null,ct);
        public Task<VaultSecretMetadata> PutAsync(string n, string v, string u, CancellationToken ct = default) => PutAsync(n,v,u,"",null,ct);
        public Task<bool> DeleteAsync(string n, string c, CancellationToken ct = default) => Task.FromResult(Values.Remove(n));
        public Task<bool> DeleteAsync(string n, CancellationToken ct = default) => DeleteAsync(n,"",ct);
        public Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<VaultSecretMetadata>> ListAsync(string c, IReadOnlySet<string>? n, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<VaultNamedSecretResolution?> ResolveAsync(string n, string c, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
