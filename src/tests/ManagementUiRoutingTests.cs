using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementUiRoutingTests
{
    [Fact]
    public async Task Anonymous_operator_is_challenged_by_the_host_cookie()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/management/");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(
            "/management/account/login",
            LocationPath(response.Headers.Location));

        using var forwarded = await client.GetAsync(response.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, forwarded.StatusCode);
        Assert.Equal(
            "/account/login",
            LocationPath(forwarded.Headers.Location));
    }

    [Fact]
    public async Task Manager_enters_management_but_client_page_is_denied()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "manager");

        using var home = await client.GetAsync("/management/");
        Assert.Equal(HttpStatusCode.OK, home.StatusCode);

        using var clients = await client.GetAsync("/management/clients");
        Assert.Equal(HttpStatusCode.Redirect, clients.StatusCode);
        Assert.Equal(
            "/management/account/accessdenied",
            LocationPath(clients.Headers.Location));

        using var forwarded = await client.GetAsync(clients.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, forwarded.StatusCode);
        Assert.Equal(
            "/account/accessdenied",
            LocationPath(forwarded.Headers.Location));
    }

    [Fact]
    public async Task Administrator_can_render_the_real_client_list()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync("/management/clients");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Clientes registrados", html, StringComparison.Ordinal);
        Assert.Contains("test-client", html, StringComparison.Ordinal);
        Assert.Contains(
            "src=\"/_content/Sufficit.Identity.UI/_framework/blazor.web.js\"",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "src=\"/_framework/blazor.web.js\"",
            html,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Administrator_can_render_client_create_and_detail_flows()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var create = await client.GetAsync("/management/clients/new");
        var createHtml = await create.Content.ReadAsStringAsync();
        using var detail = await client.GetAsync(
            "/management/clients/test-id");
        var detailHtml = await detail.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.Contains("Novo cliente", createHtml, StringComparison.Ordinal);
        Assert.Contains("Authorization Code", createHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.Contains("test-client", detailHtml, StringComparison.Ordinal);
        Assert.Contains(
            "https://client.tests.local/callback",
            detailHtml,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Administrator_can_render_persisted_audit_events()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync("/management/audit");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Eventos administrativos", html, StringComparison.Ordinal);
        Assert.Contains("test-correlation", html, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> CreateHostAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:ManagementUI:PathBase"] = "management"
        });

        builder.Services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/account/login";
                options.AccessDeniedPath = "/account/accessdenied";
            });
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton<IClientManagementService, StubClientManagementService>();
        builder.Services.AddSingleton<IManagementAuditService, StubManagementAuditService>();
        builder.Services.AddSufficitIdentityManagementUI(builder.Configuration);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();

        app.MapGet("/test-signin/{role}", async (HttpContext context, string role) =>
        {
            var identity = new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.Name, $"{role}@tests.local"),
                    new Claim(ClaimTypes.Role, role)
                ],
                CookieAuthenticationDefaults.AuthenticationScheme);

            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity));
        }).AllowAnonymous();

        app.UseSufficitIdentityManagementUI();
        await app.StartAsync();
        return app;
    }

    private static async Task SignInAsync(HttpClient client, string role)
    {
        using var response = await client.GetAsync($"/test-signin/{role}");
        response.EnsureSuccessStatusCode();

        var cookie = response.Headers
            .GetValues("Set-Cookie")
            .Single()
            .Split(';', 2)[0];
        client.DefaultRequestHeaders.Add("Cookie", cookie);
    }

    private static string? LocationPath(Uri? location)
    {
        if (location is null)
        {
            return null;
        }

        var value = location.IsAbsoluteUri
            ? location.AbsolutePath
            : location.OriginalString;
        var queryIndex = value.IndexOf('?', StringComparison.Ordinal);
        return queryIndex < 0 ? value : value[..queryIndex];
    }

    private sealed class StubClientManagementService : IClientManagementService
    {
        public Task<IReadOnlyList<ManagementClientSummary>> ListAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementClientSummary>>(
                [
                    new(
                        Id: "test-id",
                        ClientId: "test-client",
                        DisplayName: "Test Client",
                        Type: "confidential")
                ]);

        public Task<ManagementClientDetail> GetByIdAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementClientDetail(
                "test-id",
                "test-client",
                "Test Client",
                "confidential",
                "explicit",
                [],
                [],
                ["https://client.tests.local/callback"],
                []));

        public Task<ManagementClientDetail> GetByClientIdAsync(
            string clientId,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            GetByIdAsync("test-id", context, cancellationToken);

        public Task<ManagementClientDetail> CreateAsync(
            CreateManagementClientCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            string clientId,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubManagementAuditService : IManagementAuditService
    {
        public Task<IReadOnlyList<ManagementAuditRecord>> ListAsync(
            ManagementRequestContext context,
            int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementAuditRecord>>(
                [
                    new(
                        Id: 1,
                        OccurredAtUtc: new DateTime(
                            2026,
                            7,
                            29,
                            22,
                            0,
                            0,
                            DateTimeKind.Utc),
                        OperatorSubject: "operator-1",
                        OperatorDisplayName: "Admin Test",
                        Capability: ManagementCapabilities.ClientsCreate,
                        ResourceType: ManagementResourceTypes.Client,
                        ResourceId: "test-client",
                        ContextId: null,
                        AuthorizationOutcome: "allowed",
                        OperationOutcome: "succeeded",
                        ReasonCode: "allowed",
                        CorrelationId: "test-correlation",
                        AuthenticationMethods: "pwd mfa")
                ]);
    }
}
