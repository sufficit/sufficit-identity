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
using Sufficit.Identity.Management.Branding;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;
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
    public async Task Manager_enters_management_but_global_pages_are_denied()
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

        using var branding = await client.GetAsync("/management/branding");
        Assert.Equal(HttpStatusCode.Redirect, branding.StatusCode);
        Assert.Equal(
            "/management/account/accessdenied",
            LocationPath(branding.Headers.Location));
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

    [Fact]
    public async Task Administrator_renders_persisted_branding_and_rooted_logo()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync("/management/branding");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Sufficit padrão", html, StringComparison.Ordinal);
        Assert.Contains(
            "src=\"/_content/Sufficit.Identity.UI/img/header-icon.png\"",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "src=\"/_content/Sufficit.Identity.UI/img/logo-full.png\"",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "src=\"img/logo-mark.png\"",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Conecte a API",
            html,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("administrator", "Visão global de Administrator")]
    [InlineData("manager", "4082aef4…5940")]
    public async Task Authorized_operator_renders_contextual_user_directory(
        string role,
        string expectedScope)
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, role);

        using var response = await client.GetAsync("/management/users");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Diretório de identidades", html, StringComparison.Ordinal);
        Assert.Contains("alice@tests.local", html, StringComparison.Ordinal);
        Assert.Contains(expectedScope, html, StringComparison.Ordinal);
        Assert.DoesNotContain("Aguardando API", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Manager_can_render_contextual_user_create_and_password_reset()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "manager");

        using var create = await client.GetAsync(
            "/management/users/new");
        var createHtml = WebUtility.HtmlDecode(
            await create.Content.ReadAsStringAsync());
        using var detail = await client.GetAsync(
            "/management/users/user-1"
            + "?context=4082aef4-42d3-4b1b-a321-f405af935940");
        var detailHtml = WebUtility.HtmlDecode(
            await detail.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.Contains("Novo usuário", createHtml, StringComparison.Ordinal);
        Assert.Contains("Senha inicial", createHtml, StringComparison.Ordinal);
        Assert.Contains(
            "Privilégio mínimo desde a criação",
            createHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.Contains(
            "Redefinir senha",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Todos os contextos",
            detailHtml,
            StringComparison.Ordinal);
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
        builder.Services.AddSingleton<IBrandingManagementService, StubBrandingManagementService>();
        builder.Services.AddSingleton<IUserManagementService, StubUserManagementService>();
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

    private sealed class StubBrandingManagementService
        : IBrandingManagementService
    {
        private static readonly ManagementBrandingTheme Theme =
            new(
                Id: 1,
                Name: "Sufficit padrão",
                IsActive: true,
                LogoUrl:
                    "/_content/Sufficit.Identity.UI/img/logo-full.png",
                FaviconUrl:
                    "/_content/Sufficit.Identity.UI/img/favicon.png",
                HeaderIconUrl:
                    "/_content/Sufficit.Identity.UI/img/header-icon.png",
                BackgroundImageUrl:
                    "/_content/Sufficit.Identity.UI/img/login-bg.jpg",
                BrandColor: "#cc0000",
                BrandHoverColor: "#a30000",
                BrandSoftColor: "#fbe9e9",
                ThemeColor: "#cc0000",
                Title: "Sufficit Identity",
                BrandName: "Sufficit",
                BrandSubtitle: "Identity",
                AvatarUrlTemplate: null,
                CreatedAt: DateTime.UtcNow,
                UpdatedAt: DateTime.UtcNow);

        public Task<IReadOnlyList<ManagementBrandingTheme>> ListAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementBrandingTheme>>([Theme]);

        public Task<ManagementBrandingTheme?> GetActiveAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<ManagementBrandingTheme?>(Theme);

        public Task<ManagementBrandingTheme> GetAsync(
            int id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Theme);

        public Task<ManagementBrandingTheme> CreateAsync(
            SaveManagementBrandingThemeCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementBrandingTheme> UpdateAsync(
            int id,
            SaveManagementBrandingThemeCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementBrandingTheme> ActivateAsync(
            int id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            int id,
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

    private sealed class StubUserManagementService : IUserManagementService
    {
        private const string ContextId =
            "4082aef4-42d3-4b1b-a321-f405af935940";

        private static readonly ManagementUserSummary Summary = new(
            "user-1",
            "alice",
            "alice@tests.local",
            EmailConfirmed: true,
            TwoFactorEnabled: true,
            IsLockedOut: false,
            Roles: ["user"]);

        public Task<ManagementUserAccess> GetAccessAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(
                context.Operator.IsInRole("administrator")
                    ? new ManagementUserAccess(true, [ContextId], true)
                    : new ManagementUserAccess(false, [ContextId], true));

        public Task<ManagementUserPage> SearchAsync(
            ManagementUserSearch query,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserPage(
                [Summary],
                1,
                25,
                1,
                query.ContextId));

        public Task<ManagementUserDetail> GetAsync(
            string id,
            string? contextId,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserDetail(
                Summary.Id,
                Summary.UserName,
                Summary.Email,
                Summary.EmailConfirmed,
                null,
                false,
                Summary.TwoFactorEnabled,
                true,
                null,
                0,
                Summary.Roles,
                contextId is null ? [ContextId] : [contextId],
                DateTime.UtcNow,
                new ManagementUserActions(
                    CanResetPassword: true,
                    ResetPasswordRequiresMfa: false,
                    ResetPasswordReasonCode: "allowed")));

        public Task<ManagementUserDetail> CreateAsync(
            CreateManagementUserCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserDetail> ResetPasswordAsync(
            string id,
            ResetManagementUserPasswordCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
