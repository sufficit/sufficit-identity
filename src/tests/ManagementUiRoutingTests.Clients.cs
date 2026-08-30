using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Branding;
using Sufficit.Identity.Management.Claims;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Authorizations;
using Sufficit.Identity.Management.Database;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.Management.OperatorTokens;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management.Scopes;
using Sufficit.Identity.Management.Sessions;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.UI.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiRoutingTests
{
    [Fact]
    public async Task Administrator_can_render_the_real_client_list()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync("/management/clients");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Aplicações registradas", html, StringComparison.Ordinal);
        Assert.Contains("test-client", html, StringComparison.Ordinal);
        Assert.Contains(
            "src=\"/_content/Sufficit.Identity.UI.Management/_framework/blazor.web.js\"",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "href=\"/_content/Sufficit.Identity.UI.Management/users.css\"",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "src=\"/_framework/blazor.web.js\"",
            html,
            StringComparison.Ordinal);

        using var script = await client.GetAsync(
            "/_content/Sufficit.Identity.UI.Management/_framework/blazor.web.js");
        using var stylesheet = await client.GetAsync(
            "/_content/Sufficit.Identity.UI.Management/app.css");
        using var usersStylesheet = await client.GetAsync(
            "/_content/Sufficit.Identity.UI.Management/users.css");
        Assert.Equal(HttpStatusCode.OK, script.StatusCode);
        Assert.Equal(HttpStatusCode.OK, stylesheet.StatusCode);
        Assert.Equal(HttpStatusCode.OK, usersStylesheet.StatusCode);
        Assert.Contains(
            ".users-dashboard",
            await usersStylesheet.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Administrator_can_render_the_interactive_provisioning_flow()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync(
            "/management/provisioning");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Manifesto JSON", html, StringComparison.Ordinal);
        Assert.Contains("Gerar preview", html, StringComparison.Ordinal);
        Assert.Contains(
            "Use somente referências externas para segredos",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "<textarea disabled",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "aplicação ficará desabilitada",
            html,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Administrator_can_open_a_prefilled_operator_token_request_without_issuing_it()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync(
            "/management/tokens?action=issue"
            + "&purpose=Atualizar%20clientes%20Hermes"
            + "&lifetimeSeconds=900"
            + $"&capability={ManagementCapabilities.ClientsRead}"
            + $"&capability={ManagementCapabilities.ClientsUpdate}");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Solicitação preparada pelo link", html, StringComparison.Ordinal);
        Assert.Contains("Atualizar clientes Hermes", html, StringComparison.Ordinal);
        Assert.Contains(ManagementCapabilities.ClientsRead, html, StringComparison.Ordinal);
        Assert.Contains(ManagementCapabilities.ClientsUpdate, html, StringComparison.Ordinal);
        Assert.Contains(
            "Informações sobre Consultar aplicações OAuth e OIDC",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "Usada nas telas de Aplicações e detalhes do cliente",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "role=\"tooltip\"",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "aria-describedby=\"capability-help-identity-clients-read\"",
            html,
            StringComparison.Ordinal);
        Assert.Contains("Confirmar e gerar token", html, StringComparison.Ordinal);
        Assert.Contains("2 de 24 capabilities", html, StringComparison.Ordinal);
        Assert.Contains("data-sui-align-row", html, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "operator-token-capability-summary",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "operator-token-selected",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("MFA obrigatório", html, StringComparison.Ordinal);
        Assert.DoesNotContain("token-value-from-server", html, StringComparison.Ordinal);
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
        var detailHtml = WebUtility.HtmlDecode(
            await detail.Content.ReadAsStringAsync());
        using var edit = await client.GetAsync(
            "/management/clients/test-id/edit?section=tokens");
        var editHtml = WebUtility.HtmlDecode(
            await edit.Content.ReadAsStringAsync());
        using var credentials = await client.GetAsync(
            "/management/clients/test-id/edit?section=credentials");
        var credentialsHtml = WebUtility.HtmlDecode(
            await credentials.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.Contains("Nova aplicação", createHtml, StringComparison.Ordinal);
        Assert.Contains(
            "Como esta aplicação será usada?",
            createHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.Contains("test-client", detailHtml, StringComparison.Ordinal);
        Assert.Contains(
            "https://client.tests.local/callback",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Contains("Protocolos e permissões", detailHtml, StringComparison.Ordinal);
        Assert.Contains("1 hora", detailHtml, StringComparison.Ordinal);
        Assert.Contains("Padrão global", detailHtml, StringComparison.Ordinal);
        Assert.Contains("Autenticação da aplicação", detailHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, edit.StatusCode);
        Assert.Contains("Editar aplicação", editHtml, StringComparison.Ordinal);
        Assert.Contains("Test Client", editHtml, StringComparison.Ordinal);
        Assert.Contains("Aplicação: test-client", editHtml, StringComparison.Ordinal);
        Assert.Contains("Credencial protegida", editHtml, StringComparison.Ordinal);
        Assert.Contains("Credenciais", editHtml, StringComparison.Ordinal);
        Assert.Contains("Usar padrão global", editHtml, StringComparison.Ordinal);
        Assert.Contains("Salvar alterações", editHtml, StringComparison.Ordinal);
        Assert.Contains("Mais informações sobre Access token", editHtml, StringComparison.Ordinal);
        Assert.Contains("Mais informações sobre ID token", editHtml, StringComparison.Ordinal);
        Assert.Contains("Mais informações sobre Refresh token", editHtml, StringComparison.Ordinal);
        Assert.Contains("aria-current=\"page\"", editHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Seção 3 de 4", editHtml, StringComparison.Ordinal);
        Assert.DoesNotContain(">Anterior<", editHtml, StringComparison.Ordinal);
        Assert.DoesNotContain(">Continuar<", editHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, credentials.StatusCode);
        Assert.Contains("Autenticação da aplicação", credentialsHtml,
            StringComparison.Ordinal);
        Assert.Contains("Adicionar credencial", credentialsHtml,
            StringComparison.Ordinal);
        Assert.Contains("private_key_jwt", credentialsHtml,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Salvar alterações", credentialsHtml,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Administrator_can_resume_client_draft_at_a_stable_step_url()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();
        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync(
            $"/management/clients/drafts/{StubClientConfigurationDraftService.DraftId:D}/permissions");
        var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Menor privilégio", html, StringComparison.Ordinal);
        Assert.Contains("Pesquisar por nome ou finalidade", html, StringComparison.Ordinal);
        Assert.Contains("test.scope", html, StringComparison.Ordinal);
        Assert.DoesNotContain("client secret", html, StringComparison.OrdinalIgnoreCase);
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
    public async Task Administrator_renders_the_event_driven_database_dashboard()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync("/management/database");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Tempo real ativo", html, StringComparison.Ordinal);
        Assert.Contains("Eventos em tempo real", html, StringComparison.Ordinal);
        Assert.DoesNotContain("a cada 2 segundos", html, StringComparison.Ordinal);
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
}
