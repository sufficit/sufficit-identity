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
    public async Task Business_manager_role_does_not_enter_provider_management()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "manager");

        using var response = await client.GetAsync("/management/");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(
            "/management/account/accessdenied",
            LocationPath(response.Headers.Location));

        using var forwarded = await client.GetAsync(response.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, forwarded.StatusCode);
        Assert.Equal(
            "/account/accessdenied",
            LocationPath(forwarded.Headers.Location));
    }

    [Fact]
    public async Task Provider_operator_renders_runtime_driven_home_and_settings()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var home = await client.GetAsync("/management/");
        var homeHtml = WebUtility.HtmlDecode(
            await home.Content.ReadAsStringAsync());
        using var settings = await client.GetAsync("/management/settings");
        var settingsHtml = WebUtility.HtmlDecode(
            await settings.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, home.StatusCode);
        Assert.Contains(
            "Estado fornecido pelo runtime",
            homeHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Política administrativa verificada",
            homeHtml,
            StringComparison.Ordinal);
        Assert.Contains("Clientes", homeHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Parcial", homeHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("5 de 5", homeHtml, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Listagem incorporada",
            homeHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "href=\"provisioning\"",
            homeHtml,
            StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.OK, settings.StatusCode);
        Assert.Contains(
            "Configuração fornecida pelo serviço",
            settingsHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "identity.management",
            settingsHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            ManagementCapabilities.ProvisioningPreview,
            settingsHtml,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Razor Class Library",
            settingsHtml,
            StringComparison.Ordinal);
        Assert.DoesNotContain("PathBase", settingsHtml, StringComparison.Ordinal);
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
    public async Task Capability_help_uses_the_requested_en_US_culture()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync(
            "/management/tokens?culture=en-US&ui-culture=en-US");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("<html lang=\"en-US\">", html, StringComparison.Ordinal);
        Assert.Contains("OAuth and OIDC", html, StringComparison.Ordinal);
        Assert.Contains(
            "Information about View OAuth and OIDC applications",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "Used on the Applications and client detail screens",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Informações sobre Consultar aplicações",
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
        var detailHtml = WebUtility.HtmlDecode(
            await detail.Content.ReadAsStringAsync());
        using var edit = await client.GetAsync(
            "/management/clients/test-id/edit?section=tokens");
        var editHtml = WebUtility.HtmlDecode(
            await edit.Content.ReadAsStringAsync());

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
        Assert.Contains("60 minutos", detailHtml, StringComparison.Ordinal);
        Assert.Contains("Padrão global", detailHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, edit.StatusCode);
        Assert.Contains("Editar aplicação", editHtml, StringComparison.Ordinal);
        Assert.Contains("Test Client", editHtml, StringComparison.Ordinal);
        Assert.Contains("Aplicação: test-client", editHtml, StringComparison.Ordinal);
        Assert.Contains("Segredo preservado", editHtml, StringComparison.Ordinal);
        Assert.Contains("Usar padrão global", editHtml, StringComparison.Ordinal);
        Assert.Contains("Salvar alterações", editHtml, StringComparison.Ordinal);
        Assert.Contains("Mais informações sobre Access token", editHtml, StringComparison.Ordinal);
        Assert.Contains("Mais informações sobre ID token", editHtml, StringComparison.Ordinal);
        Assert.Contains("Mais informações sobre Refresh token", editHtml, StringComparison.Ordinal);
        Assert.Contains("aria-current=\"page\"", editHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Seção 3 de 4", editHtml, StringComparison.Ordinal);
        Assert.DoesNotContain(">Anterior<", editHtml, StringComparison.Ordinal);
        Assert.DoesNotContain(">Continuar<", editHtml, StringComparison.Ordinal);
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

    [Fact]
    public async Task Provider_operator_renders_global_user_directory()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync("/management/users");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Cadastros por dia", html, StringComparison.Ordinal);
        Assert.Contains("Filtros e ordenação", html, StringComparison.Ordinal);
        Assert.Contains("alice@tests.local", html, StringComparison.Ordinal);
        Assert.Contains("Diretório global", html, StringComparison.Ordinal);
        Assert.Contains(
            "--registration-height: 66.667%",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "--registration-height: 77.778%",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "--registration-height: 100%",
            html,
            StringComparison.Ordinal);
        Assert.Contains(
            "--registration-height: 72.222%",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "--registration-height: 66,667%",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Manager", html, StringComparison.Ordinal);
        Assert.DoesNotContain("Contexto", html, StringComparison.Ordinal);
        Assert.Contains(
            "src=\"https://avatars.tests.local/operator-administrator.jpg\"",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Aguardando API", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Stale_unverified_investigation_is_deep_linkable()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync(
            "/management/users?review=StaleUnverifiedWithoutExternal&sort=CreatedOldest");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Cadastros pendentes há mais de 15 dias", html,
            StringComparison.Ordinal);
        Assert.Contains("Encerrar investigação", html, StringComparison.Ordinal);
        Assert.Contains(
            "Mais de 15 dias, sem confirmação de e-mail e sem login externo vinculado.",
            html,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Provider_operator_can_render_global_user_flows()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var create = await client.GetAsync(
            "/management/users/new");
        var createHtml = WebUtility.HtmlDecode(
            await create.Content.ReadAsStringAsync());
        using var detail = await client.GetAsync(
            "/management/users/user-1");
        var detailHtml = WebUtility.HtmlDecode(
            await detail.Content.ReadAsStringAsync());
        using var edit = await client.GetAsync(
            "/management/users/user-1/edit");
        var editHtml = WebUtility.HtmlDecode(
            await edit.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        Assert.Contains("Novo usuário", createHtml, StringComparison.Ordinal);
        Assert.Contains("Senha inicial", createHtml, StringComparison.Ordinal);
        Assert.Contains(
            "Conta de autenticação, não perfil empresarial",
            createHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.Contains(
            "Redefinir senha",
            detailHtml,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Contexto", detailHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Manager", detailHtml, StringComparison.Ordinal);
        Assert.Contains(
            "Bloquear acesso",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Confirmo o bloqueio desta conta",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Editar perfil",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Excluir conta do provedor",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Digite <strong>alice</strong> para confirmar",
            detailHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, edit.StatusCode);
        Assert.Contains(
            "Salvar perfil",
            editHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Alteração da conta no provedor",
            editHtml,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Provider_operator_renders_user_claims_and_separate_scopes()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var claims = await client.GetAsync(
            "/management/claims?user=user-1");
        var claimsHtml = WebUtility.HtmlDecode(
            await claims.Content.ReadAsStringAsync());
        using var scopes = await client.GetAsync("/management/scopes");
        var scopesHtml = WebUtility.HtmlDecode(
            await scopes.Content.ReadAsStringAsync());
        using var removed = await client.GetAsync("/management/access");

        Assert.Equal(HttpStatusCode.OK, claims.StatusCode);
        Assert.Contains("Claims de alice", claimsHtml, StringComparison.Ordinal);
        Assert.Contains("urn:tests:locale", claimsHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("manager", claimsHtml, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.OK, scopes.StatusCode);
        Assert.Contains("Scopes registrados", scopesHtml, StringComparison.Ordinal);
        Assert.Contains("test.scope", scopesHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Papéis da conta", scopesHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("Atribuir cargo", scopesHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, removed.StatusCode);
    }

    [Fact]
    public async Task Provider_operator_can_render_claim_and_scope_editing_flows()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var claimCreate = await client.GetAsync(
            "/management/claims/new?user=user-1");
        var claimCreateHtml = WebUtility.HtmlDecode(
            await claimCreate.Content.ReadAsStringAsync());
        using var claimDetail = await client.GetAsync(
            "/management/claims/edit?user=user-1&claim=1");
        var claimDetailHtml = WebUtility.HtmlDecode(
            await claimDetail.Content.ReadAsStringAsync());
        using var scopeCreate = await client.GetAsync(
            "/management/scopes/new");
        var scopeCreateHtml = WebUtility.HtmlDecode(
            await scopeCreate.Content.ReadAsStringAsync());
        using var scopeDetail = await client.GetAsync(
            "/management/scopes/scope-1");
        var scopeDetailHtml = WebUtility.HtmlDecode(
            await scopeDetail.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, claimCreate.StatusCode);
        Assert.Contains(
            "Atribuir claim",
            claimCreateHtml,
            StringComparison.Ordinal);
        Assert.Contains("locale", claimCreateHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, claimDetail.StatusCode);
        Assert.Contains(
            "Salvar claim",
            claimDetailHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, scopeCreate.StatusCode);
        Assert.Contains(
            "Recursos protegidos",
            scopeCreateHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, scopeDetail.StatusCode);
        Assert.Contains(
            "Clientes vinculados",
            scopeDetailHtml,
            StringComparison.Ordinal);
        Assert.Contains("test-client", scopeDetailHtml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Claims_without_user_query_fail_closed_to_user_selection()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var claims = await client.GetAsync("/management/claims");
        var claimsHtml = WebUtility.HtmlDecode(
            await claims.Content.ReadAsStringAsync());
        using var claimCreate = await client.GetAsync("/management/claims/new");
        var claimCreateHtml = WebUtility.HtmlDecode(
            await claimCreate.Content.ReadAsStringAsync());
        using var claimDetail = await client.GetAsync("/management/claims/edit");
        var claimDetailHtml = WebUtility.HtmlDecode(
            await claimDetail.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, claims.StatusCode);
        Assert.Contains("Selecione um usuário", claimsHtml, StringComparison.Ordinal);
        Assert.DoesNotContain("urn:tests:locale", claimsHtml, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, claimCreate.StatusCode);
        Assert.Contains(
            "Selecione um usuário",
            claimCreateHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, claimDetail.StatusCode);
        Assert.Contains(
            "Selecione uma claim",
            claimDetailHtml,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Provider_operator_renders_sessions_and_authorizations()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var sessions = await client.GetAsync(
            "/management/sessions?user=user-1");
        var sessionsHtml = WebUtility.HtmlDecode(
            await sessions.Content.ReadAsStringAsync());
        using var authorizations = await client.GetAsync(
            "/management/authorizations?user=user-1");
        var authorizationsHtml = WebUtility.HtmlDecode(
            await authorizations.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, sessions.StatusCode);
        Assert.Contains(
            "Sessões e credenciais",
            sessionsHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "refresh token",
            sessionsHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "Metadados seguros",
            sessionsHtml,
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, authorizations.StatusCode);
        Assert.Contains(
            "Grants e consentimentos",
            authorizationsHtml,
            StringComparison.Ordinal);
        Assert.Contains(
            "test.scope",
            authorizationsHtml,
            StringComparison.Ordinal);
    }

    private static async Task<WebApplication> CreateHostAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:ManagementUI:PathBase"] = "management",
            ["Sufficit:Identity:Management:RequireMfa"] = "false",
            ["Sufficit:Identity:Management:Authorization:FullAdministratorRoles:0"] =
                "administrator"
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
        builder.Services.AddSingleton<IClientConfigurationDraftService,
            StubClientConfigurationDraftService>();
        builder.Services.AddSingleton<IClaimManagementService, StubClaimManagementService>();
        builder.Services.AddSingleton<IScopeManagementService, StubScopeManagementService>();
        builder.Services.AddSingleton<ISessionManagementService, StubSessionManagementService>();
        builder.Services.AddSingleton<IAuthorizationManagementService, StubAuthorizationManagementService>();
        builder.Services.AddSingleton<IBrandingManagementService, StubBrandingManagementService>();
        builder.Services.AddSingleton<IUserManagementService, StubUserManagementService>();
        builder.Services.AddSingleton<
            IProvisioningManagementService,
            StubProvisioningManagementService>();
        builder.Services.AddSingleton<
            IOperatorTokenManagementService,
            StubOperatorTokenManagementService>();
        builder.Services.AddSingleton<IManagementAuditService, StubManagementAuditService>();
        builder.Services.AddSingleton<
            IDatabaseMonitoringService,
            StubDatabaseMonitoringService>();
        builder.Services.AddSingleton<
            IUserAvatarUrlResolver,
            StubUserAvatarUrlResolver>();
        builder.Services.AddOptions<ManagementOptions>()
            .Bind(builder.Configuration.GetSection(
                "Sufficit:Identity:Management"));
        builder.Services.AddScoped<IManagementEntitlementResolver,
            ScopeAndRoleManagementEntitlementResolver>();
        builder.Services.AddScoped<IProtectedPrincipalAccessPolicy,
            TestAllowProtectedPrincipalAccessPolicy>();
        builder.Services.AddScoped<IManagementObjectAccessPolicy,
            ConfigurationManagementObjectAccessPolicy>();
        builder.Services.AddScoped<IManagementAccessPolicyProvider,
            ConfigurationManagementAccessPolicyProvider>();
        builder.Services.AddScoped<IManagementAuthorizationEvaluator,
            CapabilityManagementAuthorizationEvaluator>();
        builder.Services.AddScoped<IManagementOverviewService,
            ManagementOverviewService>();
        builder.Services.AddSufficitIdentityManagementUI(builder.Configuration);

        var app = builder.Build();
        app.UseRequestLocalization(new RequestLocalizationOptions()
            .SetDefaultCulture("pt-BR")
            .AddSupportedCultures("pt-BR", "en-US")
            .AddSupportedUICultures("pt-BR", "en-US"));
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();

        app.MapGet("/test-signin/{role}", async (HttpContext context, string role) =>
        {
            var identity = new ClaimsIdentity(
                [
                    new Claim(
                        ClaimTypes.NameIdentifier,
                        $"operator-{role}"),
                    new Claim(ClaimTypes.Name, $"{role}@tests.local"),
                    new Claim(ClaimTypes.Role, role),
                    new Claim("amr", "pwd mfa")
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

        public Task<ManagementClientDetail> UpdateAsync(
            UpdateManagementClientCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            string clientId,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubClientConfigurationDraftService
        : IClientConfigurationDraftService
    {
        internal static readonly Guid DraftId = Guid.Parse(
            "96774ce4-a56d-4c50-8668-d25f046b30fc");

        private static ManagementClientDraftDetail Draft => new(
            DraftId,
            ManagementClientProfiles.Spa,
            ManagementClientDraftSteps.Permissions,
            new ManagementClientDraftValues
            {
                ClientId = "test-spa",
                DisplayName = "Test SPA",
                ClientType = "public",
                AuthorizationCode = true,
                Scopes = ["openid", "test.scope"],
                RedirectUris = ["https://spa.tests.local/callback"],
            },
            new ClientDraftValidation(true, []),
            "test-version",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(14));

        public Task<IReadOnlyList<ManagementClientProfile>> GetProfilesAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementClientProfile>>(
            [
                new(ManagementClientProfiles.Spa, "SPA pública",
                    "Aplicação no navegador.", "code",
                    "Authorization Code + PKCE.", true, false),
            ]);

        public Task<IReadOnlyList<ManagementClientAvailableScope>> GetAvailableScopesAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementClientAvailableScope>>(
            [
                new("openid", "Identidade OpenID", "Identifica o usuário.", [], true),
                new("test.scope", "Acesso de teste", "Permissão da API de teste.", ["test-api"], false),
            ]);

        public Task<IReadOnlyList<ManagementClientDraftSummary>> ListAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementClientDraftSummary>>(
            [
                new(DraftId, ManagementClientProfiles.Spa, "SPA pública",
                    ManagementClientDraftSteps.Permissions, "test-spa", "Test SPA",
                    true, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(14)),
            ]);

        public Task<ManagementClientDraftDetail> CreateAsync(
            string profile,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) => Task.FromResult(Draft);

        public Task<ManagementClientDraftDetail> GetAsync(
            Guid id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) => Task.FromResult(Draft);

        public Task<ManagementClientDraftDetail> SaveAsync(
            SaveManagementClientDraftCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) => Task.FromResult(Draft);

        public Task<CompleteManagementClientDraftResult> CompleteAsync(
            Guid id,
            string version,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task AbandonAsync(
            Guid id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubDatabaseMonitoringService
        : IDatabaseMonitoringService
    {
        private static readonly DatabaseRuntimeSnapshot Snapshot = new(
            new DateTimeOffset(2026, 8, 7, 3, 0, 0, TimeSpan.Zero),
            TotalCommands: 42,
            FailedCommands: 0,
            Pools: [],
            ActiveConnections: [],
            new DatabaseWatchdogSnapshot(
                Enabled: true,
                Status: "healthy",
                ConsecutiveFailures: 0,
                LastProbeAtUtc: new DateTimeOffset(
                    2026,
                    8,
                    7,
                    3,
                    0,
                    0,
                    TimeSpan.Zero),
                LastLatencyMilliseconds: 4,
                LastFailureCode: null));

        public Task<DatabaseRuntimeSnapshot> GetAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Snapshot);

        public async IAsyncEnumerable<DatabaseRuntimeSnapshot> WatchAsync(
            ManagementRequestContext context,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            yield return Snapshot;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    private sealed class StubClaimManagementService : IClaimManagementService
    {
        private static readonly ManagementClaimAssignment Claim = new(
            1,
            "user-1",
            "alice",
            "alice@tests.local",
            "urn:tests:locale",
            "pt-BR");

        public Task<ManagementClaimMetadata> GetMetadataAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementClaimMetadata(
                ["locale", "zoneinfo"],
                256,
                4096));

        public Task<ManagementClaimPage> SearchAsync(
            ManagementClaimSearch query,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementClaimPage(
                [Claim],
                1,
                25,
                1,
                query.UserId));

        public Task<ManagementClaimAssignment> GetAsync(
            int id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Claim);

        public Task<ManagementClaimAssignment> CreateAsync(
            CreateManagementClaimCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementClaimAssignment> UpdateAsync(
            int id,
            UpdateManagementClaimCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            int id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubSessionManagementService
        : ISessionManagementService
    {
        public Task<ManagementSessionPage> SearchAsync(
            ManagementSessionSearch query,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementSessionPage(
                [
                    new ManagementSessionSummary(
                        "token-1",
                        "user-1",
                        "alice",
                        "alice@tests.local",
                        "test-client",
                        "Test Client",
                        "authorization-1",
                        "refresh_token",
                        "valid",
                        new DateTimeOffset(
                            2026,
                            7,
                            30,
                            12,
                            0,
                            0,
                            TimeSpan.Zero),
                        new DateTimeOffset(
                            2026,
                            8,
                            29,
                            12,
                            0,
                            0,
                            TimeSpan.Zero),
                        null,
                        true)
                ],
                1,
                25,
                1,
                query.UserId,
                query.ClientId,
                query.ActiveOnly));

        public Task RevokeAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserSessionRevocation> RevokeAllForUserAsync(
            string userId,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubAuthorizationManagementService
        : IAuthorizationManagementService
    {
        public Task<ManagementAuthorizationPage> SearchAsync(
            ManagementAuthorizationSearch query,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementAuthorizationPage(
                [
                    new ManagementAuthorizationSummary(
                        "authorization-1",
                        "user-1",
                        "alice",
                        "alice@tests.local",
                        "test-client",
                        "Test Client",
                        "permanent",
                        "valid",
                        new DateTimeOffset(
                            2026,
                            7,
                            30,
                            12,
                            0,
                            0,
                            TimeSpan.Zero),
                        ["openid", "test.scope"],
                        1,
                        true)
                ],
                1,
                25,
                1,
                query.UserId,
                query.ClientId,
                query.ActiveOnly));

        public Task RevokeAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubScopeManagementService : IScopeManagementService
    {
        private static readonly ManagementScopeDetail Scope = new(
            "scope-1",
            "test.scope",
            "Test scope",
            "Scope used by tests.",
            ["test-api"],
            ["test-client"],
            IsManifestManaged: false);

        public Task<IReadOnlyList<ManagementScopeSummary>> ListAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ManagementScopeSummary>>(
                [
                    new(
                        Scope.Id,
                        Scope.Name,
                        Scope.DisplayName,
                        Scope.Description,
                        Scope.Resources.Count,
                        Scope.ClientIds.Count,
                        Scope.IsManifestManaged)
                ]);

        public Task<ManagementScopeDetail> GetAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Scope);

        public Task<ManagementScopeDetail> CreateAsync(
            CreateManagementScopeCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementScopeDetail> UpdateAsync(
            string id,
            UpdateManagementScopeCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class StubProvisioningManagementService
        : IProvisioningManagementService
    {
        public Task<IdentityProvisioningPlan> PreviewAsync(
            IdentityProvisioningManifest manifest,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Plan());

        public Task<IdentityProvisioningPlan> ApplyAsync(
            IdentityProvisioningManifest manifest,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(Plan());

        private static IdentityProvisioningPlan Plan() =>
            new(
                [
                    new(
                        "client",
                        "test-client",
                        IdentityManifestChangeKind.Create)
                ]);
    }

    private sealed class StubOperatorTokenManagementService
        : IOperatorTokenManagementService
    {
        public Task<OperatorTokenWorkspace> GetWorkspaceAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(
                new OperatorTokenWorkspace(
                    IssuanceEnabled: true,
                    MfaRequired: true,
                    MfaSatisfied: true,
                    DefaultLifetimeSeconds: 900,
                    MaximumLifetimeSeconds: 3600,
                    MaximumCapabilities: 24,
                    AvailableCapabilities:
                    [
                        ManagementCapabilities.ClientsRead,
                        ManagementCapabilities.ClientsUpdate,
                        ManagementCapabilities.ScopesRead,
                    ],
                    ActiveTokens: []));

        public Task<OperatorTokenIssueResult> IssueAsync(
            IssueOperatorTokenCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(
                "A renderização GET não deve emitir credenciais.");

        public Task RevokeAsync(
            string id,
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

    private sealed class StubUserAvatarUrlResolver
        : IUserAvatarUrlResolver
    {
        public Task<string?> ResolveAsync(
            string? userId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>(
                string.IsNullOrWhiteSpace(userId)
                    ? null
                    : $"https://avatars.tests.local/{userId}.jpg");
    }

    private sealed class StubUserManagementService : IUserManagementService
    {
        private static readonly ManagementUserSummary Summary = new(
            "user-1",
            "alice",
            "alice@tests.local",
            EmailConfirmed: true,
            TwoFactorEnabled: true,
            IsLockedOut: false);

        public Task<ManagementUserAccess> GetAccessAsync(
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserAccess(true, true));

        public Task<ManagementUserPage> SearchAsync(
            ManagementUserSearch query,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ManagementUserPage(
                [Summary],
                1,
                25,
                1,
                new ManagementUserAnalytics(
                    DirectoryTotal: 2_525,
                    MatchingTotal: 1,
                    RegisteredToday: 3,
                    TypicalRegistrationsPerDay: 2,
                    AnomalyThreshold: 11,
                    Days:
                    [
                        new(new DateOnly(2026, 8, 3), 12, IsAnomaly: true),
                        new(new DateOnly(2026, 8, 4), 14, IsAnomaly: true),
                        new(new DateOnly(2026, 8, 5), 18, IsAnomaly: true),
                        new(new DateOnly(2026, 8, 6), 13, IsAnomaly: true)
                    ])));

        public Task<ManagementUserDetail> GetAsync(
            string id,
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
                DateTime.UtcNow,
                new ManagementUserActions(
                    CanResetPassword: true,
                    ResetPasswordRequiresMfa: false,
                    ResetPasswordReasonCode: "allowed",
                    CanSetLockout: true,
                    SetLockoutRequiresMfa: false,
                    SetLockoutReasonCode: "allowed",
                    CanUpdateProfile: true,
                    UpdateProfileRequiresMfa: false,
                    UpdateProfileReasonCode: "allowed",
                    CanDelete: true,
                    DeleteRequiresMfa: false,
                    DeleteReasonCode: "allowed")));

        public Task<ManagementUserDetail> CreateAsync(
            CreateManagementUserCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserDetail> UpdateProfileAsync(
            string id,
            UpdateManagementUserProfileCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserDetail> ResetPasswordAsync(
            string id,
            ResetManagementUserPasswordCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ManagementUserDetail> SetLockoutAsync(
            string id,
            SetManagementUserLockoutCommand command,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task RequestEmailConfirmationAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(
            string id,
            ManagementRequestContext context,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

}
