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
    public async Task Portuguese_user_directory_keeps_date_fields_in_pt_BR_when_request_is_en_US()
    {
        await using var app = await CreateHostAsync();
        using var client = app.GetTestClient();

        await SignInAsync(client, "administrator");

        using var response = await client.GetAsync(
            "/management/users?culture=en-US&ui-culture=en-US");
        var html = WebUtility.HtmlDecode(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("<html lang=\"en-US\">", html, StringComparison.Ordinal);
        Assert.Equal(2, html.Split("lang=\"pt-BR\"", StringSplitOptions.None).Length - 1);
        Assert.Equal(2, html.Split("dd/mm/aaaa", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("mm/dd/yyyy", html, StringComparison.Ordinal);
        Assert.Contains("Filtros e ordenação", html, StringComparison.Ordinal);
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
}
