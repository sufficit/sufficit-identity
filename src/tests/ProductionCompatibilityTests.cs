using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
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
/// Testes de compatibilidade com o tráfego real observado no STS Skoruba/Duende
/// legado em eveo-apps (produção). As requisições foram capturadas dos access logs
/// nginx em 2026-07-21 (sanitizadas — sem tokens/state/nonce reais) e estão
/// documentadas em <c>Fixtures/production-requests.json</c>.
///
/// Estes testes validam que o novo STS OpenIddict ABSORVE o mesmo tráfego sem
/// regressões (B8 do EVALUATION-glm-2026-07-21.md). Estratégia:
///
/// 1. Registra no test factory os mesmos client_ids reais observados em produção
///    (SufficitWebForms, sufficit_mobile_apps, SufficitBlazorServer, etc.),
///    com grants/permissions alinhados ao que cada client realmente usa.
/// 2. Replays as requisições reais (queryParams method exato como capturado).
/// 3. Asserta o comportamento esperado — que NÃO seja regressão silenciosa:
///    - fluxos suportados devem funcionar;
///    - fluxos legados removidos pelo OAuth 2.1 devem rejeitar com erro claro;
///    - paths de scanner devem 404/400 sem expor informação.
///
/// O dado de produção capturou 4 categorias:
///  - 86% do volume: <c>/connect/userinfo</c> e <c>/connect/introspect</c> (já
///    cobertos por AuthorizationCodeFlowTests/IntrospectionTests indiretamente
///    — este suite replica com tokens emitidos a partir dos clients reais).
///  - WebForms + SwaggerUI legados: <c>response_type=code id_token</c> e
///    <c>response_type=token</c> (implicit/hybrid — OAuth 2.1 remove).
///  - Mobile AppAuth: PKCE puro (já suportado, validado aqui com redirect_uri
///    custom scheme real).
///  - Device flow + PAR (já cobertos, mantidos por regressão).
/// </summary>
[Collection(StsCollection.Name)]
public sealed class ProductionCompatibilityTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public ProductionCompatibilityTests(SufficitIdentityTestFactory factory) => _factory = factory;

    // ---- client_ids reais observados em eveo-apps/production ----
    private const string WebFormsClientId = "SufficitWebForms";
    private const string WebFormsRedirectUri = "https://www.sufficit.com.br/oauth/authenticated";
    private const string MobileAppsClientId = "sufficit_mobile_apps";
    private const string MobileAppsRedirectUri = "sufficitaigateway://callback";
    private const string MobileAiModelsClientId = "sufficit_mobile_ai_models";
    private const string MobileAiModelsRedirectUri = "sufficitmobileaimodels://callback";
    private const string SwaggerClientId = "SufficitEndPointsSwaggerUI";
    private const string SwaggerRedirectUri = "https://endpoints.sufficit.com.br/oauth2-redirect.html";

    private async Task SeedProductionClientAsync(
        string clientId,
        string? secret,
        string redirectUri,
        params string[] permissions)
    {
        using var scope = _factory.Services.CreateScope();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await appManager.FindByClientIdAsync(clientId) is not null) return;

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = secret is null ? ClientTypes.Public : ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
            Permissions = { Permissions.Endpoints.Authorization, Permissions.Endpoints.Token },
        };

        if (secret is not null) descriptor.ClientSecret = secret;
        descriptor.RedirectUris.Add(new Uri(redirectUri));

        foreach (var p in permissions) descriptor.Permissions.Add(p);

        await appManager.CreateAsync(descriptor);
    }

    // ====================================================================
    // WebForms legado — implicit/hybrid (response_type=code id_token + form_post)
    // ====================================================================

    [Fact]
    public async Task WebForms_legacy_hybrid_authorize_request_is_rejected_with_unsupported_response_type()
    {
        // OAuth 2.1 remove fluxos implicit/hybrid. O novo STS (OpenIddict 7+)
        // NÃO registra implicit/hybrid flows — a requisição real do WebForms
        // legado DEVE falhar com erro claro indicando que o fluxo não é
        // suportado, em vez de comportamento indefinido. Este client DEVE ser
        // migrado para authorization_code + PKCE antes da Onda E.
        //
        // Captura de produção (fixtures/authz-01):
        //   response_type=code id_token + response_mode=form_post
        await SeedProductionClientAsync(
            WebFormsClientId, secret: null, WebFormsRedirectUri,
            Permissions.ResponseTypes.Code,        // só code é registrado
            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess,
            Permissions.Prefixes.Scope + Scopes.Roles);

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var query = new Dictionary<string, string?>
        {
            ["client_id"] = WebFormsClientId,
            ["redirect_uri"] = WebFormsRedirectUri,
            ["response_type"] = "code id_token", // hybrid — não suportado
            ["scope"] = "offline_access openid profile roles",
            ["state"] = "STATE.authenticationproperties=opaque",
            ["response_mode"] = "form_post",
            ["nonce"] = "NONCE.opaque",
            ["x-client-sku"] = "id_net472",
            ["x-client-ver"] = "8.14.0.0",
        };

        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", query));

        // OpenIddict pode responder de 3 formas para response_type não-suportado:
        //  (a) 302 redirect para redirect_uri com ?error=unsupported_response_type
        //      (quando consegue validar client/redirect_uri primeiro);
        //  (b) 400 BadRequest com JSON { error: "unsupported_response_type" }
        //      (em outros casos);
        //  (c) 400 com JSON { error: "invalid_request" } (varia por versão).
        // Qualquer um dos três é aceitável — o importante é que NÃO é 200 e
        // o erro é claro. Não deve nunca retornar um code válido.
        Assert.False(response.IsSuccessStatusCode,
            $"Hybrid flow should be rejected, got success: {response.StatusCode}");

        var rawBody = await response.Content.ReadAsStringAsync();
        var error = await ExtractErrorAsync(response);
        Assert.True(
            error is "unsupported_response_type" or "invalid_request",
            $"Expected unsupported_response_type or invalid_request for hybrid flow. " +
            $"Status={response.StatusCode}, Location={response.Headers.Location}, " +
            $"ContentType={response.Content.Headers.ContentType}, Body={rawBody.Substring(0, Math.Min(400, rawBody.Length))}, " +
            $"ExtractedError={error}");
    }

    // ====================================================================
    // Mobile AppAuth — authorization_code + PKCE (já suportado)
    // ====================================================================

    [Fact]
    public async Task Mobile_AppAuth_authorize_request_with_custom_scheme_redirect_succeeds()
    {
        // Captura de produção (fixtures/authz-02): sufficit_mobile_apps com
        // redirect_uri custom scheme (sufficitaigateway://callback). Valida
        // que o novo STS aceita redirect_uri não-HTTPS (custom scheme é o
        // padrão para apps mobile com AppAuth).
        var username = $"mobile-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#10";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        await SeedProductionClientAsync(
            MobileAppsClientId, secret: null, MobileAppsRedirectUri,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code,
            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile,
            Permissions.Prefixes.Scope + Scopes.Email,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess);
        // Adiciona requisito de PKCE — mobile AppAuth sempre envia.
        // (não há como adicionar Requirements via SeedProductionClientAsync,
        //  mas OpenIddict valida code_challenge quando presente.)

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        // PKCE: code_verifier local → challenge enviado.
        var (verifier, challenge) = Pkce.CreatePair();

        var query = new Dictionary<string, string?>
        {
            ["redirect_uri"] = MobileAppsRedirectUri,
            ["client_id"] = MobileAppsClientId,
            ["response_type"] = "code",
            ["state"] = "STATE",
            ["nonce"] = "NONCE",
            ["scope"] = "openid profile email offline_access",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };

        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", query));

        // Usuário autenticado + ConsentTypes.Implicit → redirect para redirect_uri
        // com code. Sucesso = 302 para sufficitaigateway://callback?code=...
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location ?? throw new InvalidOperationException("No redirect Location.");
        Assert.StartsWith(MobileAppsRedirectUri, location.ToString());

        var redirectQuery = QueryHelpers.ParseQuery(location.Query);
        Assert.False(
            redirectQuery.TryGetValue("error", out var error),
            $"/connect/authorize unexpectedly failed: {error}");
        Assert.False(string.IsNullOrEmpty(redirectQuery["code"].ToString()));
    }

    [Fact]
    public async Task Mobile_Ai_Models_AppAuth_authorize_with_distinct_custom_scheme_succeeds()
    {
        // Captura de produção (fixtures/authz-03): variante com redirect_uri
        // sufficitmobileaimodels://callback. Garante que múltiplos apps mobile
        // coexistem sem conflito de redirect.
        var username = $"aimodels-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#11";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        await SeedProductionClientAsync(
            MobileAiModelsClientId, secret: null, MobileAiModelsRedirectUri,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code,
            Permissions.Prefixes.Scope + Scopes.OpenId,
            Permissions.Prefixes.Scope + Scopes.Profile,
            Permissions.Prefixes.Scope + Scopes.Email,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess);

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        var (_, challenge) = Pkce.CreatePair();

        var query = new Dictionary<string, string?>
        {
            ["redirect_uri"] = MobileAiModelsRedirectUri,
            ["client_id"] = MobileAiModelsClientId,
            ["response_type"] = "code",
            ["state"] = "STATE",
            ["nonce"] = "NONCE",
            ["scope"] = "openid profile email offline_access",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };

        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", query));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith(MobileAiModelsRedirectUri, response.Headers.Location!.ToString());
    }

    // ====================================================================
    // SwaggerUI — implicit (response_type=token), OAuth 2.1 remove
    // ====================================================================

    [Fact]
    public async Task SwaggerUI_legacy_implicit_token_request_is_rejected_with_unsupported_response_type()
    {
        // Captura de produção (fixtures/authz-04): SufficitEndPointsSwaggerUI
        // usando response_type=token (implicit access_token). OAuth 2.1 remove.
        // SwaggerUI moderno suporta PKCE — mesma situação do WebForms, deve ser
        // migrado antes da Onda E.
        await SeedProductionClientAsync(
            SwaggerClientId, secret: null, SwaggerRedirectUri,
            Permissions.ResponseTypes.Code,
            Permissions.Prefixes.Scope + "policies");

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "token",
            ["client_id"] = SwaggerClientId,
            ["redirect_uri"] = SwaggerRedirectUri,
            ["scope"] = "policies",
            ["state"] = "STATE=",
        };

        using var response = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", query));

        // Mesmo padrão do WebForms hybrid: OpenIddict pode responder como 302
        // com erro na query string OU 400 com JSON. Ambos aceitáveis.
        Assert.False(response.IsSuccessStatusCode,
            $"Implicit flow should be rejected, got success: {response.StatusCode}");

        var error = await ExtractErrorAsync(response);
        Assert.True(
            error is "unsupported_response_type" or "invalid_request",
            $"Expected unsupported_response_type or invalid_request for implicit flow, got: {error}");
    }

    // ====================================================================
    // /connect/userinfo — segundo endpoint mais batido (valida fix #B1 sub bug)
    // ====================================================================

    [Fact]
    public async Task Userinfo_endpoint_returns_401_without_bearer_token_not_500()
    {
        // Captura de produção (fixtures/userinfo-01): /connect/userinfo é o
        // endpoint mais batido em volume. Quase todos User-Agent vazio
        // (chamada server-to-server). Sem Bearer deve 401, não 500.
        var client = _factory.CreateClient();

        using var response = await client.GetAsync("/connect/userinfo");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Userinfo_endpoint_with_valid_bearer_returns_user_claims_with_sub()
    {
        // Bug histórico #B1: GetUserAsync(User) resolvia sub via
        // ClaimTypes.NameIdentifier mas token carrega sub em "sub" — sempre
        // retornava null. Fix em AuthorizationController.cs:561. Como
        // /connect/userinfo é o endpoint MAIS batido em produção (200k+
        // amostras), este teste é load-bearing para o cutover.
        var username = $"userinfo-{Guid.NewGuid():N}";
        const string password = "Str0ng!Passw0rd#12";

        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(userManager, username, password);
        }

        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await TestOnlyEndpoints.SignInAsync(client, username);

        // Usa o client pré-registrado pelo TestDataSeeder (test-authcode) para
        // obter o access_token — o que importa é validar o /connect/userinfo,
        // não o fluxo até ele ( AuthorizationCodeFlowTests já cobre o auth_code).
        var (verifier, challenge) = Pkce.CreatePair();

        var authQuery = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            // Scopes limitados ao que o test-authcode tem permissão (OpenId +
            // Profile + ScopeName). Email não está permissionado no seeder;
            // o que importa para este teste é validar o /connect/userinfo em
            // si (sub-lookup fix), não a presença de email claim.
            ["scope"] = "openid profile " + TestDataSeeder.ScopeName,
            ["state"] = Guid.NewGuid().ToString("N"),
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };

        using var authResponse = await client.GetAsync(
            QueryHelpers.AddQueryString("/connect/authorize", authQuery));
        Assert.Equal(HttpStatusCode.Redirect, authResponse.StatusCode);

        var location = authResponse.Headers.Location!;
        var redirectQuery = QueryHelpers.ParseQuery(location.Query);
        Assert.False(redirectQuery.TryGetValue("error", out _),
            $"authorize failed: {redirectQuery.GetValueOrDefault("error")}");
        var code = redirectQuery["code"].ToString();

        var (_, tokenBody) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestDataSeeder.AuthorizationCodeRedirectUri,
            ["client_id"] = TestDataSeeder.AuthorizationCodeClientId,
            ["code_verifier"] = verifier,
        });

        var accessToken = tokenBody.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        using var userinfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        userinfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var userinfoResponse = await client.SendAsync(userinfoRequest);

        Assert.Equal(HttpStatusCode.OK, userinfoResponse.StatusCode);
        var userinfo = await userinfoResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(string.IsNullOrEmpty(userinfo.GetProperty("sub").GetString()));
        Assert.Equal(username, userinfo.GetProperty("name").GetString());
    }

    // ====================================================================
    // Discovery — adapters públicos (Grafana, etc.) só veem capabilities reais
    // ====================================================================

    [Fact]
    public async Task Discovery_document_does_not_advertise_implicit_or_hybrid_grants()
    {
        // Indiretamente coberto por DiscoveryTests, mas aqui valida do ponto
        // de vista do cliente real (Grafana, que é o 2o client_id mais frequente
        // com 3300 amostras): se ele tentar descobrir grant_types suportados,
        // só deve ver os suportados.
        var client = _factory.CreateClient();

        using var response = await client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var doc = await response.Content.ReadFromJsonAsync<JsonElement>();

        // response_types_supported: code deve estar, "id_token" e "token"
        // (implicit/hybrid) NÃO devem estar — alinha com OAuth 2.1.
        var responseTypes = doc.GetProperty("response_types_supported")
            .EnumerateArray().Select(r => r.GetString()).ToArray();

        Assert.Contains("code", responseTypes);
        Assert.DoesNotContain("id_token", responseTypes);
        Assert.DoesNotContain("token", responseTypes);
        Assert.DoesNotContain("code id_token", responseTypes);
        Assert.DoesNotContain("code token", responseTypes);
        Assert.DoesNotContain("code id_token token", responseTypes);
    }

    // ====================================================================
    // /connect/check-session e backchannel-logout — probes (não implementados)
    // ====================================================================

    [Fact]
    public async Task Check_session_endpoint_returns_404_not_advertised_in_discovery()
    {
        // Captura de produção (fixtures/probe-01): 2 probes para
        // /connect/check-session e /connect/checksession. Não implementado e
        // NÃO anunciado em discovery — deve 404 limpo.
        var client = _factory.CreateClient();

        using var response1 = await client.GetAsync("/connect/check-session");
        using var response2 = await client.GetAsync("/connect/checksession");

        Assert.Equal(HttpStatusCode.NotFound, response1.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, response2.StatusCode);
    }

    [Fact]
    public async Task Backchannel_logout_endpoint_accepts_post_but_is_not_advertised_in_discovery()
    {
        // Captura de produção (fixtures/probe-02): 1 POST para
        // /connect/backchannel-logout. Endpoint existe como no-op ack stub
        // (AuthorizationController.cs BackchannelLogout) mas NÃO é anunciado
        // em discovery (B4 fix: backchannel_logout_supported=false).
        var client = _factory.CreateClient();

        using var discoveryResponse = await client.GetAsync("/.well-known/openid-configuration");
        var doc = await discoveryResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(doc.GetProperty("backchannel_logout_supported").GetBoolean());

        // Endpoint aceita POST (ack stub — sem validação real de logout_token
        // porque distribuição real não está implementada; não anunciado, então
        // nenhum RP deveria bater aqui).
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["logout_token"] = "fake-token-not-validated",
        });
        using var response = await client.PostAsync("/connect/backchannel-logout", content);

        // Ack stub retorna 200 mesmo com token inválido — não anunciado, baixo risco.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ====================================================================
    // Scanners (wordpress/.env probes) — não devem expor info
    // ====================================================================

    [Fact]
    public async Task Scanner_attempt_with_wordpress_path_in_authorize_is_rejected()
    {
        // Captura de produção (fixtures/scanner-01): tentativas de scanner
        // wordpress contra /connect/authorize?...wlwmanifest.xml. Não é OAuth
        // válido; OpenIddict rejeita com erro claro.
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await client.GetAsync(
            "/connect/authorize?client_id=wp-includes/wlwmanifest.xml&response_type=code");

        // OpenIddict rejeita client_id inexistente — 400 com erro, nunca 200.
        Assert.True(
            (int)response.StatusCode >= 400,
            $"Scanner probe should be rejected with 4xx/5xx, got: {response.StatusCode}");
    }

    [Fact]
    public async Task Scanner_attempt_for_dotenv_under_account_returns_404()
    {
        // Captura de produção (fixtures/scanner-02): /account/.env não existe.
        var client = _factory.CreateClient();

        using var response = await client.GetAsync("/account/.env");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    /// <summary>
    /// Extrai o campo <c>error</c> de qualquer formato de resposta do
    /// OpenIddict para <c>/connect/authorize</c>:
    ///  (a) query string (302 redirect com ?error=...);
    ///  (b) JSON body (400 com {"error":"..."} );
    ///  (c) text/plain body (400 com "error:...\nerror_description:..." —
    ///      formato do handler de erro default do OpenIddict para erros
    ///      descobertos ANTES de autenticar o client, ex: response_type
    ///      inválido quando o client existe mas a permission não cobre aquele
    ///      response_type).
    /// </summary>
    private static async Task<string?> ExtractErrorAsync(HttpResponseMessage response)
    {
        // (a) redirect para redirect_uri?error=...
        if (response.Headers.Location is { } location)
        {
            var query = QueryHelpers.ParseQuery(location.Query);
            if (query.TryGetValue("error", out var errorFromQuery))
            {
                return errorFromQuery.ToString();
            }
        }

        var contentType = response.Content.Headers.ContentType?.MediaType ?? "";

        // (b) JSON body { error: "..." }
        if (contentType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var body = await response.Content.ReadFromJsonAsync<JsonElement>();
                if (body.TryGetProperty("error", out var errorProp))
                {
                    return errorProp.GetString();
                }
            }
            catch (Exception)
            {
                /* fall through */
            }
        }

        // (c) text/plain body — formato "error:value\nerror_description:value"
        if (contentType.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase))
        {
            var body = await response.Content.ReadAsStringAsync();
            foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Trim().StartsWith("error:", StringComparison.OrdinalIgnoreCase))
                {
                    return line.Split(':', 2)[1].Trim();
                }
            }
        }

        return null;
    }
}
