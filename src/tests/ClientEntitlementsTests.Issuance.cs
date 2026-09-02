using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Os entitlements concedidos ao registro precisam CHEGAR ao token.
/// </summary>
/// <remarks>
/// Ler e validar a propriedade não prova emissão: o OpenIddict só serializa um
/// claim que tenha destino declarado, então um claim sem caso em
/// <c>GetDestinations</c> é montado, descartado em silêncio, e o servidor de
/// recurso nega tudo sem ninguém entender por quê. Este teste existe por causa
/// desse silêncio.
/// <para>
/// A conta é configurada para access token no formato JWT — que é como um
/// serviço externo consegue validar por metadados públicos, e também a única
/// forma de inspecionar o conteúdo aqui. O padrão da implantação é token de
/// referência opaco, cujo payload é cifrado; e a introspecção devolve só claims
/// padrão, então nenhum dos dois responderia à pergunta.
/// </para>
/// </remarks>
public sealed class ClientEntitlementsIssuanceTests
{
    private const string Granted = "aiuser:33333333-3333-3333-3333-333333333333";

    [Fact]
    public async Task Granted_entitlements_reach_the_access_token()
    {
        var clientId = $"svc-ent-{Guid.NewGuid():N}";
        using var factory = CreateFactory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();

        var secret = await CreateAccountAsync(factory, clientId, [Granted]);
        var claims = await IssueAndReadClaimsAsync(factory, clientId, secret);

        Assert.Equal(Granted, Single(claims, ClientEntitlements.ClaimType));
        // O nome curto continua sendo emitido enquanto os consumidores da casa
        // (sufficit-ai, sufficit-provisioning) não migram para o container da
        // RFC 9068 §2.2.3.2.
        Assert.Equal(Granted, Single(claims, ClientEntitlements.LegacyClaimType));
    }

    [Fact]
    public async Task An_account_without_a_grant_gets_no_entitlement_claim()
    {
        var clientId = $"svc-sem-{Guid.NewGuid():N}";
        using var factory = CreateFactory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();

        var secret = await CreateAccountAsync(factory, clientId, entitlements: null);
        var claims = await IssueAndReadClaimsAsync(factory, clientId, secret);

        Assert.False(claims.TryGetProperty(ClientEntitlements.ClaimType, out _));
        Assert.False(claims.TryGetProperty(ClientEntitlements.LegacyClaimType, out _));
    }

    [Fact]
    public async Task A_malformed_grant_never_reaches_the_token()
    {
        // Um valor com espaço viraria dois entitlements do outro lado — é o
        // caminho por onde "role administrator" entraria de carona.
        var clientId = $"svc-ruim-{Guid.NewGuid():N}";
        using var factory = CreateFactory(clientId);
        await ((IAsyncLifetime)factory).InitializeAsync();

        var secret = await CreateAccountAsync(
            factory, clientId, ["aiuser:bom", "role administrator"]);
        var claims = await IssueAndReadClaimsAsync(factory, clientId, secret);

        Assert.Equal("aiuser:bom", Single(claims, ClientEntitlements.ClaimType));
        Assert.DoesNotContain(
            "administrator", claims.GetRawText(), StringComparison.Ordinal);
    }

    private static ManagementTestFactory CreateFactory(string clientId) =>
        new(extraConfiguration: new Dictionary<string, string?>
        {
            // Regra por cliente: JWS auto-contido, sem cifragem, como um
            // servidor de recurso externo receberia.
            [$"Sufficit:Identity:Tokens:AccessTokenFormatsByClient:{clientId}"] = "Jwt",
        });

    private static async Task<string> CreateAccountAsync(
        ManagementTestFactory factory,
        string clientId,
        IReadOnlyList<string>? entitlements)
    {
        var secret = $"s-{Guid.NewGuid():N}";
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.ClientCredentials,
            },
        };

        if (entitlements is not null)
        {
            descriptor.Properties[ClientEntitlements.PropertyName] =
                JsonSerializer.SerializeToElement(entitlements);
        }

        await applications.CreateAsync(descriptor);
        return secret;
    }

    private static async Task<JsonElement> IssueAndReadClaimsAsync(
        ManagementTestFactory factory, string clientId, string secret)
    {
        using var http = factory.CreateClient();
        using var response = await http.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.ClientCredentials,
                ["client_id"] = clientId,
                ["client_secret"] = secret,
            }));

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);

        using var document = JsonDocument.Parse(body);
        var token = document.RootElement.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(token));

        return ReadPayload(token!);
    }

    /// <summary>
    /// Decodifica o payload do JWS. Não valida assinatura: quem valida é o
    /// servidor de recurso, e o que este teste pergunta é o CONTEÚDO.
    /// </summary>
    private static JsonElement ReadPayload(string token)
    {
        var parts = token.Split('.');
        Assert.True(parts.Length == 3, $"token não é um JWS: {parts.Length} partes");

        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');

        return JsonDocument
            .Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)))
            .RootElement.Clone();
    }

    /// <summary>Claim único vem como string; repetido, como array.</summary>
    private static string Single(JsonElement claims, string claimType)
    {
        Assert.True(
            claims.TryGetProperty(claimType, out var element),
            $"claim ausente no token: {claimType} — payload {claims.GetRawText()}");

        return element.ValueKind == JsonValueKind.Array
            ? element.EnumerateArray().First().GetString()!
            : element.GetString()!;
    }
}
