using System.Text.Json;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Leitura e validação dos entitlements concedidos ao registro de um cliente.
/// </summary>
/// <remarks>
/// Estes valores viram claim de autorização no token de uma conta de máquina,
/// então o que passa daqui é o que o serviço do outro lado vai obedecer. A
/// validação existe para que um valor malformado não mude de sentido no
/// caminho — não para adivinhar o vocabulário de quem consome.
/// </remarks>
public sealed class ClientEntitlementsTests
{
    private static IReadOnlyDictionary<string, JsonElement> Properties(string json) =>
        new Dictionary<string, JsonElement>
        {
            [ClientEntitlements.PropertyName] = JsonDocument.Parse(json).RootElement.Clone(),
        };

    [Fact]
    public void Reads_a_list()
    {
        var values = ClientEntitlements.Read(
            Properties("[\"aiuser:33333333-3333-3333-3333-333333333333\",\"aicontrol:x\"]"));

        Assert.Equal(
            ["aiuser:33333333-3333-3333-3333-333333333333", "aicontrol:x"],
            values);
    }

    [Fact]
    public void Reads_a_single_string()
    {
        // Quem edita a propriedade à mão costuma escrever a string solta;
        // recusar isso deixaria o cliente sem capacidade e sem explicação.
        Assert.Equal(["aiuser:abc"], ClientEntitlements.Read(Properties("\"aiuser:abc\"")));
    }

    [Fact]
    public void An_absent_property_grants_nothing()
    {
        Assert.Empty(ClientEntitlements.Read(
            new Dictionary<string, JsonElement>()));
    }

    [Fact]
    public void Repeated_values_are_granted_once()
    {
        Assert.Single(ClientEntitlements.Read(Properties("[\"aiuser:a\",\"aiuser:a\"]")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    // Espaço partiria o valor em dois do outro lado: há consumidores que tratam
    // listas separadas por espaço, inclusive o claim "scope" da RFC 9068.
    [InlineData("aiuser:a b")]
    [InlineData(" aiuser:a")]
    [InlineData("aiuser:a ")]
    // Caracteres de controle atravessam log e cabeçalho.
    [InlineData("aiuser:a\nrole:administrator")]
    [InlineData("aiuser:a\tb")]
    public void Malformed_values_are_dropped(string value)
    {
        Assert.False(ClientEntitlements.IsUsable(value));
        Assert.Empty(ClientEntitlements.Read(
            Properties(JsonSerializer.Serialize(new[] { value }))));
    }

    [Fact]
    public void An_oversized_value_is_dropped()
    {
        Assert.False(ClientEntitlements.IsUsable(new string('a', 257)));
        Assert.True(ClientEntitlements.IsUsable(new string('a', 256)));
    }

    [Fact]
    public void One_bad_value_does_not_discard_the_good_ones()
    {
        var values = ClientEntitlements.Read(
            Properties("[\"aiuser:bom\",\"com espaco\",\"aicontrol:bom\"]"));

        Assert.Equal(["aiuser:bom", "aicontrol:bom"], values);
    }

    [Fact]
    public void Non_string_entries_are_ignored()
    {
        // Um número ou objeto na lista não vira claim por coerção.
        Assert.Equal(
            ["aiuser:bom"],
            ClientEntitlements.Read(Properties("[\"aiuser:bom\",42,{\"a\":1},null]")));
    }

    [Fact]
    public void The_claim_type_is_fixed_and_cannot_be_chosen()
    {
        // A escalada que os entitlements de ESCOPO tiveram que fechar com uma
        // lista de tipos proibidos não existe aqui: o operador concede valores,
        // nunca tipos. Se algum dia alguém tornar o tipo configurável, este
        // teste é o lembrete de por que não deveria.
        Assert.Equal("entitlements", ClientEntitlements.ClaimType);
        Assert.Equal("directive", ClientEntitlements.LegacyClaimType);
    }
}
