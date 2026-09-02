using System.Collections.Immutable;
using System.Text.Json;

namespace Sufficit.Identity.STS;

/// <summary>
/// Entitlements concedidos ao registro de um cliente.
/// </summary>
/// <remarks>
/// Um token de <c>client_credentials</c> não passa por nenhuma fonte de claims:
/// o handler monta uma identidade crua com <c>sub</c>, nome, escopos e
/// recursos. Isso deixava uma conta de máquina sem como receber uma concessão
/// que não fosse papel — e papel é categoria, não instância. Um agente que
/// precisa acessar o contexto <c>X</c> precisa dizer QUAL contexto, e isso é um
/// valor.
/// <para>
/// A concessão mora na propriedade <c>identity:client:entitlements</c> do
/// próprio cliente, mesma convenção de <c>identity:client:roles</c>: o banco
/// diz quem tem o quê, e revogar é um UPDATE, sem implantação.
/// </para>
/// <para>
/// O tipo do claim é fixo aqui de propósito. Deixar o operador escolher o tipo
/// seria deixá-lo escrever <c>role</c> ou <c>scope</c> e escalar sozinho — foi
/// exatamente esse buraco que os entitlements de escopo tiveram que fechar com
/// uma lista de tipos proibidos. Aqui não existe a escolha.
/// </para>
/// </remarks>
public static class ClientEntitlements
{
    /// <summary>Propriedade do cliente que guarda a concessão.</summary>
    public const string PropertyName = "identity:client:entitlements";

    /// <summary>
    /// Container padronizado pela RFC 9068 §2.2.3.2, com semântica do SCIM
    /// (RFC 7643 §4.1.2).
    /// </summary>
    public const string ClaimType = "entitlements";

    /// <summary>
    /// Nome curto que os serviços da casa já consomem (sufficit-ai e
    /// sufficit-provisioning). Emitido em paralelo durante a transição: ele não
    /// está no registro IANA e a RFC 7519 §4.3 pede nomes resistentes a
    /// colisão, mas cortá-lo antes dos consumidores migrarem seria quebrar
    /// para ganhar elegância.
    /// </summary>
    public const string LegacyClaimType = "directive";

    /// <summary>Limite defensivo: um token não é lugar para texto livre.</summary>
    private const int MaximumLength = 256;

    /// <summary>
    /// Lê a propriedade e devolve apenas os valores utilizáveis.
    /// </summary>
    /// <remarks>
    /// Aceita lista e string única, como o leitor de papéis: quem escreve à mão
    /// costuma escrever a string, e recusar em silêncio deixaria o cliente sem
    /// capacidade nenhuma sem dizer por quê.
    /// </remarks>
    public static IReadOnlyCollection<string> Read(
        IReadOnlyDictionary<string, JsonElement> properties)
    {
        ArgumentNullException.ThrowIfNull(properties);

        if (!properties.TryGetValue(PropertyName, out var declared))
        {
            return [];
        }

        var values = ImmutableArray.CreateBuilder<string>();

        switch (declared.ValueKind)
        {
            case JsonValueKind.String:
                Collect(declared.GetString(), values);
                break;

            case JsonValueKind.Array:
                foreach (var element in declared.EnumerateArray())
                {
                    if (element.ValueKind == JsonValueKind.String)
                    {
                        Collect(element.GetString(), values);
                    }
                }

                break;
        }

        return values.Distinct(StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// Um entitlement precisa sobreviver ao transporte sem mudar de sentido.
    /// </summary>
    /// <remarks>
    /// Espaço em branco é recusado porque consumidores tratam listas separadas
    /// por espaço; um valor com espaço viraria dois do outro lado. Caracteres de
    /// controle são recusados porque atravessam log e cabeçalho.
    /// </remarks>
    public static bool IsUsable(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= MaximumLength
        && value.Trim().Length == value.Length
        && !value.Any(character => char.IsWhiteSpace(character)
            || char.IsControl(character));

    private static void Collect(string? value, ImmutableArray<string>.Builder values)
    {
        if (IsUsable(value))
        {
            values.Add(value!);
        }
    }
}
