#if !APPLICATION_CONTRACTS
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.Management.Authorization;

/// <summary>
/// Os papéis que o registro de um cliente declara.
///
/// Interface estreita de propósito: o resolvedor precisa de UMA pergunta, e
/// depender do <c>IOpenIddictApplicationManager</c> inteiro por causa dela
/// obrigaria qualquer teste a fingir umas quarenta operações que ele não usa —
/// um duplo que mente sobre o que exercita.
/// </summary>
public interface IServicePrincipalRoleSource
{
    ValueTask<IReadOnlyCollection<string>> RolesAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Lê os papéis da propriedade do cliente no banco — a mesma convenção
/// <c>identity:client:*</c> que o registro dinâmico já usa para origem,
/// user-agent e data de registro.
/// </summary>
public sealed class OpenIddictServicePrincipalRoleSource(
    IOpenIddictApplicationManager applications,
    IOptions<ManagementOptions> options) : IServicePrincipalRoleSource
{
    public async ValueTask<IReadOnlyCollection<string>> RolesAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
        if (application is null)
        {
            return [];
        }

        var properties = await applications.GetPropertiesAsync(application, cancellationToken);
        return properties.TryGetValue(
            options.Value.Authorization.ClientRolesPropertyName, out var declared)
            ? Parse(declared)
            : [];
    }

    /// <summary>
    /// A propriedade é persistida como <see cref="JsonElement"/>. Aceita lista
    /// e string única: quem escreve à mão costuma escrever a string, e recusar
    /// isso seria recusar em silêncio — o cliente ficaria sem capacidade
    /// nenhuma e nada diria por quê.
    /// </summary>
    private static IReadOnlyCollection<string> Parse(JsonElement declared)
    {
        var roles = ImmutableArray.CreateBuilder<string>();

        switch (declared.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in declared.EnumerateArray())
                {
                    var value = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        roles.Add(value.Trim());
                    }
                }
                break;

            case JsonValueKind.String:
                foreach (var value in (declared.GetString() ?? string.Empty)
                    .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries))
                {
                    roles.Add(value.Trim());
                }
                break;
        }

        return roles.ToImmutable();
    }
}
#endif
