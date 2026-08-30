#if !APPLICATION_CONTRACTS
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Audit;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.ServiceAccounts;

// Mesmo arranjo do ManagementAuthorization.cs: os CONTRATOS compilam apenas na
// Application.Abstractions (que a UI referencia) e a implementação apenas na
// Management. Sem a exclusividade, o mesmo record existiria nos dois assemblies
// e quem referencia ambos — os testes — morre em CS0433.
#if APPLICATION_CONTRACTS

/// <summary>
/// Uma conta de sistema: um cliente OAuth que se autentica sozinho
/// (<c>client_credentials</c>) e recebe capacidades de gestão por PAPÉIS
/// declarados no próprio registro — a propriedade <c>identity:client:roles</c>
/// que o <see cref="ServicePrincipalEntitlementResolver"/> consulta.
/// </summary>
/// <param name="Roles">Os papéis declarados no registro do cliente.</param>
/// <param name="Capabilities">
/// O que esses papéis SIGNIFICAM nesta implantação, já resolvido pelo mesmo
/// mapa que o avaliador usa. A UI mostra os dois porque a pergunta do operador
/// nunca é "que papéis tem?" — é "o que esta conta consegue fazer?".
/// </param>
public sealed record ServiceAccountSummary(
    string ClientId,
    string? DisplayName,
    bool CanRequestTokens,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Capabilities);

/// <summary>Os papéis que esta implantação reconhece, com o significado.</summary>
public sealed record ServiceAccountRoleOption(
    string Role,
    IReadOnlyList<string> Capabilities,
    bool IsFullAdministrator);

public sealed record ServiceAccountWorkspace(
    IReadOnlyList<ServiceAccountSummary> Accounts,
    IReadOnlyList<ServiceAccountRoleOption> KnownRoles);

public sealed record SetServiceAccountRolesCommand(IReadOnlyList<string>? Roles);

public interface IServiceAccountManagementService
{
    Task<ServiceAccountWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ServiceAccountSummary> SetRolesAsync(
        string clientId,
        SetServiceAccountRolesCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

#else

/// <summary>
/// Gestão dos papéis de conta de sistema.
///
/// A leitura exige <c>identity.clients.read</c> e a escrita
/// <c>identity.clients.update</c> — as mesmas capacidades que já governam o
/// registro de clientes, porque é exatamente isso que esta tela edita. Um
/// papel de máquina concede capacidades de GESTÃO, então dar-lhe uma
/// capability própria e mais fraca criaria um atalho de escalada: quem
/// pudesse "só mexer em contas de sistema" poderia dar a uma conta o papel de
/// administrador e entrar por ela.
/// </summary>
public sealed class ServiceAccountManagementService(
    IOpenIddictApplicationManager applications,
    ManagementOperationGuard guard,
    IOptions<ManagementOptions> options) : IServiceAccountManagementService
{
    public async Task<ServiceAccountWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken,
            auditDenial: true);

        var authorization = options.Value.Authorization;
        var accounts = new List<ServiceAccountSummary>();

        await foreach (var application in applications.ListAsync(
            cancellationToken: cancellationToken))
        {
            var permissions = await applications.GetPermissionsAsync(
                application, cancellationToken);
            var canRequestTokens = permissions.Contains(
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);

            var properties = await applications.GetPropertiesAsync(
                application, cancellationToken);
            var roles = properties.TryGetValue(
                authorization.ClientRolesPropertyName, out var declared)
                ? ParseRoles(declared)
                : [];

            // A lista mostra quem PODE agir como sistema (tem o grant) ou quem
            // JÁ tem papel declarado — o segundo caso pega a configuração
            // esquecida: um cliente que perdeu o grant mas ficou com papel é
            // exatamente o resíduo que ninguém encontra sem uma tela.
            if (!canRequestTokens && roles.Count == 0)
            {
                continue;
            }

            accounts.Add(new ServiceAccountSummary(
                ClientId: (string)(await applications.GetClientIdAsync(
                    application, cancellationToken))!,
                DisplayName: (string?)await applications.GetDisplayNameAsync(
                    application, cancellationToken),
                CanRequestTokens: canRequestTokens,
                Roles: roles,
                Capabilities: Resolve(roles, authorization)));
        }

        return new ServiceAccountWorkspace(
            accounts
                .OrderBy(a => a.ClientId, StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            KnownRoles(authorization));
    }

    public async Task<ServiceAccountSummary> SetRolesAsync(
        string clientId,
        SetServiceAccountRolesCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            new ManagementResource(ManagementResourceTypes.Client, clientId),
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(clientId, cancellationToken)
            ?? throw new ManagementValidationException(
                "client_not_found", $"Não existe cliente '{clientId}'.");

        var authorization = options.Value.Authorization;
        var known = KnownRoles(authorization).Select(option => option.Role)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var roles = (command.Roles ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // Papel desconhecido é recusado na ESCRITA, ao contrário da leitura
        // (onde o resolvedor o ignora em silêncio para não derrubar o que é
        // válido). Quem digita "administrador" querendo "administrator" precisa
        // ouvir isso agora, não descobrir num 403 do serviço semanas depois.
        var unknown = roles.Where(role => !known.Contains(role)).ToArray();
        if (unknown.Length > 0)
        {
            throw new ManagementValidationException(
                "unknown_role",
                $"Papel desconhecido nesta implantação: {string.Join(", ", unknown)}. "
                + "Os papéis válidos vêm de RoleCapabilities e FullAdministratorRoles.",
                field: "roles");
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);

        if (roles.Length == 0)
        {
            descriptor.Properties.Remove(authorization.ClientRolesPropertyName);
        }
        else
        {
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(roles));
            descriptor.Properties[authorization.ClientRolesPropertyName] =
                document.RootElement.Clone();
        }

        await applications.UpdateAsync(application, descriptor, cancellationToken);

        var permissions = await applications.GetPermissionsAsync(application, cancellationToken);
        return new ServiceAccountSummary(
            ClientId: clientId,
            DisplayName: (string?)await applications.GetDisplayNameAsync(
                application, cancellationToken),
            CanRequestTokens: permissions.Contains(
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials),
            Roles: roles,
            Capabilities: Resolve(roles, authorization));
    }

    private static IReadOnlyList<ServiceAccountRoleOption> KnownRoles(
        ManagementAuthorizationOptions authorization)
    {
        var known = new List<ServiceAccountRoleOption>();

        foreach (var role in authorization.FullAdministratorRoles)
        {
            known.Add(new ServiceAccountRoleOption(
                role, [.. ManagementCapabilities.All.Order(StringComparer.Ordinal)], true));
        }

        foreach (var (role, mapped) in authorization.RoleCapabilities)
        {
            if (known.Any(option => string.Equals(
                    option.Role, role, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            known.Add(new ServiceAccountRoleOption(
                role, Resolve([role], authorization), false));
        }

        return known
            .OrderBy(option => option.Role, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// A MESMA resolução do <c>ServicePrincipalEntitlementResolver</c>: papel
    /// de administrador total dá tudo; os demais dão o que o mapa diz; nome de
    /// capability desconhecido cai fora. A tela tem que mostrar exatamente o
    /// que o avaliador vai conceder, senão ela vira uma segunda opinião.
    /// </summary>
    private static IReadOnlyList<string> Resolve(
        IReadOnlyList<string> roles,
        ManagementAuthorizationOptions authorization)
    {
        var capabilities = new HashSet<string>(StringComparer.Ordinal);

        foreach (var role in roles)
        {
            if (authorization.FullAdministratorRoles.Contains(
                    role, StringComparer.OrdinalIgnoreCase))
            {
                capabilities.UnionWith(ManagementCapabilities.All);
                continue;
            }

            if (!authorization.RoleCapabilities.TryGetValue(role, out var mapped))
            {
                continue;
            }

            foreach (var raw in mapped ?? [])
            {
                var capability = ManagementCapabilities.Normalize(raw);
                if (ManagementCapabilities.All.Contains(capability))
                {
                    capabilities.Add(capability);
                }
            }
        }

        return capabilities.Order(StringComparer.Ordinal).ToArray();
    }

    private static IReadOnlyList<string> ParseRoles(JsonElement declared)
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
