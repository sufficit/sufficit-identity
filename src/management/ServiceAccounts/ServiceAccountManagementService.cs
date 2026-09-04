using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.ServiceAccounts;

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

    public async Task<ServiceAccountCreated> CreateAsync(
        CreateServiceAccountCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Criar exige ClientsCreate E ClientsUpdate. Papéis concedem
        // capacidades de gestão, então criar uma conta JÁ COM papéis é a mesma
        // concessão de privilégio que atribuí-los depois — pedir só a
        // capacidade de criar abriria o atalho que o comentário da classe
        // descreve, agora pela porta da criação.
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            new ManagementResource(ManagementResourceTypes.Client, command.ClientId),
            cancellationToken,
            auditDenial: true);
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            new ManagementResource(ManagementResourceTypes.Client, command.ClientId),
            cancellationToken,
            auditDenial: true);

        var clientId = (command.ClientId ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ManagementValidationException(
                "client_id_required",
                "Informe o identificador da conta de sistema.",
                field: "clientId");
        }

        if (await applications.FindByClientIdAsync(clientId, cancellationToken) is not null)
        {
            throw new ManagementValidationException(
                "client_already_exists",
                $"Já existe cliente '{clientId}'.",
                field: "clientId");
        }

        var authorization = options.Value.Authorization;
        var roles = NormalizeRoles(command.Roles, authorization);

        // Segredo gerado pelo servidor por padrão: 256 bits de CSPRNG. Uma
        // credencial de máquina não expira sozinha, então a força dela não pode
        // depender do que um humano digitou com pressa.
        var secret = string.IsNullOrWhiteSpace(command.ClientSecret)
            ? Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32))
            : command.ClientSecret.Trim();

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = secret,
            DisplayName = string.IsNullOrWhiteSpace(command.DisplayName)
                ? clientId
                : command.DisplayName.Trim(),
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
        };

        // A forma é fixa de propósito: uma conta de sistema fala com o endpoint
        // de token por client_credentials e nada mais. Sem redirect, sem fluxo
        // interativo — não há usuário nessa história.
        descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        descriptor.Permissions.Add(
            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        // Contas de serviço gerenciadas por esta superfície precisam poder
        // solicitar o escopo administrativo que protege as APIs de gestão.
        // A atribuição de escopos reservados é deliberadamente bloqueada no
        // CRUD comum de clientes; aqui ela é parte do perfil fixo e auditado
        // de criação da conta de sistema.
        descriptor.Permissions.Add(
            OpenIddictConstants.Permissions.Prefixes.Scope
            + options.Value.RequiredScope);

        if (roles.Length > 0)
        {
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(roles));
            descriptor.Properties[authorization.ClientRolesPropertyName] =
                document.RootElement.Clone();
        }

        await applications.CreateAsync(descriptor, cancellationToken);

        return new ServiceAccountCreated(
            new ServiceAccountSummary(
                ClientId: clientId,
                DisplayName: descriptor.DisplayName,
                CanRequestTokens: true,
                Roles: roles,
                Capabilities: Resolve(roles, authorization)),
            secret);
    }

    /// <summary>
    /// Papéis distintos, sem brancos, recusando o que esta implantação não
    /// reconhece.
    /// </summary>
    private static string[] NormalizeRoles(
        IReadOnlyList<string>? requested,
        ManagementAuthorizationOptions authorization)
    {
        var roles = (requested ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var known = KnownRoles(authorization).Select(option => option.Role)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unknown = roles.Where(role => !known.Contains(role)).ToArray();
        if (unknown.Length > 0)
        {
            throw new ManagementValidationException(
                "unknown_role",
                $"Papel desconhecido nesta implantação: {string.Join(", ", unknown)}. "
                + "Os papéis válidos vêm de RoleCapabilities e FullAdministratorRoles.",
                field: "roles");
        }

        return roles;
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
