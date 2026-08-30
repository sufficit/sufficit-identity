using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Sufficit.Identity.Management.Authorization;

/// <summary>
/// Capacidades de um principal de MÁQUINA, lidas do registro do cliente.
///
/// Um token de <c>client_credentials</c> não passa por nenhuma das fontes de
/// capacidade do resolvedor comum: o claim <c>permission</c> só é emitido a
/// partir de um operador autenticado, e o cliente não está em papel de usuário
/// nenhum. Antes disto, a única forma de dar acesso de gestão a um serviço era
/// pô-lo num papel de administrador — trocar "não consegue nada" por "consegue
/// tudo".
///
/// A concessão mora no BANCO, na propriedade <c>identity:client:roles</c> do
/// próprio cliente, exatamente como a de um humano mora em <c>userroles</c>. O
/// que o papel significa continua em <c>RoleCapabilities</c>, que é config
/// revisada. É a mesma divisão que já valia para gente: o banco diz quem é o
/// quê, a configuração diz o que isso permite.
///
/// Duas consequências que motivaram este desenho, e não a alternativa de
/// declarar as capacidades direto na configuração:
///
/// - <b>revogar não exige implantação.</b> Tirar o papel é um UPDATE. Numa
///   configuração, revogar o acesso de um serviço comprometido dependeria de
///   publicar — e publicar é o que quebra primeiro num dia ruim;
/// - <b>revogar vale na hora.</b> A consulta acontece na checagem, não na
///   emissão do token. Capacidade carimbada dentro do token sobrevive à
///   revogação até ele expirar.
/// </summary>
public sealed class ServicePrincipalEntitlementResolver(
    IManagementEntitlementResolver inner,
    IServicePrincipalRoleSource roles,
    IOptions<ManagementOptions> options) : IManagementEntitlementResolver
{
    public async ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var resolved = await inner.ResolveAsync(principal, cancellationToken);

        if (!ManagementPrincipal.IsService(principal))
        {
            return resolved;
        }

        var clientId = ManagementPrincipal.ClientId(principal);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return resolved;
        }

        var declared = await roles.RolesAsync(clientId, cancellationToken);
        if (declared.Count == 0)
        {
            return resolved;
        }

        var authorization = options.Value.Authorization;
        var capabilities = new HashSet<string>(resolved.Capabilities, StringComparer.Ordinal);
        var machine = new HashSet<string>(StringComparer.Ordinal);

        foreach (var role in declared)
        {
            if (authorization.FullAdministratorRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            {
                // Serviço em papel de administrador total é decisão da
                // implantação, e continua valendo — mas fica explícito aqui em
                // vez de acontecer por acidente.
                machine.UnionWith(ManagementCapabilities.All);
                continue;
            }

            if (!authorization.RoleCapabilities.TryGetValue(role, out var mapped))
            {
                continue;
            }

            foreach (var raw in mapped ?? [])
            {
                var capability = ManagementCapabilities.Normalize(raw);
                // Nome desconhecido é ignorado: ele já não abre nada, e
                // derrubar a resolução por um erro de digitação na config
                // tiraria do ar as capacidades válidas do mesmo cliente.
                if (ManagementCapabilities.All.Contains(capability))
                {
                    machine.Add(capability);
                }
            }
        }

        capabilities.UnionWith(machine);

        // Tudo o que uma máquina recebe é isento de MFA, e nada além disso.
        //
        // Não é indulgência: um principal autenticado por segredo de cliente
        // nunca carrega `amr`, então exigir segundo fator dele não é uma trava,
        // é uma negação permanente. O controle dele são os papéis que o banco
        // lhe dá e o que a configuração diz que esses papéis permitem.
        return resolved with
        {
            Capabilities = capabilities,
            MultiFactorExempt = machine
        };
    }

}
