using Sufficit.Identity.Management.Authorization;

// Os CONTRATOS compilam apenas neste projeto (Application.Abstractions, que a
// UI referencia) e a implementação apenas no Management. A exclusividade é
// obrigatória: sem ela o mesmo record existiria nos dois assemblies e quem
// referencia ambos — os testes — morre em CS0433.
//
// Antes isso era garantido por #if APPLICATION_CONTRACTS; hoje é a fronteira de
// arquivo, que é mais fácil de violar sem querer. Ao mover um tipo entre os dois
// projetos, mova — não copie.

namespace Sufficit.Identity.Management.ServiceAccounts;

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

/// <summary>
/// Cria uma conta de sistema: um cliente confidencial que se autentica sozinho
/// (<c>client_credentials</c>) e recebe capacidades pelos papéis declarados.
/// </summary>
/// <param name="ClientSecret">
/// Opcional. Ausente, o servidor gera um segredo forte — o caminho recomendado,
/// porque um segredo escolhido por humano é o elo fraco de uma credencial que
/// não expira sozinha.
/// </param>
public sealed record CreateServiceAccountCommand(
    string ClientId,
    string? DisplayName = null,
    IReadOnlyList<string>? Roles = null,
    string? ClientSecret = null);

/// <summary>
/// A conta recém-criada e o segredo, devolvido UMA ÚNICA VEZ.
/// </summary>
/// <remarks>
/// O segredo é persistido apenas como hash, então não há como reexibi-lo
/// depois: quem não copiar agora precisa rotacionar. A UI trata isso como um
/// passo explícito em vez de um detalhe da resposta.
/// </remarks>
public sealed record ServiceAccountCreated(
    ServiceAccountSummary Account,
    string ClientSecret);

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

    Task<ServiceAccountCreated> CreateAsync(
        CreateServiceAccountCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
