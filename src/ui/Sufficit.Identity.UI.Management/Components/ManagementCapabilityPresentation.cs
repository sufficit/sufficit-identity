using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.UI.Management.Components;

/// <summary>
/// Human-facing copy for Management capabilities. Keeping the explanation
/// next to the canonical catalog prevents technical identifiers from becoming
/// the only documentation available at the point of delegation.
/// </summary>
public static class ManagementCapabilityPresentation
{
    private static readonly IReadOnlyDictionary<string, CapabilityCopy> Copies =
        new Dictionary<string, CapabilityCopy>(StringComparer.Ordinal)
        {
            [ManagementCapabilities.ClientsRead] = new(
                "Consultar",
                "Consultar aplicações OAuth e OIDC",
                "Usada nas telas de Aplicações e detalhes do cliente para ler Client ID, tipo, fluxos, URLs, permissões e políticas de token. Não permite alterar o cadastro."),
            [ManagementCapabilities.ClientsCreate] = new(
                "Criar",
                "Cadastrar aplicações OAuth e OIDC",
                "Usada no assistente de nova aplicação para criar um cliente e seu Client ID. Não concede permissão para editar ou excluir clientes existentes."),
            [ManagementCapabilities.ClientsUpdate] = new(
                "Atualizar",
                "Editar aplicações OAuth e OIDC",
                "Usada para alterar URLs, fluxos, scopes, consentimento, PKCE e políticas de token de um cliente. As mudanças afetam as próximas autenticações dessa aplicação."),
            [ManagementCapabilities.ClientsDelete] = new(
                "Excluir",
                "Excluir aplicações OAuth e OIDC",
                "Usada para remover o cadastro de um cliente do provedor. Deve ser reservada à retirada de uma integração, pois pode impedir novas autenticações da aplicação."),
            [ManagementCapabilities.BrandingRead] = new(
                "Consultar",
                "Consultar a identidade visual",
                "Usada na área de Branding para visualizar temas, logotipos, cores e demais recursos visuais publicados. Não permite modificar a experiência de autenticação."),
            [ManagementCapabilities.BrandingManage] = new(
                "Administrar",
                "Administrar a identidade visual",
                "Usada para criar, atualizar, publicar ou remover configurações de Branding. As alterações podem mudar a aparência das telas de autenticação para os usuários."),
            [ManagementCapabilities.UsersRead] = new(
                "Consultar",
                "Consultar usuários",
                "Usada no diretório e nos detalhes do usuário para localizar contas, visualizar perfil, status e métodos de acesso. Não permite alterar dados ou credenciais."),
            [ManagementCapabilities.UsersCreate] = new(
                "Criar",
                "Criar usuários",
                "Usada no cadastro administrativo de uma nova conta no provedor. Não concede, por si só, permissão para atribuir claims ou alterar outros usuários."),
            [ManagementCapabilities.UsersUpdate] = new(
                "Atualizar",
                "Editar usuários",
                "Usada para alterar dados do perfil, como nome, e-mail e telefone, nas telas de administração de usuários. Não permite redefinir senha, bloquear ou excluir a conta."),
            [ManagementCapabilities.UsersDisable] = new(
                "Desabilitar",
                "Bloquear ou desbloquear usuários",
                "Usada nos detalhes do usuário para impedir ou restaurar o acesso da conta. É independente da edição de perfil e da redefinição de senha."),
            [ManagementCapabilities.UsersDelete] = new(
                "Excluir",
                "Excluir usuários",
                "Usada para remover uma conta do provedor pela administração. É uma operação sensível e separada das permissões de bloquear ou editar o usuário."),
            [ManagementCapabilities.UsersReset] = new(
                "Redefinir senha",
                "Redefinir a senha de usuários",
                "Usada nos detalhes do usuário para definir uma nova senha administrativa e sinalizar a mudança de credencial. Não permite editar o perfil ou outras formas de acesso."),
            [ManagementCapabilities.ClaimsRead] = new(
                "Consultar",
                "Consultar claims de usuários",
                "Usada na área de Claims para listar os atributos personalizados atribuídos às contas. Permite diagnóstico de identidade, mas não altera valores."),
            [ManagementCapabilities.ClaimsCreate] = new(
                "Criar",
                "Atribuir claims a usuários",
                "Usada para adicionar um novo atributo personalizado a uma conta. O claim pode influenciar informações e decisões consumidas pelas aplicações integradas."),
            [ManagementCapabilities.ClaimsUpdate] = new(
                "Atualizar",
                "Editar claims de usuários",
                "Usada para alterar o tipo ou o valor de um claim personalizado já atribuído. A mudança pode aparecer em tokens e sessões emitidos posteriormente."),
            [ManagementCapabilities.ClaimsDelete] = new(
                "Excluir",
                "Remover claims de usuários",
                "Usada para retirar um atributo personalizado de uma conta. Deve ser aplicada com cuidado quando aplicações dependem desse claim para autorização."),
            [ManagementCapabilities.ScopesRead] = new(
                "Consultar",
                "Consultar scopes OAuth e OIDC",
                "Usada para listar e inspecionar scopes, recursos, claims associados e propriedades de exibição. Não permite mudar o que os clientes podem solicitar."),
            [ManagementCapabilities.ScopesCreate] = new(
                "Criar",
                "Criar scopes OAuth e OIDC",
                "Usada para registrar um novo scope que aplicações poderão solicitar nos fluxos de autorização. A associação aos clientes continua sendo uma configuração separada."),
            [ManagementCapabilities.ScopesUpdate] = new(
                "Atualizar",
                "Editar scopes OAuth e OIDC",
                "Usada para alterar descrição, recursos, claims e demais propriedades de um scope. A mudança pode afetar tokens emitidos futuramente para aplicações autorizadas."),
            [ManagementCapabilities.ScopesDelete] = new(
                "Excluir",
                "Excluir scopes OAuth e OIDC",
                "Usada para remover um scope do provedor. Pode interromper solicitações de aplicações que ainda dependem dele e deve ser precedida por inventário."),
            [ManagementCapabilities.SessionsRead] = new(
                "Consultar",
                "Consultar sessões",
                "Usada na área de Sessões para localizar logins ativos e inspecionar cliente, usuário, datas e estado. Não encerra nenhuma sessão."),
            [ManagementCapabilities.SessionsRevoke] = new(
                "Revogar",
                "Encerrar sessões",
                "Usada para revogar uma sessão selecionada e impedir sua continuidade. É indicada em resposta a logout administrativo, perda de dispositivo ou incidente de segurança."),
            [ManagementCapabilities.AuthorizationsRead] = new(
                "Consultar",
                "Consultar autorizações OAuth e OIDC",
                "Usada para listar consentimentos e concessões persistidas entre usuários e aplicações. Permite investigar o acesso concedido sem revogá-lo."),
            [ManagementCapabilities.AuthorizationsRevoke] = new(
                "Revogar",
                "Revogar autorizações OAuth e OIDC",
                "Usada para retirar uma concessão ou consentimento persistido. A aplicação precisará obter uma nova autorização antes de voltar a usar aquele acesso."),
            [ManagementCapabilities.AuditRead] = new(
                "Consultar",
                "Consultar a auditoria",
                "Usada na trilha de Auditoria para investigar quem executou uma operação, qual capability foi usada, o alvo, o resultado e o correlation ID. Não altera eventos registrados."),
            [ManagementCapabilities.DatabaseRead] = new(
                "Consultar",
                "Consultar a saúde do banco de dados",
                "Usada no monitor operacional para visualizar conectividade, latência, filas e estado do pool de conexões. Não permite consultar registros de negócio nem executar comandos SQL."),
            [ManagementCapabilities.MetricsRead] = new(
                "Consultar",
                "Consultar métricas de uso",
                "Usada na área de Métricas para visualizar volume, falhas, aplicações ativas e estado do coletor. Não permite mudar retenção ou exportação."),
            [ManagementCapabilities.MetricsManage] = new(
                "Administrar",
                "Configurar métricas de uso",
                "Usada para habilitar coleta, definir retenção, lote, timeout e exportação das métricas. A alteração muda o comportamento operacional do coletor."),
            [ManagementCapabilities.VaultSecretsRead] = new(
                "Consultar",
                "Consultar metadados de segredos",
                "Usada no Vault para listar nomes, contextos e metadados dos segredos permitidos ao operador. A interface não revela o valor armazenado."),
            [ManagementCapabilities.VaultSecretsManage] = new(
                "Administrar",
                "Administrar segredos",
                "Usada no Vault para gravar, substituir ou remover valores secretos nos namespaces autorizados. É uma capability sensível e cada alteração fica auditada."),
            [ManagementCapabilities.ProvisioningPreview] = new(
                "Gerar preview",
                "Visualizar o impacto de um manifesto",
                "Usada no Provisionamento para executar inventory e preview, mostrando diferenças antes da aplicação. Não modifica clientes, scopes ou outros recursos."),
            [ManagementCapabilities.ProvisioningApply] = new(
                "Aplicar",
                "Aplicar manifestos de provisionamento",
                "Usada no modo Enforce para criar, atualizar ou reconciliar os recursos descritos por um manifesto. A operação exige confirmação e produz evidência auditável."),
            [ManagementCapabilities.ManagementTokensRead] = new(
                "Consultar",
                "Consultar tokens temporários de Management",
                "Usada na central de Tokens para abrir o workspace e listar metadados dos tokens temporários do administrador autenticado. O valor Bearer nunca é recuperado pela listagem."),
            [ManagementCapabilities.ManagementTokensIssue] = new(
                "Emitir",
                "Emitir tokens temporários de Management",
                "Usada para gerar um Bearer temporário com um subconjunto das capabilities já possuídas pelo administrador. Essa capability não pode ser delegada ao próprio token."),
            [ManagementCapabilities.ManagementTokensRevoke] = new(
                "Revogar",
                "Revogar tokens temporários de Management",
                "Usada para invalidar um token temporário antes de sua expiração. Essa capability não pode ser incorporada a outro token temporário."),
        };

    public static CapabilityCopy Get(string capability) =>
        Copies.TryGetValue(capability, out var copy)
            ? copy
            : new CapabilityCopy(
                "Acesso administrativo",
                capability,
                "Autoriza a operação administrativa identificada por esta capability. Consulte a documentação do módulo antes de delegá-la a uma automação.");

    public static bool HasExplicitCopy(string capability) =>
        Copies.ContainsKey(capability);
}

public sealed record CapabilityCopy(
    string Label,
    string HelpTitle,
    string HelpText);
