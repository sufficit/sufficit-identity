using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.UI.Management.Clients;

namespace Sufficit.Identity.UI.Management.Provisioning;

/// <summary>
/// Turns authorization and dependency outcomes into operator-facing guidance.
/// Internal reason codes remain available as secondary support details without
/// becoming the primary message.
/// </summary>
internal static class ProvisioningErrorMessages
{
    public static ManagementDataResult<T> AccessFailure<T>(
        ManagementAuthorizationDecision decision,
        string operation,
        string capability) =>
        ManagementDataResult<T>.Failure(
            ToOutcome(decision),
            AccessMessage(decision, operation, capability),
            errorDetails: [AccessNextStep(decision, capability)]);

    public static ManagementDataResult<T> ConflictFailure<T>(
        ManagementConflictException exception,
        string operation) =>
        ManagementDataResult<T>.Failure(
            ManagementDataOutcome.Conflict,
            exception.Message,
            errorDetails: [ConflictNextStep(exception, operation)]);

    public static string TimeoutMessage(string operation) =>
        $"O Identity demorou para {operation} e a operação foi interrompida antes de confirmar o resultado.";

    public static string DependencyMessage(string operation) =>
        $"O Identity não conseguiu {operation}. Confira se o módulo Management está implantado, " +
        "se a base de dados está disponível e tente novamente.";

    private static ManagementDataOutcome ToOutcome(
        ManagementAuthorizationDecision decision) =>
        decision.Outcome is ManagementAuthorizationOutcome.StepUpRequired
            ? ManagementDataOutcome.StepUpRequired
            : ManagementDataOutcome.Forbidden;

    private static string AccessMessage(
        ManagementAuthorizationDecision decision,
        string operation,
        string capability) =>
        decision.ReasonCode switch
        {
            "operator_not_authenticated" =>
                $"Não há uma sessão autenticada para {operation}.",
            "capability_not_granted" =>
                $"A sessão está autenticada, mas falta a capability {capability} para {operation}.",
            "mfa_required" =>
                $"A sessão está autenticada, mas o MFA ainda não foi comprovado para {operation}.",
            "tenant_not_accessible" =>
                $"A conta possui a capability, mas não tem acesso ao tenant usado por {operation}.",
            "tenant_policy_unavailable" =>
                "A política de acesso do tenant não está disponível; a operação foi bloqueada por segurança.",
            "temporary_token_cannot_mint" =>
                "Um token temporário não pode emitir outro token temporário.",
            _ =>
                $"O Identity recusou {operation} por uma regra de segurança."
        };

    private static string AccessNextStep(
        ManagementAuthorizationDecision decision,
        string capability) =>
        decision.ReasonCode switch
        {
            "operator_not_authenticated" =>
                "Próximo passo: faça login no Management e repita a operação.",
            "capability_not_granted" =>
                $"Próximo passo: peça a um administrador para atribuir {capability} ao seu operador.",
            "mfa_required" =>
                "Próximo passo: conclua o segundo fator e retorne ao Management; senha isolada não basta.",
            "tenant_not_accessible" =>
                "Próximo passo: peça a associação do seu operador ao tenant correto.",
            "tenant_policy_unavailable" =>
                "Próximo passo: peça à equipe de infraestrutura para configurar a política de tenant antes de tentar novamente.",
            "temporary_token_cannot_mint" =>
                "Próximo passo: autentique-se novamente como operador humano para emitir um novo token.",
            _ => $"Código de suporte: {decision.ReasonCode}."
        };

    private static string ConflictNextStep(
        ManagementConflictException exception,
        string operation) =>
        exception.ReasonCode switch
        {
            "temporary_provisioning_token_disabled" =>
                "Próximo passo: a infraestrutura deve definir " +
                "Sufficit__Identity__Management__TemporaryProvisioningToken__Enabled=true " +
                "e implantar essa configuração antes de emitir tokens.",
            "temporary_provisioning_token_issuer_missing" =>
                "Próximo passo: configure o issuer público " +
                "Sufficit:Identity:Issuer e reinicie o Identity.",
            "provisioning_secret_unavailable" =>
                "Próximo passo: verifique a referência de segredo do cliente e o acesso ao secret store; nenhuma alteração foi aplicada.",
            _ =>
                $"Próximo passo: verifique a configuração necessária para {operation} " +
                "ou peça ao administrador do Identity para corrigir o ambiente."
        };
}
