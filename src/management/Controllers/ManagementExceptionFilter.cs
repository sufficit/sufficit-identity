using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Controllers;

internal sealed class ManagementExceptionFilter : IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        if (context.Exception is IdentityProvisioningManifestException manifest)
        {
            var manifestDetails = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Manifesto de provisioning inválido",
                Detail = "Corrija os campos listados em errors. Nenhuma alteração foi feita no banco.",
                Instance = context.HttpContext.Request.Path
            };
            manifestDetails.Extensions["reasonCode"] =
                "provisioning_manifest_invalid";
            manifestDetails.Extensions["correlationId"] =
                context.HttpContext.TraceIdentifier;
            manifestDetails.Extensions["errors"] = manifest.Errors;
            context.Result = new ObjectResult(manifestDetails)
            {
                StatusCode = StatusCodes.Status400BadRequest
            };
            context.ExceptionHandled = true;
            return;
        }

        var mapping = context.Exception switch
        {
            ManagementValidationException validation =>
                (StatusCodes.Status400BadRequest,
                    "Requisição de Management inválida",
                    validation.Message,
                    validation.ReasonCode,
                    validation.Field),
            ManagementConflictException conflict =>
                (StatusCodes.Status409Conflict,
                    "Configuração impede a operação",
                    conflict.Message,
                    conflict.ReasonCode,
                    (string?)null),
            ManagementNotFoundException notFound =>
                (StatusCodes.Status404NotFound,
                    "Recurso de Management não encontrado",
                    notFound.Message,
                    notFound.ReasonCode,
                    (string?)null),
            ManagementAccessException access
                when access.Decision.Outcome is
                    ManagementAuthorizationOutcome.StepUpRequired =>
                (StatusCodes.Status403Forbidden,
                    "MFA necessário para continuar",
                    "A sessão está autenticada, mas ainda não comprovou MFA. Conclua o segundo fator e repita a operação.",
                    access.Decision.ReasonCode,
                    (string?)null),
            ManagementAccessException access =>
                (StatusCodes.Status403Forbidden,
                    "Capability necessária ausente",
                    AccessDetail(access.Decision),
                    access.Decision.ReasonCode,
                    (string?)null),
            _ => default
        };

        if (mapping == default)
        {
            return;
        }

        var details = new ProblemDetails
        {
            Status = mapping.Item1,
            Title = mapping.Item2,
            Detail = mapping.Item3,
            Instance = context.HttpContext.Request.Path
        };
        details.Extensions["reasonCode"] = mapping.Item4;
        details.Extensions["correlationId"] =
            context.HttpContext.TraceIdentifier;
        if (context.Exception is ManagementAccessException accessException
            && !string.IsNullOrWhiteSpace(
                accessException.Decision.RequiredCapability))
        {
            details.Extensions["requiredPermission"] =
                accessException.Decision.RequiredCapability;
        }
        if (mapping.Item5 is not null)
        {
            details.Extensions["field"] = mapping.Item5;
        }

        context.Result = new ObjectResult(details)
        {
            StatusCode = mapping.Item1
        };
        context.ExceptionHandled = true;
    }

    private static string AccessDetail(
        ManagementAuthorizationDecision decision) =>
        decision.ReasonCode switch
        {
            "operator_not_authenticated" =>
                "Não há uma sessão autenticada. Faça login no Management e repita a operação.",
            "capability_not_granted" =>
                "A sessão está autenticada, mas o operador não recebeu a capability exigida pela operação.",
            "tenant_not_accessible" =>
                "O operador possui a capability, mas não está associado ao tenant do recurso.",
            "tenant_policy_unavailable" =>
                "A política de acesso do tenant não está disponível; o Identity bloqueou a operação por segurança.",
            _ => "A operação foi bloqueada por uma regra de autorização do Identity. Consulte reasonCode e correlationId para diagnóstico."
        };
}
