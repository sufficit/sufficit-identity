using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Sufficit.Identity.Management.Authorization;

/// <summary>
/// Adds an actionable, non-sensitive Problem Details body when the management
/// policy rejects an already authenticated token before a controller runs.
/// Other policies and authentication challenges retain the framework's
/// standard behavior and headers.
/// </summary>
public sealed class ManagementAuthorizationMiddlewareResultHandler
    : IAuthorizationMiddlewareResultHandler
{
    private static readonly JsonSerializerOptions SerializerOptions =
        new(JsonSerializerDefaults.Web);
    private readonly AuthorizationMiddlewareResultHandler defaultHandler = new();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (!authorizeResult.Forbidden)
        {
            await defaultHandler.HandleAsync(
                next,
                context,
                policy,
                authorizeResult);
            return;
        }

        var failedRequirements = authorizeResult.AuthorizationFailure?
            .FailedRequirements ?? [];
        var missingScope = failedRequirements
            .OfType<ScopeRequirement>()
            .FirstOrDefault();
        var requiresMfa = failedRequirements.Any(
            requirement => requirement is MfaRequirement);

        if (missingScope is null && !requiresMfa)
        {
            await defaultHandler.HandleAsync(
                next,
                context,
                policy,
                authorizeResult);
            return;
        }

        var details = missingScope is not null
            ? CreateMissingScopeDetails(context, missingScope.Scope)
            : CreateMfaDetails(context);

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/problem+json; charset=utf-8";
        await JsonSerializer.SerializeAsync(
            context.Response.Body,
            details,
            SerializerOptions,
            context.RequestAborted);
    }

    private static ProblemDetails CreateMissingScopeDetails(
        HttpContext context,
        string requiredScope)
    {
        var details = new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = "Permissão OAuth necessária ausente",
            Detail =
                "A sessão está autenticada, mas o token não contém a permissão OAuth exigida. Renove a sessão e tente novamente.",
            Instance = context.Request.Path
        };
        details.Extensions["reasonCode"] = "scope_required";
        details.Extensions["requiredPermission"] = requiredScope;
        details.Extensions["correlationId"] = context.TraceIdentifier;
        return details;
    }

    private static ProblemDetails CreateMfaDetails(HttpContext context)
    {
        var details = new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = "MFA necessário para continuar",
            Detail =
                "A sessão está autenticada, mas o token não contém evidência válida do segundo fator. Renove a sessão concluindo o MFA e tente novamente.",
            Instance = context.Request.Path
        };
        details.Extensions["reasonCode"] = "mfa_required";
        details.Extensions["correlationId"] = context.TraceIdentifier;
        return details;
    }
}
