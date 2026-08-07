using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Scim;

/// <summary>
/// Audits SCIM requests that fail authorization (401/403) — the gap
/// identified in finding L5. Without this filter, denied SCIM requests leave
/// no trace in the management audit table because the [Authorize] policy
/// short-circuits before the provisioning service runs. The filter runs
/// AFTER authorization and inspects the response status code.
/// </summary>
public sealed class ScimAuthorizationAuditHandler
    : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler fallback = new();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        await fallback.HandleAsync(next, context, policy, authorizeResult);

        if ((!authorizeResult.Challenged && !authorizeResult.Forbidden)
            || !context.Request.Path.StartsWithSegments(
                "/scim/v2",
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            var database = context.RequestServices
                .GetRequiredService<AppDbContext>();
            var principal = context.User;
            var subject = principal.FindFirst("sub")?.Value
                ?? principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? "anonymous";
            var operatorName = principal.Identity?.Name ?? subject;
            var statusCode = authorizeResult.Challenged ? 401 : 403;

            database.ManagementAuditEvents.Add(new ManagementAuditEvent
            {
                OccurredAtUtc = DateTime.UtcNow,
                OperatorSubject = Truncate(subject, 255),
                OperatorDisplayName = TruncateOptional(operatorName, 255),
                Capability = "scim.authorization",
                ResourceType = "scim-request",
                ResourceId = TruncateOptional(
                    context.Request.Path.ToString(), 255),
                ContextId = null,
                AuthorizationOutcome = "denied",
                OperationOutcome = statusCode == 401 ? "denied" : "forbidden",
                ReasonCode = statusCode == 401 ? "not_authenticated" : "scope_denied",
                CorrelationId = Truncate(
                    context.TraceIdentifier, 100),
                AuthenticationMethods = null,
            });
            await database.SaveChangesAsync(
                context.RequestAborted);
        }
        catch
        {
            // Audit failure must never block the response.
        }
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private static string? TruncateOptional(string? value, int maxLength) =>
        string.IsNullOrEmpty(value) ? null : Truncate(value, maxLength);
}
