using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
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
public sealed class ScimAuthorizationAuditFilter(
    AppDbContext database) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(
        ActionExecutingContext context,
        ActionExecutionDelegate next)
    {
        var executedContext = await next();

        var statusCode = executedContext.HttpContext.Response.StatusCode;
        // 401 = unauthenticated, 403 = authenticated but scope denied.
        if (statusCode is not (401 or 403))
        {
            return;
        }

        try
        {
            var principal = context.HttpContext.User;
            var subject = principal.FindFirst("sub")?.Value
                ?? principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                ?? "anonymous";
            var operatorName = principal.Identity?.Name ?? subject;

            database.ManagementAuditEvents.Add(new ManagementAuditEvent
            {
                OccurredAtUtc = DateTime.UtcNow,
                OperatorSubject = Truncate(subject, 255),
                OperatorDisplayName = TruncateOptional(operatorName, 255),
                Capability = "scim.authorization",
                ResourceType = "scim-request",
                ResourceId = TruncateOptional(
                    context.HttpContext.Request.Path.ToString(), 255),
                ContextId = null,
                AuthorizationOutcome = "denied",
                OperationOutcome = statusCode == 401 ? "denied" : "forbidden",
                ReasonCode = statusCode == 401 ? "not_authenticated" : "scope_denied",
                CorrelationId = Truncate(
                    context.HttpContext.TraceIdentifier, 100),
                AuthenticationMethods = null,
            });
            await database.SaveChangesAsync(
                context.HttpContext.RequestAborted);
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
