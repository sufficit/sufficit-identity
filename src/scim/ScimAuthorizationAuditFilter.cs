using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
public sealed class ScimAuthorizationAuditHandler(
    IOptions<ScimOptions>? optionsAccessor = null,
    ILogger<ScimAuthorizationAuditHandler>? logger = null)
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

        await AuditAsync(context, authorizeResult);
    }

    /// <summary>
    /// Persists the SCIM authorization audit after another composed result
    /// handler has produced the HTTP response.
    /// </summary>
    public async Task AuditAsync(
        HttpContext context,
        PolicyAuthorizationResult authorizeResult)
    {
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
            var reasonCode = statusCode == 401
                ? "not_authenticated"
                : ResolveForbiddenReason(principal);

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
                ReasonCode = reasonCode,
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

    /// <summary>
    /// Every 403 used to be recorded as <c>scope_denied</c>, which actively
    /// misleads whoever is debugging one: the most common cause on this
    /// surface is the MFA requirement, not a missing scope. SCIM is
    /// machine-to-machine, and a client-credentials token authenticates an
    /// application — it has no <c>sub</c> and can never carry <c>amr</c>, so
    /// <see cref="ScimOptions.RequireMfa"/> (true by default) rejects it no
    /// matter how it is provisioned. Naming that in the audit trail, and
    /// warning once per occurrence in the log, saves the operator from
    /// re-granting a scope the token already has.
    /// </summary>
    private string ResolveForbiddenReason(ClaimsPrincipal principal)
    {
        var options = optionsAccessor?.Value;
        if (options is null)
        {
            return "scope_denied";
        }

        var missingScope = options.EffectiveRequireScope
            && !ScimAuthenticationContext.HasScope(principal, options.RequiredScope);
        if (missingScope)
        {
            return "scope_denied";
        }

        if (options.RequireMfa
            && !ScimAuthenticationContext.HasMfaEvidence(principal))
        {
            if (ScimAuthenticationContext.IsClientCredentialsToken(principal))
            {
                logger?.LogWarning(
                    "SCIM denied a client-credentials token from client {ClientId}: "
                    + "Sufficit:Identity:Scim:RequireMfa is true, but a "
                    + "client-credentials token authenticates an application and "
                    + "can never carry an amr claim, so this caller can never be "
                    + "authorized. Provisioning clients should be constrained by "
                    + "client authentication strength (mTLS or private_key_jwt) "
                    + "instead; disabling RequireMfa weakens the interactive path "
                    + "as well.",
                    principal.FindFirst("client_id")?.Value
                        ?? principal.FindFirst("azp")?.Value);

                return "mfa_required_unsatisfiable_for_client_credentials";
            }

            return "mfa_required";
        }

        return "scope_denied";
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private static string? TruncateOptional(string? value, int maxLength) =>
        string.IsNullOrEmpty(value) ? null : Truncate(value, maxLength);
}
