using System.Text.Json;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// The audit row of a scope-grant denial, alike for every entry point
/// (Management, provisioning, dynamic registration).
/// </summary>
/// <remarks>
/// PII-free by construction: it carries the operator's subject identifier
/// (never a name or e-mail), the client id, scope names, grant types and
/// reason codes. <see cref="ManagementAuditEvent.Capability"/> records the
/// capability the operator lacked, so a query on the capability finds every
/// attempt to grant it.
/// </remarks>
public static class ClientScopeGrantAudit
{
    public const string ResourceType = "client";

    /// <summary>
    /// <c>denied</c> when the decision refused the request, <c>observed</c>
    /// when it would have (Observe mode) and the request went ahead.
    /// </summary>
    public static string OperationOutcome(ClientScopeGrantDecision decision) =>
        decision.IsAllowed ? "observed" : "denied";

    public static ManagementAuditEvent Create(
        ClientScopeGrantRequest request,
        ClientScopeGrantDecision decision,
        string operationCapability,
        string correlationId,
        string? authenticationMethods = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(decision);
        var primary = decision.Primary
            ?? throw new ArgumentException(
                "A scope-grant audit row needs at least one denial.",
                nameof(decision));

        return new ManagementAuditEvent
        {
            OccurredAtUtc = DateTime.UtcNow,
            OperatorSubject = Truncate(
                request.Operator.Subject
                    ?? "source:" + request.Source.ToString().ToLowerInvariant(),
                255),
            OperatorDisplayName = null,
            Capability = Truncate(
                primary.RequiredCapability ?? operationCapability,
                150),
            ResourceType = ResourceType,
            ResourceId = string.IsNullOrWhiteSpace(request.ClientId)
                ? null
                : Truncate(request.ClientId, 255),
            AuthorizationOutcome = decision.IsAllowed
                ? "allowed:scope_grant_observe"
                : "denied",
            OperationOutcome = OperationOutcome(decision),
            ReasonCode = Truncate(primary.ReasonCode, 100),
            CorrelationId = Truncate(correlationId, 100),
            AuthenticationMethods = authenticationMethods is null
                ? null
                : Truncate(authenticationMethods, 255),
            AfterJson = JsonSerializer.Serialize(new
            {
                source = request.Source.ToString().ToLowerInvariant(),
                operation = operationCapability,
                mode = decision.Mode.ToString().ToLowerInvariant(),
                grantTypes = decision.GrantTypes,
                denials = decision.Denials.Select(denial => new
                {
                    scope = denial.Scope,
                    reasonCode = denial.ReasonCode,
                    requiredCapability = denial.RequiredCapability,
                    enforced = denial.Enforced,
                }),
            }),
        };
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];
}
