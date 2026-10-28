using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientManagementService
{
    /// <summary>
    /// Asks the shared scope-grant decision whether this operator may put
    /// these scopes on this client (plan A2), records any denial, and throws
    /// when it is enforced.
    /// </summary>
    /// <param name="currentScopes">
    /// Scopes the client already has. Keeping one the operator could not grant
    /// is not an expansion and is not refused.
    /// </param>
    private async Task AuthorizeScopeGrantAsync(
        ManagementRequestContext context,
        string operationCapability,
        string clientId,
        IReadOnlyCollection<string> grantTypes,
        IReadOnlyCollection<string> requestedScopes,
        IReadOnlyCollection<string>? currentScopes,
        CancellationToken cancellationToken)
    {
        var resolved = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var request = new ClientScopeGrantRequest(
            ClientDefinitionSource.Management,
            new ClientScopeGrantOperator(
                context.Operator.Identity?.IsAuthenticated is true
                    ? context.OperatorSubject
                    : null,
                resolved.Capabilities),
            clientId,
            grantTypes,
            requestedScopes,
            currentScopes);
        var decision = scopeGrants.Decide(request);
        if (decision.Denials.Count == 0)
        {
            return;
        }

        var primary = decision.Primary!;
        logger.LogWarning(
            "Client scope grant {Outcome}: {ReasonCode} for scopes {Scopes} "
            + "(mode {Mode}). ClientId={ClientId} OperatorSubject={OperatorSubject} "
            + "CorrelationId={CorrelationId}",
            ClientScopeGrantAudit.OperationOutcome(decision),
            primary.ReasonCode,
            string.Join(' ', decision.Denials.Select(denial => denial.Scope)),
            decision.Mode,
            clientId,
            context.OperatorSubject,
            context.CorrelationId);

        try
        {
            database.ManagementAuditEvents.Add(ClientScopeGrantAudit.Create(
                request,
                decision,
                operationCapability,
                context.CorrelationId,
                context.AuthenticationMethods));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to persist the client scope-grant audit row. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }

        if (!decision.IsAllowed)
        {
            throw new ManagementAccessException(
                ManagementAuthorizationDecision.Denied(
                    primary.ReasonCode,
                    primary.RequiredCapability));
        }
    }

    /// <summary>
    /// Non-secret provenance: which vault secret the client's secret came
    /// from, so an inventory can tell a vault-backed client from one whose
    /// secret travelled in plaintext.
    /// </summary>
    internal const string SecretReferenceProperty =
        "identity:management:secret-reference";

    private static void SetSecretReference(
        IDictionary<string, System.Text.Json.JsonElement> properties,
        ManagementClientSecretReference reference) =>
        properties[SecretReferenceProperty] =
            System.Text.Json.JsonSerializer.SerializeToElement(
                reference.ToString());

    private static IReadOnlyCollection<string> ScopePermissions(
        IEnumerable<string> permissions) =>
        permissions
            .Where(permission => permission.StartsWith(
                OpenIddictConstants.Permissions.Prefixes.Scope,
                StringComparison.Ordinal))
            .Select(permission =>
                permission[OpenIddictConstants.Permissions.Prefixes.Scope.Length..])
            .ToArray();
}
