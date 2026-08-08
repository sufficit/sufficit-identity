using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS.Ciba;

public sealed record CibaClientAuthorization(
    bool Allowed,
    object? Application,
    string? ErrorCode = null,
    IReadOnlyList<string>? ReasonCodes = null);

public interface ICibaClientPolicy
{
    Task<CibaClientAuthorization> AuthorizeAsync(
        string? clientId,
        string? clientSecret,
        string operation,
        CancellationToken cancellationToken = default);
}

internal sealed class CibaClientPolicy(
    IOpenIddictApplicationManager applications,
    CibaOptions options,
    ILogger<CibaClientPolicy> logger,
    ISecurityDecisionTelemetry telemetry) : ICibaClientPolicy
{
    public async Task<CibaClientAuthorization> AuthorizeAsync(
        string? clientId,
        string? clientSecret,
        string operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return Denied("client_id_missing");
        }

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            return Denied("client_unknown");
        }

        var clientType = await applications.GetClientTypeAsync(
            application,
            cancellationToken);
        var confidential = string.Equals(
            clientType,
            OpenIddictConstants.ClientTypes.Confidential,
            StringComparison.OrdinalIgnoreCase);
        if (confidential
            && (string.IsNullOrWhiteSpace(clientSecret)
                || !await applications.ValidateClientSecretAsync(
                    application,
                    clientSecret,
                    cancellationToken)))
        {
            return Denied("client_authentication_failed");
        }

        var reasons = new List<string>();
        if (options.RequireConfidentialClient && !confidential)
        {
            reasons.Add("confidential_client_required");
        }
        if (options.AllowedClientIds.Count > 0
            && !options.AllowedClientIds.Contains(clientId))
        {
            reasons.Add("client_not_allowed");
        }
        if (!string.IsNullOrWhiteSpace(options.RequiredGrantPermission)
            && !await applications.HasPermissionAsync(
                application,
                options.RequiredGrantPermission,
                cancellationToken))
        {
            reasons.Add("grant_permission_missing");
        }

        if (reasons.Count > 0)
        {
            logger.LogWarning(
                "CIBA client policy {Mode} decision for operation {Operation} and client {ClientId}: {ReasonCodes}.",
                options.ClientPolicyMode,
                operation,
                clientId,
                string.Join(',', reasons));
        }
        var enforce = reasons.Count > 0
            && options.ClientPolicyMode == SecurityPolicyEnforcementMode.Enforce;
        telemetry.Record(
            "ciba_client",
            options.ClientPolicyMode.ToString(),
            reasons.Count > 0,
            enforce,
            reasons);
        return new CibaClientAuthorization(
            !enforce,
            application,
            enforce ? OpenIddictConstants.Errors.UnauthorizedClient : null,
            reasons);
    }

    private CibaClientAuthorization Denied(string reason)
    {
        telemetry.Record(
            "ciba_client",
            "Mandatory",
            wouldReject: true,
            rejected: true,
            [reason]);
        return new(
            false,
            null,
            OpenIddictConstants.Errors.InvalidClient,
            [reason]);
    }
}
