using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

/// <summary>
/// The deprecated plaintext <c>clientSecret</c> of the Management HTTP
/// create contract (plan A2). New requests name a vault secret through
/// <c>secretReference</c>; this adapter keeps existing callers working until
/// <see cref="ManagementClientSecretOptions.PlaintextExpiresAtUtc"/>, and
/// leaves a trail of every use so the cohort can be found and migrated.
/// </summary>
/// <remarks>
/// The warning is PII-free: no secret, no operator name or e-mail — the
/// operator subject identifier, the client id and the reason code only.
/// </remarks>
public sealed class PlaintextClientSecretAdapter(
    IOptions<ManagementOptions> options,
    AppDbContext database,
    TimeProvider timeProvider,
    ILogger<PlaintextClientSecretAdapter> logger)
{
    public const string DeprecatedReasonCode = "client_secret_plaintext_deprecated";
    public const string ExpiredReasonCode = "client_secret_plaintext_expired";
    public const string AmbiguousReasonCode = "client_secret_source_ambiguous";

    public DateTimeOffset ExpiresAtUtc =>
        options.Value.ClientSecrets.PlaintextExpiresAtUtc;

    /// <summary>
    /// Accepts or refuses a plaintext secret on a Management HTTP request.
    /// Throws <see cref="ManagementValidationException"/> once the adapter has
    /// expired, or when the request also names a <c>secretReference</c>.
    /// </summary>
    public async Task AcceptAsync(
        string? clientId,
        bool hasSecretReference,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        if (hasSecretReference)
        {
            throw new ManagementValidationException(
                AmbiguousReasonCode,
                "Send either secretReference or the deprecated clientSecret, not both.",
                "clientSecret");
        }

        var expired = timeProvider.GetUtcNow() >= ExpiresAtUtc;
        var reasonCode = expired ? ExpiredReasonCode : DeprecatedReasonCode;
        logger.LogWarning(
            "Management client request carried a plaintext clientSecret ({ReasonCode}); "
            + "the adapter {State} at {ExpiresAtUtc:O}. Use secretReference. "
            + "ClientId={ClientId} OperatorSubject={OperatorSubject} CorrelationId={CorrelationId}",
            reasonCode,
            expired ? "expired" : "expires",
            ExpiresAtUtc,
            clientId,
            context.OperatorSubject,
            context.CorrelationId);

        try
        {
            var audit = ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.ClientsCreate,
                new ManagementResource(ManagementResourceTypes.Client, clientId),
                ManagementAuthorizationDecision.Allowed(),
                expired ? "rejected" : "warning",
                reasonCode);
            audit.OperatorDisplayName = null;
            database.ManagementAuditEvents.Add(audit);
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Unable to persist the plaintext client secret audit warning. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }

        if (expired)
        {
            throw new ManagementValidationException(
                ExpiredReasonCode,
                $"Plaintext clientSecret is no longer accepted since {ExpiresAtUtc:yyyy-MM-dd}. "
                + "Store the secret in the vault and send secretReference instead.",
                "clientSecret");
        }
    }
}
