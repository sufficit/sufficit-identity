using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.Resources;

namespace Sufficit.Identity.STS.Grants;

/// <summary>
/// Audit trail and user notification for delegated credentials. Every
/// issuance and every refusal becomes one row in the management audit table;
/// no token value, thumbprint or subject-token content is ever recorded.
/// </summary>
public sealed class DelegatedCredentialEvents(
    AppDbContext database,
    IEmailSender emailSender,
    IStringLocalizer<AccountMessages> messages,
    SufficitIdentityOptions options,
    IHttpContextAccessor httpContextAccessor,
    ILogger<DelegatedCredentialEvents> logger)
{
    public const string Capability = "token_exchange.delegated_credential";

    public async Task RecordRefusalAsync(
        string actor,
        string callerClientId,
        string reason,
        string? label,
        CancellationToken cancellationToken)
    {
        logger.LogWarning(
            "Delegated credential refused for {Actor} by client {ClientId}: {Reason}.",
            Sanitize(actor), Sanitize(callerClientId), reason);
        await WriteAsync(new ManagementAuditEvent
        {
            OperatorSubject = Truncate(actor, 255),
            Capability = Capability,
            ResourceType = "authorization",
            ResourceId = null,
            AuthorizationOutcome = "denied",
            OperationOutcome = "refused",
            ReasonCode = Truncate(reason, 100),
            AfterJson = JsonSerializer.Serialize(new
            {
                delegator = callerClientId,
                label,
            }),
        }, cancellationToken);
    }

    /// <returns><see langword="false"/> when the audit row could not be
    /// written; the issuer then withdraws the credential (fail closed).</returns>
    public async Task<bool> RecordIssuedAsync(
        ApplicationUser user,
        string authorizationId,
        string callerClientId,
        string delegateClientId,
        string label,
        IReadOnlyCollection<string> scopes,
        DateTimeOffset expiresAt,
        IReadOnlyCollection<string> replacedAuthorizationIds,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Delegated credential {AuthorizationId} issued to client {DelegateClientId} for user {UserId} by client {ClientId}; {ReplacedCount} replaced.",
            authorizationId, Sanitize(delegateClientId), user.Id, Sanitize(callerClientId),
            replacedAuthorizationIds.Count);
        return await WriteAsync(new ManagementAuditEvent
        {
            OperatorSubject = Truncate(user.Id, 255),
            OperatorDisplayName = Truncate(user.UserName, 255),
            Capability = Capability,
            ResourceType = "authorization",
            ResourceId = Truncate(authorizationId, 255),
            AuthorizationOutcome = "allowed",
            OperationOutcome = "issued",
            ReasonCode = replacedAuthorizationIds.Count > 0 ? "replaced_same_label" : null,
            AfterJson = JsonSerializer.Serialize(new
            {
                delegator = callerClientId,
                @delegate = delegateClientId,
                label,
                scopes,
                expires_at = expiresAt.ToUnixTimeSeconds(),
                replaced = replacedAuthorizationIds,
            }),
        }, cancellationToken);
    }

    /// <summary>
    /// Best effort, after the credential exists: a delivery failure is logged
    /// and never turns a committed issuance into an error the caller would
    /// retry.
    /// </summary>
    public async Task NotifyIssuedAsync(
        ApplicationUser user,
        string delegatorDisplayName,
        string label,
        DateTimeOffset expiresAt)
    {
        if (!user.EmailConfirmed || string.IsNullOrWhiteSpace(user.Email))
        {
            return;
        }

        try
        {
            var subject = messages["DelegatedCredential.Subject",
                options.Branding.ProductName].Value;
            var body = messages["DelegatedCredential.Body",
                HtmlEncoder.Default.Encode(delegatorDisplayName),
                HtmlEncoder.Default.Encode(label),
                HtmlEncoder.Default.Encode(expiresAt.UtcDateTime.ToString(
                    "yyyy-MM-dd HH:mm 'UTC'",
                    System.Globalization.CultureInfo.InvariantCulture))].Value;
            await emailSender.SendEmailAsync(user.Email, subject, body);
        }
        catch (Exception exception)
        {
            logger.LogError(exception,
                "Delegated credential notification could not be delivered to user {UserId}.",
                user.Id);
        }
    }

    private async Task<bool> WriteAsync(ManagementAuditEvent audit, CancellationToken cancellationToken)
    {
        audit.OccurredAtUtc = DateTime.UtcNow;
        audit.CorrelationId = Truncate(
            httpContextAccessor.HttpContext?.TraceIdentifier ?? Guid.NewGuid().ToString("N"),
            100);
        try
        {
            database.ManagementAuditEvents.Add(audit);
            await database.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // The log line above already carries the decision; a failing audit
            // write must not change the protocol answer.
            database.ChangeTracker.Clear();
            logger.LogError(exception, "Delegated credential audit row could not be written.");
            return false;
        }
    }

    private static string Truncate(string? value, int maxLength) =>
        string.IsNullOrEmpty(value)
            ? string.Empty
            : value.Length <= maxLength ? value : value[..maxLength];

    private static string Sanitize(string? value) =>
        (value ?? string.Empty).Replace("\r", string.Empty).Replace("\n", string.Empty);
}
