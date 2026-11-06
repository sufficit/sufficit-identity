using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Audit;

internal sealed class ManagementAuditService(
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization) : IManagementAuditService
{
    public async Task<IReadOnlyList<ManagementAuditRecord>> ListAsync(
        ManagementRequestContext context,
        int limit = 100,
        CancellationToken cancellationToken = default) =>
        (await SearchAsync(context, new ManagementAuditQuery(Limit: limit), cancellationToken)).Items;

    public async Task<ManagementAuditPage> SearchAsync(
        ManagementRequestContext context,
        ManagementAuditQuery query,
        CancellationToken cancellationToken = default)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.AuditRead,
            new ManagementResource(ManagementResourceTypes.Audit),
            cancellationToken);
        if (!decision.IsAllowed)
            throw new ManagementAccessException(decision);

        ArgumentNullException.ThrowIfNull(query);
        if (query.ResourceType?.Length > 100 || query.ResourceId?.Length > 255)
            throw new ManagementValidationException("audit_filter_invalid",
                "Resource filters exceed their maximum length.");
        if (query.FromUtc is { } from && query.ToUtc is { } to && from >= to)
            throw new ManagementValidationException("audit_interval_invalid",
                "FromUtc must precede ToUtc.", "fromUtc");

        var entries = database.ManagementAuditEvents.AsNoTracking();
        if (!string.IsNullOrEmpty(query.ResourceType))
            entries = entries.Where(entry => entry.ResourceType == query.ResourceType);
        if (!string.IsNullOrEmpty(query.ResourceId))
            entries = entries.Where(entry => entry.ResourceId == query.ResourceId);
        if (query.FromUtc is { } fromUtc)
        {
            var start = fromUtc.UtcDateTime;
            entries = entries.Where(entry => entry.OccurredAtUtc >= start);
        }
        if (query.ToUtc is { } toUtc)
        {
            var end = toUtc.UtcDateTime;
            entries = entries.Where(entry => entry.OccurredAtUtc < end);
        }
        if (query.Cursor is not null)
        {
            var (time, id) = ReadCursor(query.Cursor);
            entries = entries.Where(entry => entry.OccurredAtUtc < time
                || (entry.OccurredAtUtc == time && entry.Id < id));
        }

        var limit = Math.Clamp(query.Limit, 1, 250);
        var rows = await entries
            .OrderByDescending(entry => entry.OccurredAtUtc)
            .ThenByDescending(entry => entry.Id)
            .Take(limit + 1)
            .Select(entry => new ManagementAuditRecord(
                entry.Id,
                entry.OccurredAtUtc,
                entry.OperatorSubject,
                entry.OperatorDisplayName,
                entry.Capability,
                entry.ResourceType,
                entry.ResourceId,
                entry.ContextId,
                entry.AuthorizationOutcome,
                entry.OperationOutcome,
                entry.ReasonCode,
                entry.CorrelationId,
                entry.AuthenticationMethods, entry.BeforeJson, entry.AfterJson))
            .ToArrayAsync(cancellationToken);
        var items = rows.Take(limit).ToArray();
        var nextCursor = rows.Length > limit
            ? FormattableString.Invariant($"{items[^1].OccurredAtUtc.Ticks}:{items[^1].Id}")
            : null;
        return new ManagementAuditPage(items, nextCursor);
    }

    // A cursor is a position, not a credential. Every page rechecks AuditRead;
    // it carries only time/id, never profile values or authorization state.
    private static (DateTime Time, long Id) ReadCursor(string cursor)
    {
        var parts = cursor.Length <= 40 ? cursor.Split(':') : [];
        if (parts.Length != 2
            || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var ticks)
            || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var id)
            || ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks || id <= 0)
            throw new ManagementValidationException("audit_cursor_invalid",
                "Use the nextCursor returned by the preceding page.", "cursor");
        return (new DateTime(ticks, DateTimeKind.Utc), id);
    }
}

internal static class ManagementAuditEventFactory
{
    public static ManagementAuditEvent Create(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision authorization,
        string operationOutcome,
        string? reasonCode = null,
        DateTime? expiresAtUtc = null) =>
        new()
        {
            // Null follows the deployment's default retention.
            ExpiresAtUtc = expiresAtUtc,
            OccurredAtUtc = DateTime.UtcNow,
            OperatorSubject = TruncateRequired(context.OperatorSubject, 255),
            OperatorDisplayName = Truncate(context.OperatorDisplayName, 255),
            Capability = TruncateRequired(capability, 150),
            ResourceType = TruncateRequired(resource.Type, 100),
            ResourceId = Truncate(resource.Id, 255),
            // ContextId carried the tenant identifier of the removed
            // multi-tenant system (2026-08 decision). The column stays for
            // legacy rows; new events record the provider context only.
            ContextId = null,
            AuthorizationOutcome = TruncateRequired(DescribeAuthorization(authorization), 50),
            OperationOutcome = TruncateRequired(operationOutcome, 50),
            ReasonCode = Truncate(reasonCode ?? authorization.ReasonCode, 100),
            CorrelationId = TruncateRequired(context.CorrelationId, 100),
            AuthenticationMethods = Truncate(context.AuthenticationMethods, 255)
        };

    /// <summary>
    /// An allowance with a reason of its own — break-glass on a protected
    /// principal, an Observe-mode pass, self-service — keeps that reason here.
    /// ReasonCode carries the operation's own code ("claim_created"), which
    /// used to overwrite it, so no audit row ever showed a break-glass use
    /// (plan A1).
    /// </summary>
    internal static string DescribeAuthorization(ManagementAuthorizationDecision authorization)
    {
        var outcome = authorization.Outcome.ToString().ToLowerInvariant();
        return authorization.IsAllowed
            && !string.IsNullOrWhiteSpace(authorization.ReasonCode)
            && !string.Equals(authorization.ReasonCode, "allowed", StringComparison.Ordinal)
                ? $"{outcome}:{authorization.ReasonCode}"
                : outcome;
    }

    private static string TruncateRequired(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private static string? Truncate(string? value, int maxLength) =>
        value is null || value.Length <= maxLength ? value : value[..maxLength];
}
