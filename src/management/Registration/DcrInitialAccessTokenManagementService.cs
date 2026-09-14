using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Registration;

/// <summary>
/// Issues and revokes initial access tokens for dynamic client registration.
/// Issuing one lets a third party create a client, so it requires the same
/// capability as creating a client directly.
/// </summary>
internal sealed class DcrInitialAccessTokenManagementService(
    AppDbContext database,
    ManagementOperationGuard guard,
    TimeProvider timeProvider,
    ILogger<DcrInitialAccessTokenManagementService> logger)
    : IDcrInitialAccessTokenManagementService
{
    internal const int DefaultLifetimeHours = 24;
    internal const int MaximumLifetimeHours = 720;
    private const int ListLimit = 200;

    private static readonly ManagementResource CollectionResource =
        new(ManagementResourceTypes.DcrInitialAccessTokenCollection);

    public async Task<IReadOnlyList<DcrInitialAccessTokenSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            CollectionResource,
            cancellationToken);

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var records = await database.DcrInitialAccessTokens
            .AsNoTracking()
            .OrderByDescending(token => token.CreatedAtUtc)
            .Take(ListLimit)
            .ToListAsync(cancellationToken);
        return records.Select(record => ToSummary(record, now)).ToArray();
    }

    public async Task<DcrInitialAccessTokenIssueResult> IssueAsync(
        IssueDcrInitialAccessTokenCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(context);
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            CollectionResource,
            cancellationToken,
            auditDenial: true);

        var label = command.Label?.Trim();
        if (string.IsNullOrWhiteSpace(label))
        {
            throw new ManagementValidationException(
                "registration_token_label_required",
                "A label identifying the registrant is required.",
                "label");
        }
        if (label.Length > IdentityDatabaseSchema.DcrInitialAccessTokenLabelLength)
        {
            throw new ManagementValidationException(
                "registration_token_label_too_long",
                $"The label must not exceed {IdentityDatabaseSchema.DcrInitialAccessTokenLabelLength} characters.",
                "label");
        }

        var lifetimeHours = command.LifetimeHours ?? DefaultLifetimeHours;
        if (lifetimeHours is < 1 or > MaximumLifetimeHours)
        {
            throw new ManagementValidationException(
                "registration_token_lifetime_invalid",
                $"The lifetime must be between 1 and {MaximumLifetimeHours} hours.",
                "lifetimeHours");
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        var (record, token) = DcrInitialAccessTokenStore.Create(
            label,
            Truncate(context.OperatorSubject),
            now,
            TimeSpan.FromHours(lifetimeHours),
            command.SingleUse ?? true);
        database.DcrInitialAccessTokens.Add(record);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.ClientsCreate,
            new ManagementResource(
                ManagementResourceTypes.DcrInitialAccessToken,
                record.Id.ToString()),
            decision,
            "succeeded",
            "dcr_initial_access_token_issued"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "DCR initial access token issued by {Subject}: tokenId={TokenId}; expiresAt={ExpiresAtUtc}; singleUse={SingleUse}; correlation={CorrelationId}.",
            context.OperatorSubject,
            record.Id,
            record.ExpiresAtUtc,
            record.SingleUse,
            context.CorrelationId);
        return new DcrInitialAccessTokenIssueResult(ToSummary(record, now), token);
    }

    public async Task RevokeAsync(
        Guid id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var resource = new ManagementResource(
            ManagementResourceTypes.DcrInitialAccessToken,
            id.ToString());
        var decision = await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsCreate,
            resource,
            cancellationToken,
            auditDenial: true);

        var record = await database.DcrInitialAccessTokens
            .SingleOrDefaultAsync(token => token.Id == id, cancellationToken)
            ?? throw new ManagementNotFoundException(
                "registration_token_not_found",
                "The registration token does not exist.");

        // Revoking twice is not an error; the first revocation is kept.
        if (record.RevokedAtUtc is null)
        {
            record.RevokedAtUtc = timeProvider.GetUtcNow().UtcDateTime;
            record.RevokedBy = Truncate(context.OperatorSubject);
        }

        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.ClientsCreate,
            resource,
            decision,
            "succeeded",
            "dcr_initial_access_token_revoked"));
        await database.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "DCR initial access token revoked by {Subject}: tokenId={TokenId}; correlation={CorrelationId}.",
            context.OperatorSubject,
            id,
            context.CorrelationId);
    }

    private static DcrInitialAccessTokenSummary ToSummary(
        DcrInitialAccessToken record,
        DateTime nowUtc) =>
        new(
            record.Id,
            record.Label,
            record.TokenHint,
            record.IssuedBy,
            record.CreatedAtUtc,
            record.ExpiresAtUtc,
            record.SingleUse,
            record.RegistrationCount,
            record.LastUsedAtUtc,
            record.RevokedAtUtc,
            record.RevokedAtUtc is not null ? "revoked"
            : record.ExpiresAtUtc <= nowUtc ? "expired"
            : record.SingleUse && record.RegistrationCount > 0 ? "used"
            : "active");

    private static string Truncate(string value) =>
        value.Length <= IdentityDatabaseSchema.DcrInitialAccessTokenSubjectLength
            ? value
            : value[..IdentityDatabaseSchema.DcrInitialAccessTokenSubjectLength];
}
