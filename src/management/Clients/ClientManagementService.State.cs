using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Diagnostics;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientManagementService
{
    /// <summary>
    /// Disables or re-enables a client (plan E1). The state lives in the
    /// client's own properties, which a manifest re-apply preserves; every
    /// replica learns of it through <see cref="IDisabledClientRegistry"/>.
    /// Operational state, not configuration: allowed on manifest-managed
    /// clients too.
    /// </summary>
    public async Task<ManagementClientDetail> SetStateAsync(
        SetManagementClientStateCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var clientId = command.ClientId?.Trim() ?? string.Empty;
        var resource = new ManagementResource(ManagementResourceTypes.Client, clientId);
        var decision = await guard.DemandAsync(
            context, ManagementCapabilities.ClientsUpdate, resource, cancellationToken, auditDenial: true);

        var reason = string.IsNullOrWhiteSpace(command.Reason) ? null : command.Reason.Trim();
        if (reason is { Length: > ClientOperationalState.MaxReasonLength })
            throw new ManagementValidationException("client_state_reason_too_long",
                $"The reason must have at most {ClientOperationalState.MaxReasonLength} characters.", "reason");
        if (!command.Enabled && reason is null)
            throw new ManagementValidationException("client_state_reason_required",
                "Say why the client is being disabled.", "reason");

        var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
        if (application is not OpenIddictEntityFrameworkCoreApplication entity)
        {
            await guard.TryWriteAuditAsync(context, ManagementCapabilities.ClientsUpdate, resource, decision,
                "not-found", "client_not_found", cancellationToken);
            throw new ManagementNotFoundException("client_not_found", $"Client '{clientId}' was not found.");
        }
        if (!string.IsNullOrWhiteSpace(command.ExpectedVersion)
            && !string.Equals(command.ExpectedVersion, entity.ConcurrencyToken, StringComparison.Ordinal))
            throw new ManagementConflictException("client_changed",
                "The client was changed by another operation. Reload the data before changing its state.");

        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);
        var before = ClientOperationalState.Read(descriptor.Properties.AsReadOnly());
        var after = command.Enabled
            ? null
            : new ClientDisablement(DateTimeOffset.UtcNow, context.OperatorDisplayName ?? context.OperatorSubject, reason);
        if (after is null) descriptor.Properties.Remove(ClientOperationalState.PropertyName);
        else descriptor.Properties[ClientOperationalState.PropertyName] = ClientOperationalState.Write(after);

        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        await applications.UpdateAsync(application, descriptor, cancellationToken);

        int revokedTokens = 0, revokedAuthorizations = 0;
        if (command.RevokeTokens)
        {
            var applicationId = entity.Id;
            revokedTokens = await database.Set<OpenIddictEntityFrameworkCoreToken>()
                .Where(token => EF.Property<string?>(token, "ApplicationId") == applicationId
                    && (token.Status == OpenIddictConstants.Statuses.Valid
                        || token.Status == OpenIddictConstants.Statuses.Inactive))
                .ExecuteUpdateAsync(set => set.SetProperty(token => token.Status, OpenIddictConstants.Statuses.Revoked),
                    cancellationToken);
            revokedAuthorizations = await database.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .Where(authorization => EF.Property<string?>(authorization, "ApplicationId") == applicationId
                    && authorization.Status == OpenIddictConstants.Statuses.Valid)
                .ExecuteUpdateAsync(set => set.SetProperty(authorization => authorization.Status,
                    OpenIddictConstants.Statuses.Revoked), cancellationToken);
        }

        var audit = ManagementAuditEventFactory.Create(context, ManagementCapabilities.ClientsUpdate, resource,
            decision, "succeeded", command.Enabled ? "client_enabled" : "client_disabled");
        audit.BeforeJson = JsonSerializer.Serialize(new { Status = State(before), before?.Reason });
        audit.AfterJson = JsonSerializer.Serialize(new
        {
            Status = State(after), after?.Reason, command.RevokeTokens, revokedTokens, revokedAuthorizations,
        });
        database.ManagementAuditEvents.Add(audit);
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        logger.LogInformation(
            "Client {ClientId} {State} by {Operator}; revoked {Tokens} tokens and {Authorizations} authorizations. CorrelationId={CorrelationId}",
            LogValue.Sanitize(clientId), State(after), context.OperatorSubject, revokedTokens, revokedAuthorizations, LogValue.Sanitize(context.CorrelationId));

        if (disabledClients is not null)
            await disabledClients.PublishChangeAsync(cancellationToken);

        return await GetByClientIdAsync(clientId, context, cancellationToken);
    }

    private static string State(ClientDisablement? disablement) =>
        disablement is null ? ClientOperationalState.Active : ClientOperationalState.Disabled;
}
