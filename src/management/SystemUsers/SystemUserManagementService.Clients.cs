using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Sufficit.Identity.Application.Diagnostics;

namespace Sufficit.Identity.Management.SystemUsers;

/// <summary>
/// Clients bound to a system user (<see cref="SystemUserClientBinding"/>).
/// </summary>
/// <remarks>
/// Binding hands a client secret the power to act as the user, so it is a
/// credential operation on the user (<see cref="ManagementCapabilities.UsersReset"/>,
/// minting a credential, or <see cref="ManagementCapabilities.UsersSystem"/>)
/// AND a change to the client registration
/// (<see cref="ManagementCapabilities.ClientsUpdate"/>). Holding only one of
/// them is not enough.
/// </remarks>
internal sealed partial class SystemUserManagementService
{
    public async Task<IReadOnlyList<SystemUserClientSummary>> ListClientsAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        await DemandAsync(context, ManagementCapabilities.UsersRead, UserResource(userId), cancellationToken);
        _ = await FindSystemUserAsync(userId, cancellationToken);

        var bound = new List<SystemUserClientSummary>();
        await foreach (var application in applications.ListAsync(cancellationToken: cancellationToken))
        {
            var properties = await applications.GetPropertiesAsync(application, cancellationToken);
            if (string.Equals(SystemUserClientBinding.Read(properties), userId, StringComparison.Ordinal))
            {
                bound.Add(await SummarizeClientAsync(application, cancellationToken));
            }
        }

        return [.. bound.OrderBy(x => x.ClientId, StringComparer.Ordinal)];
    }

    public async Task<SystemUserClientSummary> BindClientAsync(
        string userId,
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var (decision, application) = await DemandBindingAsync(userId, clientId, context, cancellationToken);
        if (!string.Equals(
                await applications.GetClientTypeAsync(application, cancellationToken),
                ClientTypes.Confidential,
                StringComparison.Ordinal)
            || !await applications.HasPermissionAsync(
                application, Permissions.GrantTypes.ClientCredentials, cancellationToken))
        {
            throw new ManagementValidationException(
                "system_user_client_not_allowed",
                "The client must be confidential and allow the client_credentials grant.",
                "clientId");
        }

        var properties = await applications.GetPropertiesAsync(application, cancellationToken);
        var current = SystemUserClientBinding.Read(properties);
        if (string.Equals(current, userId, StringComparison.Ordinal))
        {
            return await SummarizeClientAsync(application, cancellationToken);
        }

        if (current is not null)
        {
            throw new ManagementConflictException(
                "system_user_client_bound_elsewhere",
                "The client already acts as another system user; unbind it there first.");
        }

        await SetBindingAsync(application, userId, cancellationToken);
        await AuditBindingAsync(context, userId, clientId, decision, "system_user_client_bound", cancellationToken);
        return await SummarizeClientAsync(application, cancellationToken);
    }

    public async Task UnbindClientAsync(
        string userId,
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var (decision, application) = await DemandBindingAsync(userId, clientId, context, cancellationToken);
        var properties = await applications.GetPropertiesAsync(application, cancellationToken);
        if (!string.Equals(SystemUserClientBinding.Read(properties), userId, StringComparison.Ordinal))
        {
            throw new ManagementNotFoundException(
                "system_user_client_not_bound", "The client does not act as this system user.");
        }

        await SetBindingAsync(application, null, cancellationToken);
        await AuditBindingAsync(context, userId, clientId, decision, "system_user_client_unbound", cancellationToken);
    }

    private async Task<(ManagementAuthorizationDecision Decision, object Application)> DemandBindingAsync(
        string userId,
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken)
    {
        var decision = await DemandAsync(
            context, ManagementCapabilities.UsersReset, UserResource(userId), cancellationToken,
            auditDenial: true, mintsCredential: true);
        var trimmed = clientId?.Trim() ?? string.Empty;
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsUpdate,
            new ManagementResource(ManagementResourceTypes.Client, trimmed, trimmed),
            cancellationToken,
            auditDenial: true);
        _ = await FindSystemUserAsync(userId, cancellationToken);

        var application = string.IsNullOrEmpty(trimmed)
            ? null
            : await applications.FindByClientIdAsync(trimmed, cancellationToken);
        return application is null
            ? throw new ManagementNotFoundException("client_not_found", "The client was not found.")
            : (decision, application);
    }

    private async Task SetBindingAsync(object application, string? userId, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);
        if (userId is null)
        {
            descriptor.Properties.Remove(SystemUserClientBinding.PropertyName);
        }
        else
        {
            descriptor.Properties[SystemUserClientBinding.PropertyName] = JsonSerializer.SerializeToElement(userId);
        }

        await applications.UpdateAsync(application, descriptor, cancellationToken);
    }

    private async Task AuditBindingAsync(
        ManagementRequestContext context,
        string userId,
        string clientId,
        ManagementAuthorizationDecision decision,
        string reason,
        CancellationToken cancellationToken)
    {
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.UsersReset,
            UserResource(userId),
            decision,
            "succeeded",
            reason));
        await database.SaveChangesAsync(cancellationToken);
        logger.LogInformation(
            "Client {ClientId} {Action} system user {UserId} by {Subject}; correlation={CorrelationId}.",
            LogValue.Sanitize(clientId), reason == "system_user_client_bound" ? "bound to" : "unbound from",
            LogValue.Sanitize(userId), context.OperatorSubject, LogValue.Sanitize(context.CorrelationId));
    }

    private async Task<SystemUserClientSummary> SummarizeClientAsync(
        object application, CancellationToken cancellationToken) =>
        new(await applications.GetClientIdAsync(application, cancellationToken) ?? string.Empty,
            await applications.GetDisplayNameAsync(application, cancellationToken));
}
