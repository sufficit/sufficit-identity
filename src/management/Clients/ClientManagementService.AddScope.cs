using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Clients;

public interface IClientScopeManagementService
{
    Task AddScopeAsync(string clientId, string scopeName, string expectedVersion,
        ManagementRequestContext context, CancellationToken cancellationToken);
}

internal sealed partial class ClientManagementService
{
    public async Task AddScopeAsync(string clientId, string scopeName, string expectedVersion,
        ManagementRequestContext context, CancellationToken cancellationToken)
    {
        const string capability = ManagementCapabilities.ClientsUpdate;
        var resource = new ManagementResource(ManagementResourceTypes.Client, clientId);
        var decision = await guard.DemandAsync(context, capability, resource, cancellationToken, auditDenial: true);
        var application = await applications.FindByClientIdAsync(clientId, cancellationToken)
            as OpenIddictEntityFrameworkCoreApplication
            ?? throw new ManagementNotFoundException("client_not_found", "The client was not found.");
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, cancellationToken);
        if (descriptor.Properties.ContainsKey(OpenIddictManifestProvisioner.SchemaVersionProperty))
        {
            throw new ManagementConflictException(
                "client_manifest_managed",
                "This client is managed by a declarative manifest. Change the manifest and apply provisioning.");
        }

        var permission = OpenIddictConstants.Permissions.Prefixes.Scope + scopeName;
        if (descriptor.Permissions.Contains(permission))
            return;

        if (!string.Equals(expectedVersion, application.ConcurrencyToken, StringComparison.Ordinal))
            throw new ManagementConflictException("client_changed", "Reload the client before adding a scope.");

        if (reservedScopePolicy.IsReserved(scopeName))
            throw new ManagementValidationException("scope_reserved", "This administrative scope cannot be assigned through the management API.", "scopeName");
        if (await scopes.FindByNameAsync(scopeName, cancellationToken) is null)
            throw new ManagementNotFoundException("scope_not_found", "The scope was not found.");

        var grants = descriptor.Permissions
            .Where(value => value.StartsWith(OpenIddictConstants.Permissions.Prefixes.GrantType, StringComparison.Ordinal))
            .ToArray();
        await AuthorizeScopeGrantAsync(context, capability, clientId, grants,
            [permission], ScopePermissions(descriptor.Permissions), cancellationToken);

        descriptor.Permissions.Add(permission);
        try
        {
            await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
            await applications.UpdateAsync(application, descriptor, cancellationToken);

            var audit = ManagementAuditEventFactory.Create(context, capability, resource, decision,
                "succeeded", "client_scope_added");
            audit.AfterJson = JsonSerializer.Serialize(new { Scope = scopeName });
            database.ManagementAuditEvents.Add(audit);
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is DbUpdateConcurrencyException or OpenIddictExceptions.ConcurrencyException)
        {
            throw new ManagementConflictException("client_changed", "Reload the client before adding a scope.");
        }
    }
}
