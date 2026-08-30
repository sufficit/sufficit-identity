using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Provisioning;
using System.Globalization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Clients;

internal sealed partial class ClientManagementService
{
    public async Task<IReadOnlyList<ManagementClientSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken,
            auditDenial: true);

        var result = new List<ManagementClientSummary>();

        await foreach (var application in applications.ListAsync(
            cancellationToken: cancellationToken))
        {
            result.Add(new ManagementClientSummary(
                Id: (string)(await applications.GetIdAsync(
                    application,
                    cancellationToken))!,
                ClientId: (string)(await applications.GetClientIdAsync(
                    application,
                    cancellationToken))!,
                DisplayName: (string?)await applications.GetDisplayNameAsync(
                    application,
                    cancellationToken),
                Type: (string?)await applications.GetClientTypeAsync(
                    application,
                    cancellationToken)));
        }

        return result
            .OrderBy(client => client.DisplayName ?? client.ClientId,
                StringComparer.OrdinalIgnoreCase)
            .ThenBy(client => client.ClientId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public async Task<ManagementClientPage> SearchAsync(
        ManagementClientQuery query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection),
            cancellationToken,
            auditDenial: true);

        var normalized = NormalizeSearchQuery(query);
        var applicationsQuery = database.Set<OpenIddictEntityFrameworkCoreApplication>()
            .AsNoTracking();

        var search = normalized.Search;
        if (!string.IsNullOrWhiteSpace(search))
        {
            applicationsQuery = applicationsQuery.Where(application =>
                (application.ClientId != null &&
                 application.ClientId!.Contains(search)) ||
                (application.DisplayName != null &&
                 application.DisplayName.Contains(search)));
        }

        if (normalized.Type is not "all")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.ClientType == normalized.Type);
        }

        if (normalized.Grant is not "all")
        {
            var permission = $"\"gt:{normalized.Grant}\"";
            applicationsQuery = applicationsQuery.Where(application =>
                application.Permissions != null &&
                application.Permissions.Contains(permission));
        }

        if (normalized.Scope is not "all")
        {
            var permission = $"\"scp:{normalized.Scope}\"";
            applicationsQuery = applicationsQuery.Where(application =>
                application.Permissions != null &&
                application.Permissions.Contains(permission));
        }

        if (normalized.Origin is "manifest")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.Properties != null &&
                application.Properties.Contains(
                    OpenIddictManifestProvisioner.SchemaVersionProperty));
        }
        else if (normalized.Origin is "dcr")
        {
            applicationsQuery = applicationsQuery.Where(application =>
                application.Properties != null &&
                application.Properties.Contains(
                    DynamicClientRegistrationProperties.Origin));
        }
        else if (normalized.Origin is "manual")
        {
            // "Manual" means neither provisioned by a manifest nor
            // self-registered: what an operator created by hand.
            applicationsQuery = applicationsQuery.Where(application =>
                (application.Properties == null
                    || !application.Properties.Contains(
                        OpenIddictManifestProvisioner.SchemaVersionProperty))
                && (application.Properties == null
                    || !application.Properties.Contains(
                        DynamicClientRegistrationProperties.Origin)));
        }

        var totalCount = await applicationsQuery.CountAsync(cancellationToken);
        var rows = await applicationsQuery
            .OrderBy(application => application.DisplayName ?? application.ClientId)
            .ThenBy(application => application.ClientId)
            .Skip((normalized.Page - 1) * normalized.PageSize)
            .Take(normalized.PageSize)
            .ToArrayAsync(cancellationToken);

        var items = rows
            .Select(application =>
            {
                var registration = ReadRegistrationProvenance(
                    application.Properties);
                return new ManagementClientSummary(
                    application.Id ?? string.Empty,
                    application.ClientId ?? string.Empty,
                    application.DisplayName,
                    application.ClientType,
                    null,
                    ResolveOrigin(application.Properties),
                    registration.RegisteredAtUtc,
                    registration.Anonymous,
                    registration.RemoteAddress,
                    registration.UserAgent);
            })
            .ToArray();

        return new ManagementClientPage(
            items,
            totalCount,
            normalized.Page,
            normalized.PageSize);
    }

    public async Task<ManagementClientDetail> GetByIdAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, id),
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByIdAsync(id, cancellationToken);
        if (application is null)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                "The OAuth client was not found.");
        }

        return await ToDetailAsync(application, cancellationToken);
    }

    public async Task<ManagementClientDetail> GetByClientIdAsync(
        string clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        await guard.DemandAsync(
            context,
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.Client, clientId),
            cancellationToken,
            auditDenial: true);

        var application = await applications.FindByClientIdAsync(
            clientId,
            cancellationToken);
        if (application is null)
        {
            throw new ManagementNotFoundException(
                "client_not_found",
                $"Client '{clientId}' was not found.");
        }

        return await ToDetailAsync(application, cancellationToken);
    }
}
