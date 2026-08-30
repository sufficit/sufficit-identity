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

internal sealed partial class ClientManagementService(
    IOpenIddictApplicationManager applications,
    IOpenIddictApplicationCache<OpenIddictEntityFrameworkCoreApplication>
        applicationCache,
    AppDbContext database,
    IReservedScopePolicy reservedScopePolicy,
    IClientDefinitionValidator clientDefinitionValidator,
    IConfiguration configuration,
    ManagementOperationGuard guard,
    ClientCredentialRegistry credentials,
    ILogger<ClientManagementService> logger) : IClientManagementService
{

    private static (string? Search, string Type, string Grant, string Scope,
        string Origin, string Status, int Page, int PageSize)
        NormalizeSearchQuery(ManagementClientQuery query)
    {
        if (query.Page < 1 || query.PageSize is < 1 or > 100)
        {
            throw new ManagementValidationException(
                "client_query_paging_invalid",
                "page deve ser positivo e pageSize deve estar entre 1 e 100.",
                "pageSize");
        }

        static string Normalize(string? value) =>
            string.IsNullOrWhiteSpace(value) ? "all" : value.Trim().ToLowerInvariant();

        var type = Normalize(query.Type);
        if (type is not ("all" or "public" or "confidential"))
        {
            throw new ManagementValidationException(
                "client_query_type_invalid",
                "type deve ser all, public ou confidential.",
                "type");
        }

        var grant = Normalize(query.Grant);
        var scope = Normalize(query.Scope);
        var origin = Normalize(query.Origin);
        if (origin is not ("all" or "manual" or "manifest" or "dcr"))
        {
            throw new ManagementValidationException(
                "client_query_origin_invalid",
                "origin deve ser all, manual, manifest ou dcr.",
                "origin");
        }

        var status = Normalize(query.Status);
        if (status is not ("all" or "active"))
        {
            throw new ManagementValidationException(
                "client_query_status_invalid",
                "status deve ser all ou active até que o ciclo de ativação seja habilitado.",
                "status");
        }

        return (string.IsNullOrWhiteSpace(query.Search) ? null : query.Search.Trim(),
            type, grant, scope, origin, status, query.Page, query.PageSize);
    }

    /// <summary>
    /// Reads the DCR provenance stamps from the raw Properties JSON column.
    /// Returns empty values for clients that were not self-registered.
    /// </summary>
    private static (DateTimeOffset? RegisteredAtUtc, bool Anonymous,
        string? RemoteAddress, string? UserAgent)
        ReadRegistrationProvenance(string? properties)
    {
        if (string.IsNullOrWhiteSpace(properties)) return (null, false, null, null);
        try
        {
            using var document = JsonDocument.Parse(properties);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return (null, false, null, null);

            var root = document.RootElement;
            return (
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.RegisteredAt,
                    out var registeredAt)
                && registeredAt.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(
                    registeredAt.GetString(),
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AdjustToUniversal
                        | System.Globalization.DateTimeStyles.AssumeUniversal,
                    out var parsed)
                    ? parsed
                    : null,
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.Anonymous,
                    out var anonymous)
                    && anonymous.ValueKind == JsonValueKind.True,
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.RemoteAddress,
                    out var address)
                && address.ValueKind == JsonValueKind.String
                    ? address.GetString()
                    : null,
                root.TryGetProperty(
                    DynamicClientRegistrationProperties.UserAgent,
                    out var userAgent)
                && userAgent.ValueKind == JsonValueKind.String
                    ? userAgent.GetString()
                    : null);
        }
        catch (JsonException)
        {
            // A malformed Properties blob must not break the console listing.
            return (null, false, null, null);
        }
    }

}
