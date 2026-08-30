using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Scim;

internal sealed partial class ScimProvisioningService
{
    private static (string Attribute, string Value) ParseEqualityFilter(
        string filter)
    {
        var match = EqualityFilterRegex().Match(filter.Trim());
        if (!match.Success)
        {
            throw ScimException.BadRequest(
                "Only the SCIM 'eq' operator is supported for id, userName, externalId and displayName.",
                "invalidFilter");
        }

        var encoded = $"\"{match.Groups["value"].Value}\"";
        return (
            match.Groups["attribute"].Value,
            JsonSerializer.Deserialize<string>(encoded)
                ?? string.Empty);
    }

    private static string NormalizePatchOperation(
        ScimPatchOperation operation)
    {
        var op = operation.Op?.Trim().ToLowerInvariant();
        if (op is not ("add" or "replace" or "remove"))
        {
            throw ScimException.BadRequest(
                $"SCIM patch operation '{operation.Op}' is not supported.",
                "invalidSyntax");
        }
        return op;
    }

    private static void ValidatePatchRequest(ScimPatchRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.Schemas.Contains(
            ScimSchemas.PatchOperation,
            StringComparer.Ordinal))
        {
            throw ScimException.BadRequest(
                $"The schemas collection must contain '{ScimSchemas.PatchOperation}'.",
                "invalidSyntax");
        }
        if (request.Operations.Count is 0)
        {
            throw ScimException.BadRequest(
                "At least one SCIM patch operation is required.",
                "invalidSyntax");
        }
    }

    private static void EnsureIdentityResult(IdentityResult result)
    {
        if (result.Succeeded)
        {
            return;
        }

        var duplicate = result.Errors.Any(error =>
            error.Code is "DuplicateUserName" or "DuplicateEmail");
        if (duplicate)
        {
            throw ScimException.Conflict(
                "A SCIM user with the same userName or email already exists.");
        }
        throw ScimException.BadRequest(
            string.Join(
                ' ',
                result.Errors.Select(error => error.Description)),
            "invalidValue");
    }

    private (int StartIndex, int Skip, int Count) Paging(
        int startIndex,
        int count)
    {
        var normalizedStart = Math.Max(startIndex, 1);
        var max = Math.Clamp(options.Value.MaxResults, 1, 1000);
        var normalizedCount = Math.Clamp(count, 0, max);
        return (
            normalizedStart,
            normalizedStart - 1,
            normalizedCount);
    }

    /// <summary>
    /// Queues a READ audit row instead of writing it inline. Reads are
    /// observability, so the record does not have to be atomic with the
    /// response — and making it atomic turned every SCIM GET into a database
    /// write. Mutations keep <see cref="AddAudit"/>, where committing the
    /// record together with the change is the whole point.
    /// </summary>
    private void EnqueueReadAudit(
        ScimRequestContext context,
        string capability,
        string resourceType,
        string? resourceId,
        string operationOutcome,
        string reasonCode)
    {
        if (auditQueue is null)
        {
            AddAudit(
                context,
                capability,
                resourceType,
                resourceId,
                operationOutcome,
                reasonCode);
            return;
        }

        auditQueue.Enqueue(BuildAudit(
            context,
            capability,
            resourceType,
            resourceId,
            operationOutcome,
            reasonCode));
    }

    private void AddAudit(
        ScimRequestContext context,
        string capability,
        string resourceType,
        string? resourceId,
        string operationOutcome,
        string reasonCode) =>
        database.ManagementAuditEvents.Add(BuildAudit(
            context,
            capability,
            resourceType,
            resourceId,
            operationOutcome,
            reasonCode));

    private static ManagementAuditEvent BuildAudit(
        ScimRequestContext context,
        string capability,
        string resourceType,
        string? resourceId,
        string operationOutcome,
        string reasonCode)
    {
        return new ManagementAuditEvent
        {
            OccurredAtUtc = DateTime.UtcNow,
            OperatorSubject = Truncate(context.Actor, 255),
            Capability = Truncate(capability, 150),
            ResourceType = Truncate(resourceType, 100),
            ResourceId = TruncateOptional(resourceId, 255),
            AuthorizationOutcome = "allowed",
            OperationOutcome = Truncate(operationOutcome, 50),
            ReasonCode = TruncateOptional(reasonCode, 100),
            CorrelationId = Truncate(context.CorrelationId, 100),
            AuthenticationMethods = TruncateOptional(
                context.AuthenticationMethods,
                255)
        };
    }

    private async Task RollbackAsync(
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction)
    {
        await transaction.RollbackAsync(CancellationToken.None);
        database.ChangeTracker.Clear();
    }

    private static string JsonString(JsonElement value, string path)
    {
        var result = JsonNullableString(value, path);
        if (string.IsNullOrWhiteSpace(result))
        {
            throw ScimException.BadRequest(
                $"SCIM attribute '{path}' requires a string value.",
                "invalidValue");
        }
        return result;
    }

    private static string? JsonNullableString(
        JsonElement value,
        string path)
    {
        if (value.ValueKind is JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind is not JsonValueKind.String)
        {
            throw ScimException.BadRequest(
                $"SCIM attribute '{path}' requires a string value.",
                "invalidValue");
        }
        return NormalizeOptional(value.GetString());
    }
}
