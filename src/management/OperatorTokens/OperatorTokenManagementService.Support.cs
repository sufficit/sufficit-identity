using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using OidcClaims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.OperatorTokens;

internal sealed partial class OperatorTokenManagementService
{
    private async Task<object?> FindOwnedAsync(
        string id,
        string subject,
        CancellationToken cancellationToken)
    {
        var token = await tokenManager.FindByIdAsync(id, cancellationToken);
        if (token is null
            || !string.Equals(
                await tokenManager.GetSubjectAsync(token, cancellationToken),
                subject,
                StringComparison.Ordinal)
            || !await tokenManager.HasTypeAsync(
                token,
                TokenTypeIdentifiers.AccessToken,
                cancellationToken))
        {
            return null;
        }

        var properties = await tokenManager.GetPropertiesAsync(
            token,
            cancellationToken);
        return string.Equals(
            GetStringProperty(properties, KindProperty),
            OperatorKind,
            StringComparison.Ordinal)
                ? token
                : null;
    }

    private async Task<IReadOnlyList<string>> ResolveCapabilitiesAsync(
        IReadOnlyList<string> requested,
        ManagementRequestContext context,
        TemporaryOperatorTokenOptions policy,
        CancellationToken cancellationToken)
    {
        var normalized = (requested ?? [])
            .Where(capability => !string.IsNullOrWhiteSpace(capability))
            .Select(capability => ManagementCapabilities.Normalize(
                capability.Trim()))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (normalized.Length is 0)
        {
            throw new ManagementValidationException(
                "operator_token_capability_required",
                "Selecione pelo menos uma capability para o token temporário.",
                "capabilities");
        }
        if (normalized.Length > ResolveMaximumCapabilities(policy))
        {
            throw new ManagementValidationException(
                "operator_token_capability_limit",
                $"O token temporário aceita no máximo {ResolveMaximumCapabilities(policy)} capabilities.",
                "capabilities");
        }

        var unknown = normalized
            .Where(capability => !ManagementCapabilities.All.Contains(capability))
            .ToArray();
        if (unknown.Length > 0)
        {
            throw new ManagementValidationException(
                "operator_token_capability_unknown",
                $"Capability desconhecida: {string.Join(", ", unknown)}.",
                "capabilities");
        }

        var nonDelegable = normalized
            .Where(NonDelegableCapabilities.Contains)
            .ToArray();
        if (nonDelegable.Length > 0)
        {
            throw new ManagementValidationException(
                "operator_token_capability_not_delegable",
                "Tokens temporários não podem emitir ou revogar outros tokens temporários.",
                "capabilities");
        }

        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var unavailable = normalized
            .Where(capability => !grants.Contains(capability))
            .ToArray();
        if (unavailable.Length > 0)
        {
            throw new ManagementAccessException(
                ManagementAuthorizationDecision.Denied(
                    "capability_not_granted"));
        }

        return normalized;
    }

    private async Task PersistPropertiesAsync(
        string id,
        IReadOnlyDictionary<string, JsonElement> properties,
        CancellationToken cancellationToken)
    {
        var entity = await database
            .Set<OpenIddictEntityFrameworkCoreToken>()
            .SingleAsync(token => token.Id == id, cancellationToken);
        var serialized = properties.Count is 0
            ? null
            : JsonSerializer.Serialize(properties);
        if (!string.Equals(
            entity.Properties,
            serialized,
            StringComparison.Ordinal))
        {
            entity.Properties = serialized;
            await database.SaveChangesAsync(cancellationToken);
        }
    }

    private async Task TryWriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string outcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    capability,
                    resource,
                    decision,
                    outcome,
                    reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist temporary operator-token audit event. CorrelationId={CorrelationId}.",
                context.CorrelationId);
        }
    }

    private async Task RecordRejectedIssueAsync(
        ManagementRequestContext context,
        ManagementAuthorizationDecision decision,
        string outcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        await TryWriteAuditAsync(
            context,
            ManagementCapabilities.ManagementTokensIssue,
            CollectionResource,
            decision,
            outcome,
            reasonCode,
            cancellationToken);
        logger.LogWarning(
            "Temporary operator-token issuance rejected for subject {Subject}: outcome={Outcome}; reason={ReasonCode}; correlation={CorrelationId}.",
            context.OperatorSubject,
            outcome,
            reasonCode,
            context.CorrelationId);
    }

    /// <summary>Authentication evidence projected from the operator principal.</summary>
    private static IEnumerable<Claim> EvidenceClaims(ManagementRequestContext context)
    {
        foreach (var claimType in new[] { "amr", "auth_time", "acr", "aal" })
        {
            foreach (var claim in context.Operator.FindAll(claimType))
            {
                yield return new Claim(claimType, claim.Value);
            }
        }
    }

    private string ResolveIssuer()
    {
        var issuer = configuration["Sufficit:Identity:Issuer"];
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ManagementConflictException(
                "temporary_operator_token_issuer_missing",
                "O token temporário não pode ser emitido porque o issuer público do Identity não está configurado.");
        }
        return issuer.TrimEnd('/') + "/";
    }

    private static string NormalizePurpose(string value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new ManagementValidationException(
                "operator_token_purpose_required",
                "Informe a finalidade do token temporário.",
                "purpose");
        }
        if (normalized.Length > 120)
        {
            throw new ManagementValidationException(
                "operator_token_purpose_too_long",
                "A finalidade deve ter no máximo 120 caracteres.",
                "purpose");
        }
        return normalized;
    }

    private static bool HasMfaEvidence(ClaimsPrincipal principal) =>
        principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .Any(MfaMethods.Contains);

    private static int ResolveLifetime(
        int? requested,
        TemporaryOperatorTokenOptions policy)
    {
        var maximum = ResolveMaximumLifetime(policy);
        var lifetime = requested ?? ResolveDefaultLifetime(policy);
        if (lifetime < 60 || lifetime > maximum)
        {
            throw new ManagementValidationException(
                "operator_token_lifetime_invalid",
                $"A validade deve ficar entre 60 e {maximum} segundos.",
                "lifetimeSeconds");
        }
        return lifetime;
    }

    private static int ResolveMaximumLifetime(
        TemporaryOperatorTokenOptions policy) =>
        Math.Clamp(policy.MaximumLifetimeSeconds, 60, 3600);

    private static int ResolveDefaultLifetime(
        TemporaryOperatorTokenOptions policy) =>
        Math.Clamp(
            policy.DefaultLifetimeSeconds,
            60,
            ResolveMaximumLifetime(policy));

    private static int ResolveMaximumCapabilities(
        TemporaryOperatorTokenOptions policy) =>
        Math.Clamp(policy.MaximumCapabilities, 1, 64);

    private static string? GetStringProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key) =>
        properties.TryGetValue(key, out var value)
        && value.ValueKind is JsonValueKind.String
            ? value.GetString()
            : null;

    private static IReadOnlyList<string> GetStringArrayProperty(
        IReadOnlyDictionary<string, JsonElement> properties,
        string key)
    {
        if (!properties.TryGetValue(key, out var value)
            || value.ValueKind is not JsonValueKind.Array)
        {
            return [];
        }
        return value.EnumerateArray()
            .Where(item => item.ValueKind is JsonValueKind.String)
            .Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Cast<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private static async Task<List<string>> ToListAsync(
        IAsyncEnumerable<string> values,
        CancellationToken cancellationToken)
    {
        var result = new List<string>();
        await foreach (var value in values.WithCancellation(cancellationToken))
        {
            result.Add(value);
        }
        return result;
    }
}
