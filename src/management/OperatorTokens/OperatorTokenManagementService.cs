using Sufficit.Identity.Management.Authorization;
#if !APPLICATION_CONTRACTS
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
#endif

namespace Sufficit.Identity.Management.OperatorTokens;

#if APPLICATION_CONTRACTS

/// <summary>
/// Metadata for a short-lived Management bearer. The reference-token value is
/// deliberately absent and is returned only once by the issuance result.
/// </summary>
public sealed record OperatorTokenSummary(
    string Id,
    string Purpose,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string Status,
    IReadOnlyList<string> Capabilities);

public sealed record OperatorTokenWorkspace(
    bool IssuanceEnabled,
    bool MfaRequired,
    bool MfaSatisfied,
    int DefaultLifetimeSeconds,
    int MaximumLifetimeSeconds,
    int MaximumCapabilities,
    IReadOnlyList<string> AvailableCapabilities,
    IReadOnlyList<OperatorTokenSummary> ActiveTokens);

public sealed record IssueOperatorTokenCommand(
    string Purpose,
    int? LifetimeSeconds,
    IReadOnlyList<string> Capabilities);

public sealed record OperatorTokenIssueResult(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Capabilities,
    OperatorTokenSummary Token);

public interface IOperatorTokenManagementService
{
    Task<OperatorTokenWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<OperatorTokenIssueResult> IssueAsync(
        IssueOperatorTokenCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

#else

internal sealed class OperatorTokenManagementService(
    AppDbContext database,
    IOpenIddictScopeManager scopeManager,
    IOpenIddictTokenManager tokenManager,
    IOpenIddictServerDispatcher dispatcher,
    IOpenIddictServerFactory factory,
    IManagementAuthorizationEvaluator authorization,
    IManagementEntitlementResolver entitlements,
    IOptions<ManagementOptions> options,
    IConfiguration configuration,
    TimeProvider timeProvider,
    ILogger<OperatorTokenManagementService> logger)
    : IOperatorTokenManagementService
{
    internal const string TemporaryTokenMarker =
        "identity:temporary-operator-token";
    internal const string TemporaryClientId =
        "SufficitIdentityOperatorTemporary";

    private const string PermissionClaimType = "permission";
    private const string KindProperty =
        "urn:sufficit:identity:temporary-token:kind";
    private const string PurposeProperty =
        "urn:sufficit:identity:temporary-token:purpose";
    private const string CapabilitiesProperty =
        "urn:sufficit:identity:temporary-token:capabilities";
    private const string OperatorKind = "operator";

    private static readonly ManagementResource CollectionResource =
        new(ManagementResourceTypes.OperatorTokenCollection);

    private static readonly HashSet<string> NonDelegableCapabilities =
        new(StringComparer.Ordinal)
        {
            ManagementCapabilities.ManagementTokensIssue,
            ManagementCapabilities.ManagementTokensRevoke,
        };

    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

    public async Task<OperatorTokenWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        await DemandAsync(
            context,
            ManagementCapabilities.ManagementTokensRead,
            CollectionResource,
            cancellationToken);

        var policy = options.Value.TemporaryOperatorToken;
        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var available = grants.Capabilities
            .Where(ManagementCapabilities.All.Contains)
            .Where(capability => !NonDelegableCapabilities.Contains(capability))
            .Order(StringComparer.Ordinal)
            .ToArray();
        var active = await ListActiveAsync(
            context.OperatorSubject,
            cancellationToken);

        logger.LogDebug(
            "Temporary operator-token workspace read for subject {Subject}: active={ActiveCount}; availableCapabilities={CapabilityCount}; correlation={CorrelationId}.",
            context.OperatorSubject,
            active.Count,
            available.Length,
            context.CorrelationId);

        return new OperatorTokenWorkspace(
            policy.Enabled,
            options.Value.RequireMfa,
            HasMfaEvidence(context.Operator),
            ResolveDefaultLifetime(policy),
            ResolveMaximumLifetime(policy),
            ResolveMaximumCapabilities(policy),
            available,
            active);
    }

    public async Task<OperatorTokenIssueResult> IssueAsync(
        IssueOperatorTokenCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(context);

        var issueDecision = await DemandAsync(
            context,
            ManagementCapabilities.ManagementTokensIssue,
            CollectionResource,
            cancellationToken,
            auditDenial: true);

        if (context.Operator.FindFirst(TemporaryTokenMarker)?.Value is "true"
            || context.Operator.FindFirst(
                "identity:temporary-provisioning-token")?.Value is "true")
        {
            var nested = ManagementAuthorizationDecision.Denied(
                "temporary_token_cannot_mint");
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ManagementTokensIssue,
                CollectionResource,
                nested,
                "denied",
                nested.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(nested);
        }

        TemporaryOperatorTokenOptions policy;
        string purpose;
        int lifetimeSeconds;
        IReadOnlyList<string> capabilities;
        try
        {
            policy = options.Value.TemporaryOperatorToken;
            if (!policy.Enabled)
            {
                throw new ManagementConflictException(
                    "temporary_operator_token_disabled",
                    "A emissão de tokens temporários de Management está desabilitada neste ambiente.");
            }

            purpose = NormalizePurpose(command.Purpose);
            lifetimeSeconds = ResolveLifetime(
                command.LifetimeSeconds,
                policy);
            capabilities = await ResolveCapabilitiesAsync(
                command.Capabilities,
                context,
                policy,
                cancellationToken);
        }
        catch (ManagementValidationException exception)
        {
            await RecordRejectedIssueAsync(
                context,
                issueDecision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementConflictException exception)
        {
            await RecordRejectedIssueAsync(
                context,
                issueDecision,
                "rejected",
                exception.ReasonCode,
                cancellationToken);
            throw;
        }
        catch (ManagementAccessException exception)
        {
            await RecordRejectedIssueAsync(
                context,
                exception.Decision,
                "denied",
                exception.Decision.ReasonCode,
                cancellationToken);
            throw;
        }

        var now = timeProvider.GetUtcNow();
        var expiration = now.AddSeconds(lifetimeSeconds);
        var scopes = new[] { options.Value.RequiredScope };

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var identity = BuildIdentity(
                context,
                now,
                expiration,
                scopes,
                capabilities);
            var resources = await ToListAsync(
                scopeManager.ListResourcesAsync(
                    identity.GetScopes(),
                    cancellationToken),
                cancellationToken);
            identity.SetResources(resources);
            identity.SetClaims(OidcClaims.Audience, [.. resources]);
            identity.SetDestinations(_ => [Destinations.AccessToken]);

            var principal = new ClaimsPrincipal(identity);
            var tokenContext = await GenerateAsync(principal);
            var tokenId = tokenContext.Principal.GetTokenId()
                ?? throw new InvalidOperationException(
                    "OpenIddict não retornou o identificador do token temporário.");
            var token = await tokenManager.FindByIdAsync(
                    tokenId,
                    cancellationToken)
                ?? throw new InvalidOperationException(
                    "O registro do token temporário não foi encontrado.");

            var descriptor = new OpenIddictTokenDescriptor();
            await tokenManager.PopulateAsync(
                descriptor,
                token,
                cancellationToken);
            descriptor.Properties[KindProperty] =
                JsonSerializer.SerializeToElement(OperatorKind);
            descriptor.Properties[PurposeProperty] =
                JsonSerializer.SerializeToElement(purpose);
            descriptor.Properties[CapabilitiesProperty] =
                JsonSerializer.SerializeToElement(capabilities);
            await tokenManager.UpdateAsync(
                token,
                descriptor,
                cancellationToken);
            await PersistPropertiesAsync(
                tokenId,
                descriptor.Properties,
                cancellationToken);

            var resource = new ManagementResource(
                ManagementResourceTypes.OperatorToken,
                tokenId);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ManagementTokensIssue,
                    resource,
                    issueDecision,
                    "succeeded",
                    "temporary_operator_token_issued"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            logger.LogInformation(
                "Temporary operator token issued for subject {Subject}: tokenId={TokenId}; expiresAt={ExpiresAtUtc}; capabilities={Capabilities}; correlation={CorrelationId}.",
                context.OperatorSubject,
                tokenId,
                expiration,
                string.Join(',', capabilities),
                context.CorrelationId);

            var summary = new OperatorTokenSummary(
                tokenId,
                purpose,
                now,
                expiration,
                Statuses.Valid,
                capabilities);
            return new OperatorTokenIssueResult(
                tokenContext.Token!,
                "Bearer",
                expiration,
                scopes,
                capabilities,
                summary);
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Temporary operator-token issuance failed for subject {Subject}; correlation={CorrelationId}.",
                context.OperatorSubject,
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ManagementTokensIssue,
                CollectionResource,
                issueDecision,
                "failed",
                "temporary_operator_token_failed",
                cancellationToken);
            throw;
        }
    }

    public async Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var normalizedId = id?.Trim();
        if (string.IsNullOrWhiteSpace(normalizedId))
        {
            throw new ManagementValidationException(
                "operator_token_id_required",
                "O identificador do token é obrigatório.",
                "id");
        }

        var resource = new ManagementResource(
            ManagementResourceTypes.OperatorToken,
            normalizedId);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ManagementTokensRevoke,
            resource,
            cancellationToken,
            auditDenial: true);
        var token = await FindOwnedAsync(
            normalizedId,
            context.OperatorSubject,
            cancellationToken);
        if (token is null)
        {
            throw new ManagementNotFoundException(
                "operator_token_not_found",
                "O token temporário não existe ou não pertence ao operador atual.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            if (!await tokenManager.TryRevokeAsync(token, cancellationToken))
            {
                throw new ManagementConflictException(
                    "operator_token_revoke_failed",
                    "O token temporário não pôde ser revogado.");
            }

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ManagementTokensRevoke,
                    resource,
                    decision,
                    "succeeded",
                    "temporary_operator_token_revoked"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            logger.LogInformation(
                "Temporary operator token revoked for subject {Subject}: tokenId={TokenId}; correlation={CorrelationId}.",
                context.OperatorSubject,
                normalizedId,
                context.CorrelationId);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
    }

    private async Task<IReadOnlyList<OperatorTokenSummary>> ListActiveAsync(
        string subject,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var result = new List<OperatorTokenSummary>();
        await foreach (var token in tokenManager.FindBySubjectAsync(
            subject,
            cancellationToken))
        {
            if (!await tokenManager.HasTypeAsync(
                    token,
                    TokenTypeIdentifiers.AccessToken,
                    cancellationToken))
            {
                continue;
            }

            var properties = await tokenManager.GetPropertiesAsync(
                token,
                cancellationToken);
            if (!string.Equals(
                    GetStringProperty(properties, KindProperty),
                    OperatorKind,
                    StringComparison.Ordinal))
            {
                continue;
            }

            var expiration = await tokenManager.GetExpirationDateAsync(
                token,
                cancellationToken);
            var status = await tokenManager.GetStatusAsync(
                token,
                cancellationToken) ?? "unknown";
            if (expiration is null
                || expiration <= now
                || !string.Equals(status, Statuses.Valid, StringComparison.Ordinal))
            {
                continue;
            }

            result.Add(new OperatorTokenSummary(
                await tokenManager.GetIdAsync(token, cancellationToken)
                    ?? throw new InvalidOperationException(
                        "O token temporário não possui identificador."),
                GetStringProperty(properties, PurposeProperty)
                    ?? "Operação temporária",
                await tokenManager.GetCreationDateAsync(
                    token,
                    cancellationToken) ?? DateTimeOffset.MinValue,
                expiration.Value,
                status,
                GetStringArrayProperty(properties, CapabilitiesProperty)));
        }

        return result
            .OrderByDescending(token => token.CreatedAtUtc)
            .Take(100)
            .ToArray();
    }

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

    private ClaimsIdentity BuildIdentity(
        ManagementRequestContext context,
        DateTimeOffset now,
        DateTimeOffset expiration,
        IReadOnlyList<string> scopes,
        IReadOnlyList<string> capabilities)
    {
        var identity = new ClaimsIdentity(
            authenticationType: "TemporaryOperatorToken",
            nameType: OidcClaims.Name,
            roleType: OidcClaims.Role);
        identity.SetClaim(OidcClaims.Subject, context.OperatorSubject);
        identity.SetClaim(OidcClaims.ClientId, TemporaryClientId);
        identity.SetClaim(
            OidcClaims.Name,
            context.OperatorDisplayName ?? context.OperatorSubject);
        identity.SetClaim(OidcClaims.Scope, string.Join(' ', scopes));
        identity.SetScopes(scopes);
        identity.SetCreationDate(now);
        identity.SetExpirationDate(expiration);
        identity.SetClaim(OidcClaims.Private.Issuer, ResolveIssuer());
        identity.SetClaim(TemporaryTokenMarker, "true");
        identity.SetClaim(
            PermissionClaimType,
            string.Join(' ', capabilities));

        foreach (var claimType in new[]
        {
            "amr", "auth_time", "acr", "aal", ManagementTenantClaims.Type
        })
        {
            foreach (var claim in context.Operator.FindAll(claimType))
            {
                identity.AddClaim(new Claim(claimType, claim.Value));
            }
        }

        return identity;
    }

    private async Task<GenerateTokenContext> GenerateAsync(
        ClaimsPrincipal principal)
    {
        var transaction = await factory.CreateTransactionAsync();
        var tokenContext = new GenerateTokenContext(transaction)
        {
            CreateTokenEntry = true,
            IsReferenceToken = true,
            PersistTokenPayload = true,
            Principal = principal,
            TokenFormat = TokenFormats.Private.JsonWebToken,
            TokenType = TokenTypeIdentifiers.AccessToken,
        };
        await dispatcher.DispatchAsync(tokenContext);
        if (tokenContext.IsRejected
            || string.IsNullOrWhiteSpace(tokenContext.Token))
        {
            throw new InvalidOperationException(
                tokenContext.ErrorDescription
                ?? "OpenIddict não conseguiu emitir o token temporário.");
        }

        return tokenContext;
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

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken,
        bool auditDenial = false)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            resource,
            cancellationToken);
        if (decision.IsAllowed)
        {
            return decision;
        }

        if (auditDenial)
        {
            await TryWriteAuditAsync(
                context,
                capability,
                resource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
        }
        throw new ManagementAccessException(decision);
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

#endif
