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

internal sealed partial class OperatorTokenManagementService(
    AppDbContext database,
    IOpenIddictTokenManager tokenManager,
    Sufficit.Identity.Application.Security.IPrivilegedTokenMintingService minting,
    IManagementEntitlementResolver entitlements,
    IOptions<ManagementOptions> options,
    IConfiguration configuration,
    TimeProvider timeProvider,
    ILogger<OperatorTokenManagementService> logger,
    ManagementOperationGuard guard)
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
        await guard.DemandAsync(
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

        var issueDecision = await guard.DemandAsync(
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
            // A3 (eval 2026-08-14): minting mechanics (identity scaffolding,
            // resources-from-scopes, reference+persist dispatch) live in the
            // shared minting service; this issuer keeps its POLICY and its
            // missing-issuer error contract.
            var mint = await minting.MintAsync(
                new Sufficit.Identity.Application.Security.PrivilegedTokenMintRequest(
                    AuthenticationType: "TemporaryOperatorToken",
                    Subject: context.OperatorSubject,
                    ClientId: TemporaryClientId,
                    DisplayName: context.OperatorDisplayName ?? context.OperatorSubject,
                    CreatedAtUtc: now,
                    ExpiresAtUtc: expiration,
                    Scopes: scopes,
                    Resources: null,
                    StringClaims: new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [TemporaryTokenMarker] = "true",
                        [PermissionClaimType] = string.Join(' ', capabilities),
                    },
                    EvidenceClaims: EvidenceClaims(context),
                    Issuer: ResolveIssuer()),
                cancellationToken);
            var tokenId = mint.TokenId;
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
                mint.Token!,
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
        var decision = await guard.DemandAsync(
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

}
