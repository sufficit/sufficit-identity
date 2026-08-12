#if !APPLICATION_CONTRACTS
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using OidcClaims = OpenIddict.Abstractions.OpenIddictConstants.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Provisioning;

#if APPLICATION_CONTRACTS

/// <summary>
/// A short-lived access token for a command-line provisioning operation.
/// The access-token value is returned only at issuance time.
/// </summary>
public sealed record ProvisioningTokenIssueResult(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Capabilities);

public sealed record ProvisioningTokenIssueRequest(int? LifetimeSeconds = null);

public interface IProvisioningTokenManagementService
{
    Task<ProvisioningTokenIssueResult> IssueAsync(
        ManagementRequestContext context,
        ProvisioningTokenIssueRequest? request = null,
        CancellationToken cancellationToken = default);
}

#else

internal interface IProvisioningTokenIssuer
{
    Task<ProvisioningTokenIssueResult> IssueAsync(
        ManagementRequestContext context,
        int lifetimeSeconds,
        string managementScope,
        IReadOnlyList<string> capabilities,
        CancellationToken cancellationToken = default);
}

internal sealed class ProvisioningTokenManagementService(
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    IProvisioningTokenIssuer issuer,
    IOptions<ManagementOptions> options,
    ILogger<ProvisioningTokenManagementService> logger)
    : IProvisioningTokenManagementService
{
    private const string TemporaryTokenMarker =
        "identity:temporary-provisioning-token";

    private static readonly ManagementResource TokenResource =
        new(
            ManagementResourceTypes.Provisioning,
            "temporary-token");

    private static readonly string[] TokenCapabilities =
    [
        ManagementCapabilities.ProvisioningPreview,
        ManagementCapabilities.ProvisioningApply
    ];

    public async Task<ProvisioningTokenIssueResult> IssueAsync(
        ManagementRequestContext context,
        ProvisioningTokenIssueRequest? request = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.ProvisioningApply,
            TokenResource,
            cancellationToken);

        if (!decision.IsAllowed)
        {
            await TryWriteAuditAsync(
                context,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(decision);
        }

        if (context.Operator.FindFirst(TemporaryTokenMarker)?.Value
            is "true")
        {
            var nestedDecision = ManagementAuthorizationDecision.Denied(
                "temporary_token_cannot_mint");
            await TryWriteAuditAsync(
                context,
                nestedDecision,
                "denied",
                nestedDecision.ReasonCode,
                cancellationToken);
            throw new ManagementAccessException(nestedDecision);
        }

        var policy = options.Value.TemporaryProvisioningToken;
        if (!policy.Enabled)
        {
            throw new ManagementConflictException(
                "temporary_provisioning_token_disabled",
                "A emissão de tokens temporários de provisioning está desabilitada neste ambiente.");
        }

        var lifetimeSeconds = ResolveLifetime(
            request?.LifetimeSeconds,
            policy);

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var result = await issuer.IssueAsync(
                context,
                lifetimeSeconds,
                options.Value.RequiredScope,
                TokenCapabilities,
                cancellationToken);

            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ProvisioningApply,
                    TokenResource,
                    decision,
                    "succeeded",
                    "provisioning_temporary_token_issued"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return result;
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
                "Temporary provisioning-token issuance failed. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                decision,
                "failed",
                "provisioning_temporary_token_failed",
                cancellationToken);
            throw;
        }
    }

    private static int ResolveLifetime(
        int? requested,
        TemporaryProvisioningTokenOptions policy)
    {
        var maximum = Math.Clamp(policy.MaximumLifetimeSeconds, 60, 3600);
        var defaultLifetime = Math.Clamp(
            policy.DefaultLifetimeSeconds,
            60,
            maximum);
        var lifetime = requested ?? defaultLifetime;
        if (lifetime < 60 || lifetime > maximum)
        {
            throw new ManagementValidationException(
                "temporary_token_lifetime_invalid",
                $"A validade deve estar entre 60 e {maximum} segundos.",
                "lifetimeSeconds");
        }

        return lifetime;
    }

    private async Task TryWriteAuditAsync(
        ManagementRequestContext context,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ProvisioningApply,
                    TokenResource,
                    decision,
                    operationOutcome,
                    reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist temporary provisioning-token audit event. CorrelationId={CorrelationId}",
                context.CorrelationId);
        }
    }
}

/// <summary>
/// Issues the reference access token consumed by the existing OpenIddict
/// validation middleware. This service is intentionally kept in the
/// Management assembly so both the embedded UI and HTTP controller use the
/// same issuance boundary.
/// </summary>
internal sealed class ProvisioningTokenIssuer(
    IOpenIddictScopeManager scopeManager,
    IOpenIddictServerDispatcher dispatcher,
    IOpenIddictServerFactory factory,
    IConfiguration configuration)
    : IProvisioningTokenIssuer
{
    private const string TemporaryTokenMarker =
        "identity:temporary-provisioning-token";
    private const string PermissionClaimType = "permission";
    private const string TemporaryClientId =
        "SufficitIdentityProvisioningTemporary";

    public async Task<ProvisioningTokenIssueResult> IssueAsync(
        ManagementRequestContext context,
        int lifetimeSeconds,
        string managementScope,
        IReadOnlyList<string> capabilities,
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var expiration = now.AddSeconds(lifetimeSeconds);
        var scopes = new[] { managementScope };
        var issuer = ResolveIssuer();
        var identity = new ClaimsIdentity(
            authenticationType: "TemporaryProvisioningToken",
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
        identity.SetClaim(
            OidcClaims.Private.Issuer,
            issuer);
        identity.SetClaim(TemporaryTokenMarker, "true");
        identity.SetClaim(
            PermissionClaimType,
            string.Join(' ', capabilities));

        foreach (var claim in context.Operator.FindAll("amr"))
        {
            identity.AddClaim(new Claim("amr", claim.Value));
        }

        foreach (var claimType in new[] { "auth_time", "acr" })
        {
            foreach (var claim in context.Operator.FindAll(claimType))
            {
                identity.AddClaim(new Claim(claimType, claim.Value));
            }
        }

        var resources = await ToListAsync(
            scopeManager.ListResourcesAsync(
                identity.GetScopes(),
                cancellationToken),
            cancellationToken);
        identity.SetResources(resources);
        identity.SetClaims(OidcClaims.Audience, [.. resources]);
        identity.SetDestinations(_ => [Destinations.AccessToken]);

        var principal = new ClaimsPrincipal(identity);
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

        return new ProvisioningTokenIssueResult(
            tokenContext.Token,
            "Bearer",
            expiration,
            scopes,
            capabilities);
    }

    private string ResolveIssuer()
    {
        var issuer = configuration["Sufficit:Identity:Issuer"];
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:Issuer must be configured before issuing temporary tokens.");
        }

        return issuer.TrimEnd('/') + "/";
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
