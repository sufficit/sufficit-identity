using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Provisioning;

/// <summary>
/// Canonical application boundary for declarative OpenIddict provisioning.
/// HTTP and embedded UI adapters must both use this service.
/// </summary>
public interface IProvisioningManagementService
{
    Task<IdentityProvisioningPlan> PreviewAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<IdentityProvisioningPlan> ApplyAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

internal sealed class ProvisioningManagementService(
    OpenIddictManifestProvisioner provisioner,
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    ILogger<ProvisioningManagementService> logger)
    : IProvisioningManagementService
{
    private static readonly ManagementResource ManifestResource =
        new(
            ManagementResourceTypes.Provisioning,
            $"schema-v{IdentityProvisioningManifest.CurrentSchemaVersion}");

    public async Task<IdentityProvisioningPlan> PreviewAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(context);

        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ProvisioningPreview,
            cancellationToken);

        try
        {
            var plan = await provisioner.PreviewAsync(
                manifest,
                cancellationToken);
            await WriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningPreview,
                decision,
                "succeeded",
                plan.HasChanges
                    ? "provisioning_changes_previewed"
                    : "provisioning_manifest_current",
                cancellationToken);
            return plan;
        }
        catch (IdentityProvisioningManifestException)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningPreview,
                decision,
                "rejected",
                "provisioning_manifest_invalid",
                cancellationToken);
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Provisioning preview failed. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningPreview,
                decision,
                "failed",
                "provisioning_preview_failed",
                cancellationToken);
            throw;
        }
    }

    public async Task<IdentityProvisioningPlan> ApplyAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(context);

        var decision = await DemandAsync(
            context,
            ManagementCapabilities.ProvisioningApply,
            cancellationToken);

        try
        {
            IdentityProvisioningManifestValidator.ValidateAndThrow(manifest);
        }
        catch (IdentityProvisioningManifestException)
        {
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningApply,
                decision,
                "rejected",
                "provisioning_manifest_invalid",
                cancellationToken);
            throw;
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        try
        {
            var plan = await provisioner.ApplyAsync(
                manifest,
                cancellationToken);
            database.ManagementAuditEvents.Add(
                ManagementAuditEventFactory.Create(
                    context,
                    ManagementCapabilities.ProvisioningApply,
                    ManifestResource,
                    decision,
                    "succeeded",
                    plan.HasChanges
                        ? "provisioning_manifest_applied"
                        : "provisioning_manifest_current"));
            await database.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return plan;
        }
        catch (OperationCanceledException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            throw;
        }
        catch (Exception exception)
            when (exception is ClientSecretResolverUnavailableException
                or ClientSecretResolutionException)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogWarning(
                exception,
                "Provisioning secret resolution is unavailable. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningApply,
                decision,
                "conflict",
                "provisioning_secret_unavailable",
                cancellationToken);
            throw new ManagementConflictException(
                "provisioning_secret_unavailable",
                "O ambiente não conseguiu resolver a referência de segredo do cliente.");
        }
        catch (Exception exception)
        {
            await transaction.RollbackAsync(CancellationToken.None);
            database.ChangeTracker.Clear();
            logger.LogError(
                exception,
                "Provisioning apply failed and was rolled back. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningApply,
                decision,
                "failed",
                "provisioning_apply_failed",
                cancellationToken);
            throw;
        }
    }

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            ManifestResource,
            cancellationToken);
        if (decision.IsAllowed)
        {
            return decision;
        }

        await TryWriteAuditAsync(
            context,
            capability,
            decision,
            "denied",
            decision.ReasonCode,
            cancellationToken);
        throw new ManagementAccessException(decision);
    }

    private async Task WriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        database.ManagementAuditEvents.Add(
            ManagementAuditEventFactory.Create(
                context,
                capability,
                ManifestResource,
                decision,
                operationOutcome,
                reasonCode));
        await database.SaveChangesAsync(cancellationToken);
    }

    private async Task TryWriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            await WriteAuditAsync(
                context,
                capability,
                decision,
                operationOutcome,
                reasonCode,
                cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist provisioning audit event. Capability={Capability} CorrelationId={CorrelationId}",
                capability,
                context.CorrelationId);
        }
    }
}
