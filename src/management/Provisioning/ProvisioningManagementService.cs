using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Provisioning;

internal sealed class ProvisioningManagementService(
    OpenIddictManifestProvisioner provisioner,
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    IReservedScopePolicy reservedScopePolicy,
    IClientDefinitionValidator clientDefinitionValidator,
    ILogger<ProvisioningManagementService> logger,
    IManagementEntitlementResolver entitlements,
    IClientScopeGrantAuthorization scopeGrants)
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
            IdentityProvisioningManifestValidator.ValidateAndThrow(
                manifest,
                reservedScopePolicy,
                clientDefinitionValidator);
            await AuthorizeScopeGrantsAsync(
                manifest,
                context,
                ManagementCapabilities.ProvisioningPreview,
                cancellationToken);
            var plan = await provisioner.PreviewAsync(
                manifest,
                cancellationToken,
                context.OperatorSubject);
            foreach (var observed in plan.Changes.Where(change =>
                         change.Kind is IdentityManifestChangeKind.Observed))
            {
                await TryWriteAuditAsync(
                    context,
                    ManagementCapabilities.ProvisioningPreview,
                    decision,
                    "observed",
                    "provisioning_client_transition_observed",
                    cancellationToken);
            }
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
        catch (ManagementAccessException)
        {
            // Recorded per client by the scope-grant decision.
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

    public async Task<IdentityProvisioningInventory> InventoryAsync(
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
            var inventory = await provisioner.InventoryAsync(
                manifest,
                cancellationToken);
            await WriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningPreview,
                decision,
                "succeeded",
                "provisioning_manifest_inventory",
                cancellationToken);
            return inventory with { CorrelationId = context.CorrelationId };
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
                "Provisioning inventory failed. CorrelationId={CorrelationId}",
                context.CorrelationId);
            await TryWriteAuditAsync(
                context,
                ManagementCapabilities.ProvisioningPreview,
                decision,
                "failed",
                "provisioning_inventory_failed",
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
            IdentityProvisioningManifestValidator.ValidateAndThrow(
                manifest,
                reservedScopePolicy,
                clientDefinitionValidator);
            await AuthorizeScopeGrantsAsync(
                manifest,
                context,
                ManagementCapabilities.ProvisioningApply,
                cancellationToken);
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
                cancellationToken,
                context.OperatorSubject);
            foreach (var adoption in plan.Changes.Where(change =>
                         change.Kind is IdentityManifestChangeKind.Adopted))
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.ProvisioningApply,
                        new ManagementResource(
                            ManagementResourceTypes.Client,
                            adoption.Identifier),
                        decision,
                        "succeeded",
                        "provisioning_client_adopted"));
            }

            foreach (var observed in plan.Changes.Where(change =>
                         change.Kind is IdentityManifestChangeKind.Observed))
            {
                database.ManagementAuditEvents.Add(
                    ManagementAuditEventFactory.Create(
                        context,
                        ManagementCapabilities.ProvisioningApply,
                        new ManagementResource(
                            ManagementResourceTypes.Client,
                            observed.Identifier),
                        decision,
                        "observed",
                        "provisioning_client_transition_observed"));
            }

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
                "The environment could not resolve the client's secret reference.");
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

    /// <summary>
    /// Plan A2: the operator applying a manifest may only put on its clients
    /// the privileged scopes they could grant by hand. A provisioning token
    /// carries only the two provisioning capabilities, so it grants no
    /// privileged scope a client does not already hold.
    /// </summary>
    private async Task AuthorizeScopeGrantsAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        string operationCapability,
        CancellationToken cancellationToken)
    {
        if (manifest.Clients is not { Count: > 0 })
        {
            return;
        }

        var resolved = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var grantOperator = new ClientScopeGrantOperator(
            context.Operator.Identity?.IsAuthenticated is true
                ? context.OperatorSubject
                : null,
            resolved.Capabilities);
        ManagementAccessException? refusal = null;

        foreach (var client in manifest.Clients.OrderBy(
                     client => client.ClientId,
                     StringComparer.Ordinal))
        {
            var request = new ClientScopeGrantRequest(
                ClientDefinitionSource.Provisioning,
                grantOperator,
                client.ClientId,
                client.GrantTypes ?? [],
                client.Scopes ?? [],
                await provisioner.GetClientScopesAsync(
                    client.ClientId,
                    cancellationToken));
            var grant = scopeGrants.Decide(request);
            if (grant.Denials.Count == 0)
            {
                continue;
            }

            var primary = grant.Primary!;
            logger.LogWarning(
                "Manifest client scope grant {Outcome}: {ReasonCode} for scopes {Scopes} "
                + "(mode {Mode}). ClientId={ClientId} OperatorSubject={OperatorSubject} "
                + "CorrelationId={CorrelationId}",
                Sufficit.Identity.Core.Services.ClientScopeGrantAudit.OperationOutcome(grant),
                primary.ReasonCode,
                string.Join(' ', grant.Denials.Select(denial => denial.Scope)),
                grant.Mode,
                client.ClientId,
                context.OperatorSubject,
                context.CorrelationId);
            try
            {
                database.ManagementAuditEvents.Add(
                    Sufficit.Identity.Core.Services.ClientScopeGrantAudit.Create(
                        request,
                        grant,
                        operationCapability,
                        context.CorrelationId,
                        context.AuthenticationMethods));
                await database.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                database.ChangeTracker.Clear();
                logger.LogError(
                    exception,
                    "Unable to persist the manifest scope-grant audit row. CorrelationId={CorrelationId}",
                    context.CorrelationId);
            }

            if (!grant.IsAllowed)
            {
                refusal ??= new ManagementAccessException(
                    ManagementAuthorizationDecision.Denied(
                        primary.ReasonCode,
                        primary.RequiredCapability));
            }
        }

        // Every client is recorded before refusing, so one attempt shows the
        // whole manifest's expansion rather than only its first client.
        if (refusal is not null)
        {
            throw refusal;
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
