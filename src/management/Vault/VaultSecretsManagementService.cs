#if !APPLICATION_CONTRACTS
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Vault;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Vault;

#if APPLICATION_CONTRACTS

public interface IVaultSecretsManagementService
{
    Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret?> GetAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret> PutAsync(
        string name,
        string contextId,
        SaveManagementVaultSecret command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementVaultSecret(
    string Name,
    string Namespace,
    string ContextId,
    string OwnerSubject,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    bool HasValue);

public sealed record SaveManagementVaultSecret(string Value);

#else

public sealed class VaultSecretsManagementService(
    AppDbContext database,
    IVaultNamedSecretStore store,
    IManagementAuthorizationEvaluator authorization,
    IOptions<VaultOptions> options,
    IOptions<ManagementOptions> managementOptions)
    : IVaultSecretsManagementService
{
    public async Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var normalizedContext = VaultBackedSecretStore.NormalizeContextId(
            contextId);
        // Vault secret contexts (contextId/namespaces) remain as pure data
        // organization after the multi-tenant removal (2026-08 decision);
        // access is gated by the vault capability + MFA, not by tenant.
        var resource = new ManagementResource(
            ManagementResourceTypes.VaultSecretCollection);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsRead,
            resource,
            cancellationToken);
        EnsureEnabled();
        var items = await store.ListAsync(
            normalizedContext,
            namespaces: null,
            cancellationToken);
        await AuditBreakGlassReadAsync(
            context,
            resource,
            ResolveDecision(context, objectDecision),
            cancellationToken);
        return items.Select(ToContract).ToArray();
    }

    public async Task<ManagementVaultSecret?> GetAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        var normalizedContext = VaultBackedSecretStore.NormalizeContextId(
            contextId);
        var resource = ItemResource(normalized);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsRead,
            resource,
            cancellationToken);
        EnsureEnabled();
        var items = await store.ListAsync(
            normalizedContext,
            namespaces: null,
            cancellationToken);
        var result = items.FirstOrDefault(item => item.Name == normalized)
            is { } item ? ToContract(item) : null;
        await AuditBreakGlassReadAsync(
            context,
            resource,
            ResolveDecision(context, objectDecision),
            cancellationToken);
        return result;
    }

    public async Task<ManagementVaultSecret> PutAsync(
        string name,
        string contextId,
        SaveManagementVaultSecret command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        var normalizedContext = VaultBackedSecretStore.NormalizeContextId(
            contextId);
        var resource = ItemResource(normalized);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            resource,
            cancellationToken);
        var decision = ResolveDecision(context, objectDecision);
        EnsureEnabled();
        if (string.IsNullOrWhiteSpace(command.Value))
            throw new ManagementValidationException(
                "secret_value_required", "O valor do segredo é obrigatório.", "value");

        var metadata = await store.PutAsync(
            normalized,
            command.Value,
            context.OperatorSubject,
            normalizedContext,
            cancellationToken);
        database.ManagementAuditEvents.Add(
            Sufficit.Identity.Management.Audit.ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsManage,
                resource,
                decision,
                "succeeded",
                decision.ReasonCode == "vault_break_glass"
                    ? "vault_break_glass"
                    : "vault_secret_updated"));
        await database.SaveChangesAsync(cancellationToken);
        return ToContract(metadata);
    }

    public async Task DeleteAsync(
        string name,
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        var normalizedContext = VaultBackedSecretStore.NormalizeContextId(
            contextId);
        var resource = ItemResource(normalized);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            resource,
            cancellationToken);
        var decision = ResolveDecision(context, objectDecision);
        EnsureEnabled();
        if (!await store.DeleteAsync(
                normalized,
                normalizedContext,
                cancellationToken))
            throw new ManagementNotFoundException(
                "secret_not_found", "Segredo nomeado não encontrado.");
        database.ManagementAuditEvents.Add(
            Sufficit.Identity.Management.Audit.ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsManage,
                resource,
                decision,
                "succeeded",
                decision.ReasonCode == "vault_break_glass"
                    ? "vault_break_glass"
                    : "vault_secret_deleted"));
        await database.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Decorates the object decision with the break-glass reason when the
    /// operator carries the dedicated emergency claim AND MFA evidence. With
    /// the tenant boundary removed, break-glass grants no extra access — it
    /// exists so emergency sessions are unmissable in the audit trail (every
    /// vault operation performed under it is journaled with the
    /// vault_break_glass reason).
    /// </summary>
    private ManagementAuthorizationDecision ResolveDecision(
        ManagementRequestContext context,
        ManagementAuthorizationDecision objectDecision) =>
        ConfigurationManagementObjectAccessPolicy.HasVaultBreakGlassEvidence(
            context.Operator,
            managementOptions.Value.Authorization.VaultSecrets)
            ? ManagementAuthorizationDecision.Allowed("vault_break_glass")
            : objectDecision;

    private async Task AuditBreakGlassReadAsync(
        ManagementRequestContext context,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(
                decision.ReasonCode,
                "vault_break_glass",
                StringComparison.Ordinal))
        {
            return;
        }

        database.ManagementAuditEvents.Add(
            Sufficit.Identity.Management.Audit.ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsRead,
                resource,
                decision,
                "succeeded",
                "vault_break_glass"));
        await database.SaveChangesAsync(cancellationToken);
    }

    private static ManagementResource ItemResource(
        string normalizedName) =>
        new(
            ManagementResourceTypes.VaultSecrets,
            normalizedName);

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator, capability, resource, cancellationToken);
        if (!decision.IsAllowed)
            throw new ManagementAccessException(decision);
        return decision;
    }

    private void EnsureEnabled()
    {
        if (!options.Value.Enabled)
            throw new ManagementValidationException(
                "vault_required",
                "Habilite Sufficit:Vault:Enabled antes de administrar segredos.");
    }

    private static ManagementVaultSecret ToContract(VaultSecretMetadata item) =>
        new(
            item.Name,
            item.Namespace,
            item.ContextId,
            item.OwnerSubject,
            item.UpdatedAtUtc,
            item.UpdatedBy,
            item.HasValue);
}

#endif
