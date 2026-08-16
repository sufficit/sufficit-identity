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

    /// <summary>Plaintext disclosure. Requires the dedicated resolve
    /// capability and journals every call. Returns null when the secret does
    /// not exist; an expired secret is returned with a null value and
    /// <see cref="VaultSecretStatus.Expired"/> so the API can answer 410.</summary>
    Task<ResolvedManagementVaultSecret?> ResolveAsync(
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

public enum VaultSecretStatus
{
    Active,
    ExpiringSoon,
    Expired,
}

/// <summary>Shared expiration semantics so every surface (management API,
/// clients, UI) reports the same status for the same instant.</summary>
public static class VaultSecretExpiration
{
    /// <summary>Secrets expiring within this window report
    /// <see cref="VaultSecretStatus.ExpiringSoon"/> so operators can rotate
    /// before resolution starts failing.</summary>
    public static readonly TimeSpan ExpiringSoonWindow = TimeSpan.FromDays(7);

    public static VaultSecretStatus GetStatus(
        DateTime? expiresAtUtc,
        DateTime nowUtc)
    {
        if (expiresAtUtc is not { } expiration) return VaultSecretStatus.Active;
        if (expiration <= nowUtc) return VaultSecretStatus.Expired;
        return expiration - nowUtc <= ExpiringSoonWindow
            ? VaultSecretStatus.ExpiringSoon
            : VaultSecretStatus.Active;
    }
}

public sealed record ManagementVaultSecret(
    string Name,
    string Namespace,
    string ContextId,
    string OwnerSubject,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    bool HasValue,
    DateTime? ExpiresAtUtc = null,
    VaultSecretStatus Status = VaultSecretStatus.Active);

public sealed record ResolvedManagementVaultSecret(
    string Name,
    string Namespace,
    string ContextId,
    string? Value,
    VaultSecretStatus Status,
    DateTime? ExpiresAtUtc,
    DateTime UpdatedAtUtc);

public sealed record SaveManagementVaultSecret(
    string Value,
    DateTime? ExpiresAtUtc = null);

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
        if (command.ExpiresAtUtc is { } expiration
            && expiration <= DateTime.UtcNow)
            throw new ManagementValidationException(
                "secret_expiration_invalid",
                "A expiração do segredo deve estar no futuro.",
                "expiresAtUtc");

        var metadata = await store.PutAsync(
            normalized,
            command.Value,
            context.OperatorSubject,
            normalizedContext,
            command.ExpiresAtUtc,
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

    public async Task<ResolvedManagementVaultSecret?> ResolveAsync(
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
            ManagementCapabilities.VaultSecretsResolve,
            resource,
            cancellationToken);
        var decision = ResolveDecision(context, objectDecision);
        EnsureEnabled();
        var resolution = await store.ResolveAsync(
            normalized,
            normalizedContext,
            cancellationToken);
        // Plaintext disclosure (and the expired refusal) is always journaled,
        // unlike metadata reads which only journal under break-glass.
        var status = VaultSecretExpiration.GetStatus(
            resolution?.Metadata.ExpiresAtUtc,
            DateTime.UtcNow);
        database.ManagementAuditEvents.Add(
            Sufficit.Identity.Management.Audit.ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsResolve,
                resource,
                decision,
                "succeeded",
                resolution is null
                    ? "vault_secret_resolve_missing"
                    : status == VaultSecretStatus.Expired
                        ? "vault_secret_resolve_expired"
                        : "vault_secret_resolved"));
        await database.SaveChangesAsync(cancellationToken);
        if (resolution is null) return null;

        return new ResolvedManagementVaultSecret(
            resolution.Metadata.Name,
            resolution.Metadata.Namespace,
            resolution.Metadata.ContextId,
            resolution.Value,
            status,
            resolution.Metadata.ExpiresAtUtc,
            resolution.Metadata.UpdatedAtUtc);
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
            item.HasValue,
            item.ExpiresAtUtc,
            VaultSecretExpiration.GetStatus(
                item.ExpiresAtUtc,
                DateTime.UtcNow));
}

#endif
