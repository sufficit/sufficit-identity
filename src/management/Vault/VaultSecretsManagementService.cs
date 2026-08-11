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

public sealed record VaultSecretNamespaceDecision(
    ManagementAuthorizationDecision Authorization,
    IReadOnlySet<string>? Namespaces);

public interface IVaultSecretNamespaceAccessPolicy
{
    ValueTask<VaultSecretNamespaceDecision> ResolveAsync(
        System.Security.Claims.ClaimsPrincipal principal,
        string contextId,
        string? requiredNamespace,
        CancellationToken cancellationToken = default);
}

public sealed class ConfigurationVaultSecretNamespaceAccessPolicy(
    IOptions<Sufficit.Identity.Management.ManagementOptions> options)
    : IVaultSecretNamespaceAccessPolicy
{
    public ValueTask<VaultSecretNamespaceDecision> ResolveAsync(
        System.Security.Claims.ClaimsPrincipal principal,
        string contextId,
        string? requiredNamespace,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var policy = options.Value.Authorization.VaultSecrets;
        if (ConfigurationManagementObjectAccessPolicy
            .HasVaultBreakGlassEvidence(principal, policy))
        {
            return ValueTask.FromResult(new VaultSecretNamespaceDecision(
                ManagementAuthorizationDecision.Allowed("vault_break_glass"),
                Namespaces: null));
        }

        var normalizedContext = VaultBackedSecretStore.NormalizeContextId(
            contextId);
        var prefix = normalizedContext + ":";
        var namespaces = principal.FindAll(policy.NamespaceClaimType)
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries))
            .Where(value => value.StartsWith(prefix, StringComparison.Ordinal))
            .Select(value => value[prefix.Length..])
            .Select(TryNormalizeNamespace)
            .Where(value => value is not null)
            .Select(value => value!)
            .ToHashSet(StringComparer.Ordinal);

        if (requiredNamespace is not null
            && !namespaces.Contains(
                VaultBackedSecretStore.NormalizeNamespace(requiredNamespace)))
        {
            return ValueTask.FromResult(new VaultSecretNamespaceDecision(
                ManagementAuthorizationDecision.Denied(
                    "vault_namespace_not_accessible"),
                namespaces));
        }

        return ValueTask.FromResult(new VaultSecretNamespaceDecision(
            namespaces.Count > 0
                ? ManagementAuthorizationDecision.Allowed()
                : ManagementAuthorizationDecision.Denied(
                    "vault_namespace_not_accessible"),
            namespaces));
    }

    private static string? TryNormalizeNamespace(string value)
    {
        try
        {
            return VaultBackedSecretStore.NormalizeNamespace(value);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}

public sealed class VaultSecretsManagementService(
    AppDbContext database,
    IVaultNamedSecretStore store,
    IManagementAuthorizationEvaluator authorization,
    IVaultSecretNamespaceAccessPolicy namespaceAccess,
    IOptions<VaultOptions> options)
    : IVaultSecretsManagementService
{
    public async Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        string contextId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var normalizedContext = VaultBackedSecretStore.NormalizeContextId(
            contextId);
        var resource = new ManagementResource(
            ManagementResourceTypes.VaultSecretCollection,
            TenantId: normalizedContext);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsRead,
            resource,
            cancellationToken);
        var namespaceDecision = await DemandNamespaceAsync(
            context,
            normalizedContext,
            requiredNamespace: null,
            cancellationToken);
        EnsureEnabled();
        var items = await store.ListAsync(
            normalizedContext,
            namespaceDecision.Namespaces,
            cancellationToken);
        await AuditBreakGlassReadAsync(
            context,
            resource,
            EffectiveDecision(objectDecision, namespaceDecision.Authorization),
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
        var resource = ItemResource(normalized, normalizedContext);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsRead,
            resource,
            cancellationToken);
        var namespaceDecision = await DemandNamespaceAsync(
            context,
            normalizedContext,
            VaultBackedSecretStore.GetNamespace(normalized),
            cancellationToken);
        EnsureEnabled();
        var items = await store.ListAsync(
            normalizedContext,
            namespaceDecision.Namespaces,
            cancellationToken);
        var result = items.FirstOrDefault(item => item.Name == normalized)
            is { } item ? ToContract(item) : null;
        await AuditBreakGlassReadAsync(
            context,
            resource,
            EffectiveDecision(objectDecision, namespaceDecision.Authorization),
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
        var resource = ItemResource(normalized, normalizedContext);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            resource,
            cancellationToken);
        var namespaceDecision = await DemandNamespaceAsync(
            context,
            normalizedContext,
            VaultBackedSecretStore.GetNamespace(normalized),
            cancellationToken);
        var decision = EffectiveDecision(
            objectDecision,
            namespaceDecision.Authorization);
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
        var resource = ItemResource(normalized, normalizedContext);
        var objectDecision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            resource,
            cancellationToken);
        var namespaceDecision = await DemandNamespaceAsync(
            context,
            normalizedContext,
            VaultBackedSecretStore.GetNamespace(normalized),
            cancellationToken);
        var decision = EffectiveDecision(
            objectDecision,
            namespaceDecision.Authorization);
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

    private async Task<VaultSecretNamespaceDecision> DemandNamespaceAsync(
        ManagementRequestContext context,
        string contextId,
        string? requiredNamespace,
        CancellationToken cancellationToken)
    {
        var decision = await namespaceAccess.ResolveAsync(
            context.Operator,
            contextId,
            requiredNamespace,
            cancellationToken);
        if (!decision.Authorization.IsAllowed)
        {
            throw new ManagementAccessException(decision.Authorization);
        }
        return decision;
    }

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

    private static ManagementAuthorizationDecision EffectiveDecision(
        ManagementAuthorizationDecision objectDecision,
        ManagementAuthorizationDecision namespaceDecision) =>
        objectDecision.ReasonCode == "vault_break_glass"
            || namespaceDecision.ReasonCode == "vault_break_glass"
            ? ManagementAuthorizationDecision.Allowed("vault_break_glass")
            : objectDecision;

    private static ManagementResource ItemResource(
        string normalizedName,
        string normalizedContext) =>
        new(
            ManagementResourceTypes.VaultSecrets,
            normalizedName,
            normalizedContext);

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
