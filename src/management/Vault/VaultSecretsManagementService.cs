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
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret?> GetAsync(
        string name,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementVaultSecret> PutAsync(
        string name,
        SaveManagementVaultSecret command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string name,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementVaultSecret(
    string Name,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    bool HasValue);

public sealed record SaveManagementVaultSecret(string Value);

#else

internal sealed class VaultSecretsManagementService(
    AppDbContext database,
    IVaultNamedSecretStore store,
    IManagementAuthorizationEvaluator authorization,
    IOptions<VaultOptions> options)
    : IVaultSecretsManagementService
{
    private static readonly ManagementResource Resource =
        new(ManagementResourceTypes.VaultSecrets);

    public async Task<IReadOnlyList<ManagementVaultSecret>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(context, ManagementCapabilities.VaultSecretsRead,
            Resource, cancellationToken);
        EnsureEnabled();
        var items = await store.ListAsync(cancellationToken);
        return items.Select(ToContract).ToArray();
    }

    public async Task<ManagementVaultSecret?> GetAsync(
        string name,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        await DemandAsync(context, ManagementCapabilities.VaultSecretsRead,
            Resource with { Id = normalized }, cancellationToken);
        EnsureEnabled();
        var items = await store.ListAsync(cancellationToken);
        return items.FirstOrDefault(item => item.Name == normalized)
            is { } item ? ToContract(item) : null;
    }

    public async Task<ManagementVaultSecret> PutAsync(
        string name,
        SaveManagementVaultSecret command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        var decision = await DemandAsync(context, ManagementCapabilities.VaultSecretsManage,
            Resource with { Id = normalized }, cancellationToken);
        EnsureEnabled();
        if (string.IsNullOrWhiteSpace(command.Value))
            throw new ManagementValidationException(
                "secret_value_required", "O valor do segredo é obrigatório.", "value");

        var metadata = await store.PutAsync(
            normalized,
            command.Value,
            context.OperatorSubject,
            cancellationToken);
        database.ManagementAuditEvents.Add(
            Sufficit.Identity.Management.Audit.ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsManage,
                Resource with { Id = normalized },
                decision,
                "succeeded",
                "vault_secret_updated"));
        await database.SaveChangesAsync(cancellationToken);
        return ToContract(metadata);
    }

    public async Task DeleteAsync(
        string name,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var normalized = VaultBackedSecretStore.NormalizeName(name);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.VaultSecretsManage,
            Resource with { Id = normalized },
            cancellationToken);
        EnsureEnabled();
        if (!await store.DeleteAsync(normalized, cancellationToken))
            throw new ManagementNotFoundException(
                "secret_not_found", "Segredo nomeado não encontrado.");
        database.ManagementAuditEvents.Add(
            Sufficit.Identity.Management.Audit.ManagementAuditEventFactory.Create(
                context,
                ManagementCapabilities.VaultSecretsManage,
                Resource with { Id = normalized },
                decision,
                "succeeded",
                "vault_secret_deleted"));
        await database.SaveChangesAsync(cancellationToken);
    }

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
        new(item.Name, item.UpdatedAtUtc, item.UpdatedBy, item.HasValue);
}

#endif
