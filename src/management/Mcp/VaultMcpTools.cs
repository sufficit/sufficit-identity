using System.Text.Json;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Management.Mcp;

/// <summary>
/// Vault tools for MCP agents, operating directly on the named-secret store.
/// Default scope is the caller's personal context (<c>user-&lt;sub&gt;</c>);
/// an explicit <c>contextId</c> targets a shared context and requires the
/// corresponding vault capability. Plaintext resolution demands the
/// <c>confirmPlaintext</c> flag and is always journaled.
/// </summary>
public sealed class VaultMcpTools(
    IVaultNamedSecretStore store,
    IManagementAuthorizationEvaluator authorization,
    AppDbContext database,
    IOptions<VaultOptions> options)
{
    internal const string PersonalContextPrefix = "user-";

    public IReadOnlyList<McpToolDescriptor> Tools =>
    [
        new(
            "vault_list",
            "Lists secret metadata (never values) in your personal vault, or in an explicit shared context when authorized. Secrets in the ai/ namespace are also visible to Sufficit AI agents.",
            Schema(new Dictionary<string, object>
            {
                ["contextId"] = new { type = "string", description = "Optional shared context. Omit for your personal vault." },
            }),
            ListAsync),
        new(
            "vault_get_info",
            "Returns metadata (never the value) for one secret.",
            Schema(new Dictionary<string, object>
            {
                ["name"] = new { type = "string", description = "Secret path, e.g. ai/anthropic-key." },
                ["contextId"] = new { type = "string", description = "Optional shared context. Omit for your personal vault." },
            }, required: ["name"]),
            GetInfoAsync),
        new(
            "vault_save",
            "Creates or rotates a secret. Optional ISO-8601 expiresAtUtc; expired secrets stop resolving.",
            Schema(new Dictionary<string, object>
            {
                ["name"] = new { type = "string", description = "Secret path, e.g. ai/anthropic-key. Use the ai/ namespace to share with Sufficit AI agents." },
                ["value"] = new { type = "string", description = "Plaintext value to store (encrypted at rest)." },
                ["expiresAtUtc"] = new { type = "string", description = "Optional ISO-8601 expiration instant (must be in the future)." },
                ["contextId"] = new { type = "string", description = "Optional shared context. Omit for your personal vault." },
            }, required: ["name", "value"]),
            SaveAsync),
        new(
            "vault_delete",
            "Deletes a secret.",
            Schema(new Dictionary<string, object>
            {
                ["name"] = new { type = "string" },
                ["contextId"] = new { type = "string", description = "Optional shared context. Omit for your personal vault." },
            }, required: ["name"]),
            DeleteAsync),
        new(
            "vault_resolve",
            "Returns the PLAINTEXT value of a secret. Requires confirmPlaintext=true. Every resolution is audited; expired secrets are refused.",
            Schema(new Dictionary<string, object>
            {
                ["name"] = new { type = "string" },
                ["confirmPlaintext"] = new { type = "boolean", description = "Must be true to disclose the value." },
                ["contextId"] = new { type = "string", description = "Optional shared context. Omit for your personal vault." },
            }, required: ["name", "confirmPlaintext"]),
            ResolveAsync),
    ];

    private async Task<object> ListAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var vaultContext = await ResolveContextAsync(
            context, args, ManagementCapabilities.VaultSecretsRead, ct);
        EnsureEnabled();
        var now = DateTime.UtcNow;
        var items = await store.ListAsync(vaultContext, namespaces: null, ct);
        return new
        {
            contextId = vaultContext,
            secrets = items.Select(item => new
            {
                name = item.Name,
                @namespace = item.Namespace,
                updatedAtUtc = item.UpdatedAtUtc,
                expiresAtUtc = item.ExpiresAtUtc,
                status = VaultSecretExpiration.GetStatus(item.ExpiresAtUtc, now)
                    .ToString(),
            }),
        };
    }

    private async Task<object> GetInfoAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var vaultContext = await ResolveContextAsync(
            context, args, ManagementCapabilities.VaultSecretsRead, ct);
        EnsureEnabled();
        var name = NormalizeName(args);
        var items = await store.ListAsync(vaultContext, namespaces: null, ct);
        var item = items.FirstOrDefault(candidate => candidate.Name == name)
            ?? throw new McpToolException($"Secret '{name}' not found.");
        return new
        {
            name = item.Name,
            @namespace = item.Namespace,
            contextId = item.ContextId,
            updatedAtUtc = item.UpdatedAtUtc,
            updatedBy = item.UpdatedBy,
            expiresAtUtc = item.ExpiresAtUtc,
            status = VaultSecretExpiration.GetStatus(
                item.ExpiresAtUtc, DateTime.UtcNow).ToString(),
        };
    }

    private async Task<object> SaveAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var vaultContext = await ResolveContextAsync(
            context, args, ManagementCapabilities.VaultSecretsManage, ct);
        EnsureEnabled();
        var name = NormalizeName(args);
        var value = IdentityMcpToolRegistry.RequireString(args, "value");
        var expiresAtUtc = IdentityMcpToolRegistry.ReadUtcInstant(args, "expiresAtUtc");
        if (expiresAtUtc is { } expiration && expiration <= DateTime.UtcNow)
            throw new McpToolException("expiresAtUtc must be in the future.");

        var metadata = await store.PutAsync(
            name, value, context.Subject, vaultContext, expiresAtUtc, ct);
        return new
        {
            saved = true,
            name = metadata.Name,
            contextId = metadata.ContextId,
            expiresAtUtc = metadata.ExpiresAtUtc,
        };
    }

    private async Task<object> DeleteAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        var vaultContext = await ResolveContextAsync(
            context, args, ManagementCapabilities.VaultSecretsManage, ct);
        EnsureEnabled();
        var name = NormalizeName(args);
        if (!await store.DeleteAsync(name, vaultContext, ct))
            throw new McpToolException($"Secret '{name}' not found.");
        return new { deleted = true, name };
    }

    private async Task<object> ResolveAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        if (!IdentityMcpToolRegistry.ReadBool(args, "confirmPlaintext"))
            throw new McpToolException(
                "confirmPlaintext must be true to return a secret value.");

        var vaultContext = await ResolveContextAsync(
            context, args, ManagementCapabilities.VaultSecretsResolve, ct);
        EnsureEnabled();
        var name = NormalizeName(args);
        var resolution = await store.ResolveAsync(name, vaultContext, ct);
        var status = VaultSecretExpiration.GetStatus(
            resolution?.Metadata.ExpiresAtUtc, DateTime.UtcNow);
        await AuditResolveAsync(context, name, resolution, status, ct);
        if (resolution is null)
            throw new McpToolException($"Secret '{name}' not found.");
        if (status == VaultSecretStatus.Expired || resolution.Value is null)
            throw new McpToolException($"Secret '{name}' is expired.");

        return new
        {
            name,
            contextId = vaultContext,
            value = resolution.Value,
            status = status.ToString(),
            expiresAtUtc = resolution.Metadata.ExpiresAtUtc,
        };
    }

    /// <summary>
    /// Personal context by default; an explicit non-personal context is an
    /// operator surface and demands the corresponding vault capability.
    /// </summary>
    private async Task<string> ResolveContextAsync(
        McpToolCallContext context,
        JsonElement args,
        string capability,
        CancellationToken ct)
    {
        var personal = VaultBackedSecretStore.NormalizeContextId(
            PersonalContextPrefix + context.Subject.ToLowerInvariant());
        var requested = IdentityMcpToolRegistry.ReadString(args, "contextId");
        if (string.IsNullOrWhiteSpace(requested))
            return personal;

        var normalized = VaultBackedSecretStore.NormalizeContextId(requested);
        if (string.Equals(normalized, personal, StringComparison.Ordinal))
            return personal;

        var decision = await authorization.EvaluateAsync(
            context.Principal,
            capability,
            new ManagementResource(ManagementResourceTypes.VaultSecretCollection),
            ct);
        if (!decision.IsAllowed)
            throw new McpToolException(
                $"Access to context '{normalized}' requires the {capability} capability.");
        return normalized;
    }

    private async Task AuditResolveAsync(
        McpToolCallContext context,
        string name,
        VaultNamedSecretResolution? resolution,
        VaultSecretStatus status,
        CancellationToken ct)
    {
        database.ManagementAuditEvents.Add(
            Audit.ManagementAuditEventFactory.Create(
                context.AsManagementContext(),
                ManagementCapabilities.VaultSecretsResolve,
                new ManagementResource(ManagementResourceTypes.VaultSecrets, name),
                ManagementAuthorizationDecision.Allowed("mcp_self_service"),
                "succeeded",
                resolution is null
                    ? "vault_secret_resolve_missing"
                    : status == VaultSecretStatus.Expired
                        ? "vault_secret_resolve_expired"
                        : "vault_secret_resolved"));
        await database.SaveChangesAsync(ct);
    }

    private void EnsureEnabled()
    {
        if (!options.Value.Enabled)
            throw new McpToolException(
                "The vault is disabled on this deployment (Sufficit:Vault:Enabled).");
    }

    private static string NormalizeName(JsonElement args)
    {
        try
        {
            return VaultBackedSecretStore.NormalizeName(
                IdentityMcpToolRegistry.RequireString(args, "name"));
        }
        catch (ArgumentException exception)
        {
            throw new McpToolException(exception.Message);
        }
    }

    private static object Schema(
        Dictionary<string, object> properties,
        string[]? required = null) => new
    {
        type = "object",
        properties,
        required = required ?? [],
    };
}
