using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Vault;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Management.Mcp;

public sealed partial class VaultMcpTools
{
    private McpToolDescriptor PrepareEntryTool => new(
        "vault_prepare_entry",
        "Prepare a complete browser link for the user to paste and save an API key or password directly in their personal Sufficit Identity Vault. Use this when connecting services such as ASAAS that require an API key. Never ask for the value in chat. This only prepares metadata; it does not create an empty secret. After the user saves, call vault_get_info with the exact returned secretName; do not resolve plaintext just to check existence.",
        Schema(new Dictionary<string, object>
        {
            ["name"] = new { type = "string", description = "Personal entry name without the personal/ prefix, e.g. asaas/production/api-key. Never include the secret value." },
        }, required: ["name"]),
        PrepareEntryAsync);

    private async Task<object> PrepareEntryAsync(
        McpToolCallContext context, JsonElement args, CancellationToken ct)
    {
        EnsureEnabled();
        string name;
        try
        {
            name = UserVaultPersonalSecretService.ToStoredName(
                IdentityMcpToolRegistry.RequireString(args, "name"));
        }
        catch (ArgumentException)
        {
            throw new McpToolException("Use a valid personal entry name, e.g. asaas/production/api-key.");
        }
        var request = httpContextAccessor.HttpContext?.Request
            ?? throw new McpToolException("The Vault browser address is unavailable.");
        if (!request.IsHttps && !string.Equals(request.Host.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            throw new McpToolException("A secure Identity browser address is required.");
        var origin = $"{request.Scheme}://{request.Host}{request.PathBase}";
        var vaultContext = UserVaultPersonalSecretService.ContextFor(context.Subject);
        var entries = await store.ListAsync(vaultContext,
            new HashSet<string>(StringComparer.Ordinal) { "personal" }, ct);
        var existing = entries.FirstOrDefault(item => item.Name == name);
        return new
        {
            url = QueryHelpers.AddQueryString(origin + "/vault/new", "name",
                UserVaultPersonalSecretService.ToDisplayName(name)),
            secretName = name,
            exists = existing is not null,
            status = existing is null ? "missing" : VaultSecretExpiration.GetStatus(existing.ExpiresAtUtc, DateTime.UtcNow).ToString(),
            saved = false,
            nextStep = "Ask the user to open the link while signed in to the same Sufficit account, paste the key and save. Then check vault_get_info with secretName, without contextId. A saved key is not yet proof that the provider accepts it.",
        };
    }
}
