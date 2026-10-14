using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Mcp;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Reads one secret of a shared Vault context with the personal-Vault scopes. Exists for
/// first-party agents whose conversation must not touch anybody's personal Vault (a group
/// conversation of a shared agent): they resolve credentials of a shared context instead.
/// The rule is the Identity MCP's: a context other than the caller's own personal one needs
/// the Vault resolve capability, every read is audited, and nothing is listed or written here.
/// </summary>
[ApiController]
[Authorize(Policy = PersonalVaultController.PolicyName)]
[Route("api/vault/context/secrets")]
public sealed class SharedContextVaultController(
    IVaultNamedSecretStore store,
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization,
    IOptions<VaultOptions> options) : ControllerBase
{
    /// <summary>Querystring on purpose: <c>GET …/resolve?contextId=&amp;name=</c>.
    /// 403 = no capability for shared contexts, 404 = absent, 410 = expired.</summary>
    [HttpGet("resolve")]
    public async Task<IActionResult> Resolve(
        [FromQuery] string name,
        [FromQuery] string contextId,
        CancellationToken cancellationToken = default)
    {
        if (!options.Value.Enabled)
            throw new InvalidOperationException("The Vault is disabled on this deployment (Sufficit:Vault:Enabled).");
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(contextId))
            return BadRequest(new { error = "name_and_context_required" });
        var context = VaultBackedSecretStore.NormalizeContextId(contextId);
        if (context.StartsWith(VaultMcpTools.PersonalContextPrefix, StringComparison.Ordinal))
            return BadRequest(new { error = "shared_context_only" }); // personal Vaults have their own API
        var decision = await authorization.EvaluateAsync(
            User,
            ManagementCapabilities.VaultSecretsResolve,
            new ManagementResource(ManagementResourceTypes.VaultSecretCollection),
            cancellationToken);
        if (!decision.IsAllowed)
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "context_not_allowed", contextId = context });

        var normalizedName = VaultBackedSecretStore.NormalizeName(name);
        var resolution = await store.ResolveAsync(normalizedName, context, cancellationToken);
        var status = VaultSecretExpiration.GetStatus(resolution?.Metadata.ExpiresAtUtc, DateTime.UtcNow);
        database.ManagementAuditEvents.Add(Audit.ManagementAuditEventFactory.Create(
            new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            ManagementCapabilities.VaultSecretsResolve,
            new ManagementResource(ManagementResourceTypes.VaultSecrets, normalizedName),
            decision,
            "succeeded",
            resolution is null ? "context_vault_resolve_missing"
            : status == VaultSecretStatus.Expired ? "context_vault_resolve_expired"
            : "context_vault_resolved"));
        await database.SaveChangesAsync(cancellationToken);
        if (resolution is null) return NotFound();
        if (status == VaultSecretStatus.Expired || resolution.Value is null)
            return StatusCode(StatusCodes.Status410Gone, new { name = normalizedName, contextId = context, status = status.ToString() });
        return Ok(new
        {
            name = normalizedName,
            contextId = context,
            value = resolution.Value,
            status = status.ToString(),
            expiresAtUtc = resolution.Metadata.ExpiresAtUtc,
        });
    }
}
