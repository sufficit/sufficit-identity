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
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Subject-bound HTTP adapter for the personal Identity Vault. Unlike the
/// management Vault API, callers cannot choose a context: every operation is
/// forced into <c>user-&lt;sub&gt;</c>. It exists so first-party device clients
/// can implement a secret store without tunnelling CRUD through MCP tool calls.
/// </summary>
/// <remarks>
/// Two scopes open it. The Identity MCP scope gives the whole personal Vault, as
/// before. The narrow <see cref="NarrowScope"/> is what a delegated agent
/// credential carries (a cloud executor acting for its owner): it never gets the
/// Identity MCP, and with this scope alone it reads and writes only
/// <c>genius/…</c> (Genius device secrets, such as an agent's channel tokens) and
/// reads <c>ai/…</c> (what the owner shares with their AI agents).
/// </remarks>
[ApiController]
[Authorize(Policy = PolicyName)]
[Route("api/vault/personal/secrets")]
public sealed class PersonalVaultController(
    IVaultNamedSecretStore store,
    AppDbContext database,
    IOptions<VaultOptions> options,
    IAuthorizationService authorization) : ControllerBase
{
    public const string PolicyName = "sufficit-identity-personal-vault";
    public const string NarrowScope = "identity.vault";
    private static readonly string[] NarrowWritable = ["genius/"];
    private static readonly string[] NarrowReadable = ["genius/", "ai/"];

    [HttpGet]
    public async Task<IActionResult> List(
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var narrow = await IsNarrowAsync();
        var items = (await store.ListAsync(
            PersonalContext(),
            namespaces: null,
            cancellationToken))
            .Where(item => !narrow || Allowed(item.Name, NarrowReadable));
        var now = DateTime.UtcNow;

        return Ok(new
        {
            secrets = items.Select(item => new
            {
                name = item.Name,
                @namespace = item.Namespace,
                updatedAtUtc = item.UpdatedAtUtc,
                expiresAtUtc = item.ExpiresAtUtc,
                status = VaultSecretExpiration.GetStatus(
                    item.ExpiresAtUtc,
                    now).ToString(),
            }),
        });
    }

    [HttpGet("{*name}")]
    public async Task<IActionResult> Resolve(
        string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalizedName = NormalizeName(name);
        if (await IsNarrowAsync() && !Allowed(normalizedName, NarrowReadable))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "vault_name_outside_scope" });
        }
        var contextId = PersonalContext();
        var resolution = await store.ResolveAsync(
            normalizedName,
            contextId,
            cancellationToken);
        var status = VaultSecretExpiration.GetStatus(
            resolution?.Metadata.ExpiresAtUtc,
            DateTime.UtcNow);
        await AuditResolveAsync(
            normalizedName,
            resolution,
            status,
            cancellationToken);
        if (resolution is null)
        {
            return NotFound();
        }
        if (status == VaultSecretStatus.Expired || resolution.Value is null)
        {
            return StatusCode(StatusCodes.Status410Gone, new
            {
                name = normalizedName,
                contextId,
                status = status.ToString(),
                expiresAtUtc = resolution.Metadata.ExpiresAtUtc,
            });
        }

        return Ok(new
        {
            name = normalizedName,
            contextId,
            value = resolution.Value,
            status = status.ToString(),
            expiresAtUtc = resolution.Metadata.ExpiresAtUtc,
        });
    }

    [HttpPut("{*name}")]
    public async Task<IActionResult> Put(
        string name,
        [FromBody] SavePersonalVaultSecret command,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        if (string.IsNullOrWhiteSpace(command.Value))
        {
            return BadRequest(new { error = "value_required" });
        }
        if (command.ExpiresAtUtc is { } expiration
            && expiration <= DateTime.UtcNow)
        {
            return BadRequest(new { error = "expiration_must_be_in_the_future" });
        }

        var normalizedName = NormalizeName(name);
        if (await IsNarrowAsync() && !Allowed(normalizedName, NarrowWritable))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "vault_name_outside_scope" });
        }
        var contextId = PersonalContext();
        var metadata = await store.PutAsync(
            normalizedName,
            command.Value,
            Subject(),
            contextId,
            command.ExpiresAtUtc,
            cancellationToken);
        return Ok(new
        {
            saved = true,
            name = metadata.Name,
            contextId = metadata.ContextId,
            expiresAtUtc = metadata.ExpiresAtUtc,
        });
    }

    [HttpDelete("{*name}")]
    public async Task<IActionResult> Delete(
        string name,
        CancellationToken cancellationToken = default)
    {
        EnsureEnabled();
        var normalizedName = NormalizeName(name);
        if (await IsNarrowAsync() && !Allowed(normalizedName, NarrowWritable))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "vault_name_outside_scope" });
        }
        var deleted = await store.DeleteAsync(
            normalizedName,
            PersonalContext(),
            cancellationToken);
        return deleted ? NoContent() : NotFound();
    }

    /// <summary>True when the caller holds only the narrow scope, not the Identity MCP.</summary>
    private async Task<bool> IsNarrowAsync() =>
        !(await authorization.AuthorizeAsync(User, McpResourceMetadataChallenge.PolicyName)).Succeeded;

    private static bool Allowed(string name, IEnumerable<string> prefixes) =>
        prefixes.Any(prefix => name.StartsWith(prefix, StringComparison.Ordinal));

    private string PersonalContext() =>
        VaultBackedSecretStore.NormalizeContextId(
            VaultMcpTools.PersonalContextPrefix + Subject().ToLowerInvariant());

    private string Subject() => User.GetClaim(OpenIddictConstants.Claims.Subject)
        ?? throw new InvalidOperationException(
            "The authenticated personal Vault caller has no subject.");

    private void EnsureEnabled()
    {
        if (!options.Value.Enabled)
        {
            throw new InvalidOperationException(
                "The Vault is disabled on this deployment (Sufficit:Vault:Enabled).");
        }
    }

    private static string NormalizeName(string name) =>
        VaultBackedSecretStore.NormalizeName(name);

    private async Task AuditResolveAsync(
        string name,
        VaultNamedSecretResolution? resolution,
        VaultSecretStatus status,
        CancellationToken cancellationToken)
    {
        database.ManagementAuditEvents.Add(
            Audit.ManagementAuditEventFactory.Create(
                new ManagementRequestContext(
                    User,
                    HttpContext.TraceIdentifier),
                ManagementCapabilities.VaultSecretsResolve,
                new ManagementResource(
                    ManagementResourceTypes.VaultSecrets,
                    name),
                ManagementAuthorizationDecision.Allowed(
                    "personal_vault_scope"),
                "succeeded",
                resolution is null
                    ? "personal_vault_resolve_missing"
                    : status == VaultSecretStatus.Expired
                        ? "personal_vault_resolve_expired"
                        : "personal_vault_resolved"));
        await database.SaveChangesAsync(cancellationToken);
    }
}

public sealed record SavePersonalVaultSecret(
    string Value,
    DateTime? ExpiresAtUtc = null);
