using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// Idempotently provisions the dedicated MCP scope and grants its OpenIddict
/// permission to configured first-party clients. The official server invokes
/// this after database readiness and before accepting requests.
/// </summary>
public sealed class McpScopeProvisioner(
    IOpenIddictScopeManager scopes,
    IOpenIddictApplicationManager applications,
    SufficitIdentityOptions options,
    ILogger<McpScopeProvisioner> logger)
{
    public async Task ProvisionAsync(CancellationToken cancellationToken = default)
    {
        var requiredScope = options.Mcp.RequiredScope.Trim();
        if (string.IsNullOrWhiteSpace(requiredScope))
        {
            throw new InvalidOperationException(
                "Sufficit:Identity:Mcp:RequiredScope must not be empty.");
        }

        if (await scopes.FindByNameAsync(requiredScope, cancellationToken) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = requiredScope,
                DisplayName = "Sufficit Identity MCP and personal Vault",
                Description =
                    "Access your own Identity self-service tools and personal Vault. " +
                    "This does not grant management or shared-context access.",
            }, cancellationToken);
            logger.LogInformation(
                "Provisioned the dedicated Identity MCP scope {Scope}.",
                requiredScope);
        }

        var permission = Permissions.Prefixes.Scope + requiredScope;
        foreach (var clientId in options.Mcp.ImplicitClientIds
                     .Where(value => !string.IsNullOrWhiteSpace(value))
                     .Select(value => value.Trim())
                     .Distinct(StringComparer.Ordinal))
        {
            var application = await applications.FindByClientIdAsync(
                clientId,
                cancellationToken);
            if (application is null)
            {
                logger.LogWarning(
                    "Trusted Identity MCP client {ClientId} is not registered; " +
                    "its implicit scope permission could not be provisioned.",
                    clientId);
                continue;
            }

            if (await applications.HasPermissionAsync(
                    application,
                    permission,
                    cancellationToken))
            {
                continue;
            }

            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(
                descriptor,
                application,
                cancellationToken);
            descriptor.Permissions.Add(permission);
            await applications.UpdateAsync(
                application,
                descriptor,
                cancellationToken);
            logger.LogInformation(
                "Granted scope {Scope} to trusted client {ClientId}.",
                requiredScope,
                clientId);
        }
    }
}
