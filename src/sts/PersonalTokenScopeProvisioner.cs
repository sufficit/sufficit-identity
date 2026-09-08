using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>Reconciles the self-service scope and explicitly configured client
/// permissions before serving traffic. Existing unrelated permissions are preserved.</summary>
public sealed class PersonalTokenScopeProvisioner(
    IOpenIddictScopeManager scopes,
    IOpenIddictApplicationManager applications,
    SufficitIdentityOptions options,
    ILogger<PersonalTokenScopeProvisioner> logger)
{
    public async Task ProvisionAsync(CancellationToken cancellationToken = default)
    {
        var scopeName = options.PersonalTokens.RequiredScope.Trim();
        if (string.IsNullOrWhiteSpace(scopeName))
            return;

        if (await scopes.FindByNameAsync(scopeName, cancellationToken) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = scopeName,
                DisplayName = "Manage your own personal tokens",
                Description = "Issue personal tokens within your delegated authority; MFA and recent authentication are required.",
            }, cancellationToken);
        }

        foreach (var clientId in options.PersonalTokens.ScopeClientIds
                     .Where(value => !string.IsNullOrWhiteSpace(value))
                     .Select(value => value.Trim()).Distinct(StringComparer.Ordinal))
        {
            var application = await applications.FindByClientIdAsync(clientId, cancellationToken);
            if (application is null)
            {
                logger.LogWarning("Personal-token scope client {ClientId} is not registered.", clientId);
                continue;
            }

            var permission = Permissions.Prefixes.Scope + scopeName;
            if (await applications.HasPermissionAsync(application, permission, cancellationToken))
                continue;

            var descriptor = new OpenIddictApplicationDescriptor();
            await applications.PopulateAsync(descriptor, application, cancellationToken);
            descriptor.Permissions.Add(permission);
            await applications.UpdateAsync(application, descriptor, cancellationToken);
            logger.LogInformation("Granted personal-token scope {Scope} to configured client {ClientId}.", scopeName, clientId);
        }
    }
}
