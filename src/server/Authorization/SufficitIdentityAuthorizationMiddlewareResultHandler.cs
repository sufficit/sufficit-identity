using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Scim;

namespace Sufficit.Identity.Server;

/// <summary>
/// Composes the authorization response behavior of the optional Management
/// and SCIM modules when both are enabled in the same host.
/// </summary>
public sealed class SufficitIdentityAuthorizationMiddlewareResultHandler(
    ManagementAuthorizationMiddlewareResultHandler managementHandler,
    ScimAuthorizationAuditHandler scimAuditHandler)
    : IAuthorizationMiddlewareResultHandler
{
    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        await managementHandler.HandleAsync(
            next,
            context,
            policy,
            authorizeResult);
        await scimAuditHandler.AuditAsync(context, authorizeResult);
    }
}
