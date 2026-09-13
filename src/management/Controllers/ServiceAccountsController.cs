using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.ServiceAccounts;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Service accounts: clients that authenticate on their own and receive
/// management capabilities through roles declared in the registration
/// (<c>identity:client:roles</c>). Read under <c>identity.clients.read</c>,
/// write under <c>identity.clients.update</c> — it is the client registry
/// that this surface edits.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/service-accounts")]
public sealed class ServiceAccountsController(
    IServiceAccountManagementService accounts) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ServiceAccountWorkspace>> Get(
        CancellationToken cancellationToken) =>
        Ok(await accounts.GetWorkspaceAsync(
            RequestContext(),
            cancellationToken));

    /// <summary>
    /// Creates a service account. The secret is returned ONLY ONCE in the
    /// response body — it is stored only as a hash and cannot be shown again.
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<ServiceAccountCreated>> Create(
        [FromBody] CreateServiceAccountCommand command,
        CancellationToken cancellationToken) =>
        Ok(await accounts.CreateAsync(
            command,
            RequestContext(),
            cancellationToken));

    [HttpPut("{clientId}/roles")]
    public async Task<ActionResult<ServiceAccountSummary>> SetRoles(
        string clientId,
        [FromBody] SetServiceAccountRolesCommand command,
        CancellationToken cancellationToken) =>
        Ok(await accounts.SetRolesAsync(
            clientId,
            command,
            RequestContext(),
            cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
