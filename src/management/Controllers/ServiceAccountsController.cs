using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.ServiceAccounts;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Contas de sistema: clientes que se autenticam sozinhos e recebem
/// capacidades de gestão por papéis declarados no registro
/// (<c>identity:client:roles</c>). Leitura sob <c>identity.clients.read</c>,
/// escrita sob <c>identity.clients.update</c> — é o registro de clientes que
/// esta superfície edita.
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
    /// Cria uma conta de sistema. O segredo volta UMA ÚNICA VEZ no corpo da
    /// resposta — é armazenado apenas como hash e não pode ser reexibido.
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
