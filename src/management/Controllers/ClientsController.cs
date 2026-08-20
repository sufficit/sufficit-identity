using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for the canonical OAuth/OIDC client management use cases.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/clients")]
public sealed class ClientsController(IClientManagementService clients)
    : ControllerBase
{
    /// <summary>Lists registered clients with bounded server-side paging.</summary>
    [HttpGet]
    public async Task<ActionResult<ManagementClientPage>> List(
        CancellationToken cancellationToken,
        [FromQuery(Name = "q")] string? search,
        [FromQuery] string? type,
        [FromQuery] string? grant,
        [FromQuery] string? scope,
        [FromQuery] string? origin,
        [FromQuery] string? status,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25) =>
        Ok(await clients.SearchAsync(
            new ManagementClientQuery(
                search,
                type,
                grant,
                scope,
                origin,
                status,
                page,
                pageSize),
            RequestContext(),
            cancellationToken));

    /// <summary>Gets a single client by client_id.</summary>
    [HttpGet("{clientId}")]
    public async Task<ActionResult<ManagementClientDetail>> Get(
        string clientId,
        CancellationToken cancellationToken) =>
        Ok(await clients.GetByClientIdAsync(
            clientId,
            RequestContext(),
            cancellationToken));

    /// <summary>Creates a new client using secure application defaults.</summary>
    [HttpPost]
    public async Task<ActionResult<ManagementClientDetail>> Create(
        [FromBody] CreateClientRequest request,
        CancellationToken cancellationToken)
    {
        var result = await clients.CreateAsync(
            new CreateManagementClientCommand(
                request.ClientId,
                request.ClientSecret,
                request.DisplayName,
                request.ConsentType,
                request.RequirePar,
                request.GrantTypes,
                request.Scopes,
                request.RedirectUris,
                request.PostLogoutRedirectUris,
                request.FrontchannelLogoutUri,
                request.FrontchannelLogoutSessionRequired,
                request.BackchannelLogoutUri,
                request.BackchannelLogoutSessionRequired,
                request.JwksUri,
                request.AccessTokenLifetimeMinutes,
                request.IdentityTokenLifetimeMinutes,
                request.RefreshTokenLifetimeDays,
                request.JwksJson),
            RequestContext(),
            cancellationToken);

        return CreatedAtAction(
            nameof(Get),
            new { clientId = result.ClientId },
            result);
    }

    /// <summary>Updates a manually managed client without changing its secret.</summary>
    [HttpPut("{clientId}")]
    public async Task<ActionResult<ManagementClientDetail>> Update(
        string clientId,
        [FromBody] UpdateClientRequest request,
        CancellationToken cancellationToken)
    {
        var result = await clients.UpdateAsync(
            new UpdateManagementClientCommand(
                clientId,
                request.DisplayName,
                request.ConsentType,
                request.RequirePar,
                request.GrantTypes,
                request.Scopes,
                request.RedirectUris,
                request.PostLogoutRedirectUris,
                request.FrontchannelLogoutUri,
                request.FrontchannelLogoutSessionRequired,
                request.BackchannelLogoutUri,
                request.BackchannelLogoutSessionRequired,
                request.ExpectedVersion,
                request.JwksUri,
                request.AccessTokenLifetimeMinutes,
                request.IdentityTokenLifetimeMinutes,
                request.RefreshTokenLifetimeDays,
                request.ClearAccessTokenLifetime,
                request.ClearIdentityTokenLifetime,
                request.ClearRefreshTokenLifetime,
                request.JwksJson),
            RequestContext(),
            cancellationToken);

        return Ok(result);
    }

    /// <summary>
    /// Lists the client's authentication methods and every independently
    /// managed shared credential. Secret values are never returned.
    /// </summary>
    [HttpGet("{clientId}/credentials")]
    public async Task<ActionResult<ManagementClientCredentialsOverview>>
        GetCredentials(
            string clientId,
            CancellationToken cancellationToken) =>
        Ok(await clients.GetCredentialsAsync(
            clientId,
            RequestContext(),
            cancellationToken));

    /// <summary>
    /// Adds a shared credential. The plaintext is returned exactly once in
    /// this response and is never persisted or logged.
    /// </summary>
    [HttpPost("{clientId}/credentials")]
    public async Task<ActionResult<CreateManagementClientCredentialResult>>
        CreateCredential(
            string clientId,
            [FromBody] CreateClientCredentialRequest request,
            CancellationToken cancellationToken)
    {
        var result = await clients.CreateCredentialAsync(
            new CreateManagementClientCredentialCommand(
                clientId,
                request.ExpectedClientVersion,
                request.Label,
                request.Generate,
                request.ClientSecret,
                request.NotBeforeUtc,
                request.ExpiresAtUtc),
            RequestContext(),
            cancellationToken);

        return CreatedAtAction(
            nameof(GetCredentials),
            new { clientId },
            result);
    }

    /// <summary>Immediately revokes an additional shared credential.</summary>
    [HttpPost("{clientId}/credentials/{credentialId:guid}/revoke")]
    public async Task<ActionResult<ManagementClientCredentialsOverview>>
        RevokeCredential(
            string clientId,
            Guid credentialId,
            [FromBody] RevokeClientCredentialRequest request,
            CancellationToken cancellationToken) =>
        Ok(await clients.RevokeCredentialAsync(
            new RevokeManagementClientCredentialCommand(
                clientId,
                credentialId,
                request.ExpectedCredentialVersion,
                request.Reason),
            RequestContext(),
            cancellationToken));

    /// <summary>
    /// Registers public X.509 material for RFC 8705 client authentication.
    /// Private keys are rejected and never persisted.
    /// </summary>
    [HttpPost("{clientId}/certificates")]
    public async Task<ActionResult<ManagementClientCredentialsOverview>>
        RegisterTlsCertificate(
            string clientId,
            [FromBody] RegisterClientTlsCertificateRequest request,
            CancellationToken cancellationToken)
    {
        var result = await clients.RegisterTlsCertificateAsync(
            new RegisterManagementClientTlsCertificateCommand(
                clientId,
                request.ExpectedClientVersion,
                request.KeyId,
                request.AuthenticationMethod,
                request.CertificatePem),
            RequestContext(),
            cancellationToken);

        return CreatedAtAction(
            nameof(GetCredentials),
            new { clientId },
            result);
    }

    /// <summary>
    /// Immediately removes a registered mTLS certificate or subordinate CA.
    /// New authentications using the removed material are rejected.
    /// </summary>
    [HttpPost("{clientId}/certificates/{keyId}/revoke")]
    public async Task<ActionResult<ManagementClientCredentialsOverview>>
        RevokeTlsCertificate(
            string clientId,
            string keyId,
            [FromBody] RevokeClientTlsCertificateRequest request,
            CancellationToken cancellationToken) =>
        Ok(await clients.RevokeTlsCertificateAsync(
            new RevokeManagementClientTlsCertificateCommand(
                clientId,
                request.ExpectedClientVersion,
                keyId),
            RequestContext(),
            cancellationToken));

    /// <summary>
    /// Replaces the shared credential of a manually managed client. The
    /// plaintext value is returned only in this response.
    /// </summary>
    [HttpPost("{clientId}/secret/rotate")]
    public async Task<ActionResult<RotateManagementClientSecretResult>> RotateSecret(
        string clientId,
        [FromBody] RotateClientSecretRequest request,
        CancellationToken cancellationToken)
    {
        var result = await clients.RotateSecretAsync(
            new RotateManagementClientSecretCommand(
                clientId,
                request.ExpectedVersion,
                request.Generate,
                request.ClientSecret),
            RequestContext(),
            cancellationToken);

        return Ok(result);
    }

    /// <summary>Deletes a client.</summary>
    [HttpDelete("{clientId}")]
    public async Task<IActionResult> Delete(
        string clientId,
        CancellationToken cancellationToken)
    {
        await clients.DeleteAsync(
            clientId,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}

public sealed class CreateClientRequest
{
    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? ClientSecret { get; set; }

    public string? DisplayName { get; set; }

    /// <summary>
    /// Optional consent type. When omitted, explicit consent is used.
    /// </summary>
    public string? ConsentType { get; set; }

    /// <summary>
    /// Requires Pushed Authorization Requests (RFC 9126) for this client.
    /// </summary>
    public bool RequirePar { get; set; }

    public List<string> GrantTypes { get; set; } = [];

    public List<string> Scopes { get; set; } = [];

    public List<string> RedirectUris { get; set; } = [];

    public List<string> PostLogoutRedirectUris { get; set; } = [];

    public string? FrontchannelLogoutUri { get; set; }

    public bool FrontchannelLogoutSessionRequired { get; set; }

    public string? BackchannelLogoutUri { get; set; }

    public bool BackchannelLogoutSessionRequired { get; set; }

    public string? JwksUri { get; set; }

    /// <summary>Embedded public JWKS used for private_key_jwt.</summary>
    public string? JwksJson { get; set; }

    /// <summary>Optional per-application access token lifetime in minutes.</summary>
    public int? AccessTokenLifetimeMinutes { get; set; }

    /// <summary>Optional per-application identity token lifetime in minutes.</summary>
    public int? IdentityTokenLifetimeMinutes { get; set; }

    /// <summary>Optional per-application refresh token lifetime in days.</summary>
    public int? RefreshTokenLifetimeDays { get; set; }
}

public sealed class UpdateClientRequest
{
    public string? DisplayName { get; set; }
    public string? ConsentType { get; set; }
    public bool RequirePar { get; set; }
    public List<string> GrantTypes { get; set; } = [];
    public List<string> Scopes { get; set; } = [];
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public string? FrontchannelLogoutUri { get; set; }
    public bool FrontchannelLogoutSessionRequired { get; set; }
    public string? BackchannelLogoutUri { get; set; }
    public bool BackchannelLogoutSessionRequired { get; set; }
    public string? ExpectedVersion { get; set; }
    public string? JwksUri { get; set; }
    public string? JwksJson { get; set; }
    public int? AccessTokenLifetimeMinutes { get; set; }
    public int? IdentityTokenLifetimeMinutes { get; set; }
    public int? RefreshTokenLifetimeDays { get; set; }
    public bool ClearAccessTokenLifetime { get; set; }
    public bool ClearIdentityTokenLifetime { get; set; }
    public bool ClearRefreshTokenLifetime { get; set; }
}

public sealed class RotateClientSecretRequest
{
    public string? ExpectedVersion { get; set; }
    public bool Generate { get; set; } = true;
    public string? ClientSecret { get; set; }
}

public sealed class RegisterClientTlsCertificateRequest
{
    [Required]
    public string ExpectedClientVersion { get; set; } = string.Empty;

    public string? KeyId { get; set; }

    [Required]
    public string AuthenticationMethod { get; set; } =
        OpenIddictConstants.ClientAuthenticationMethods.SelfSignedTlsClientAuth;

    [Required]
    public string CertificatePem { get; set; } = string.Empty;
}

public sealed class RevokeClientTlsCertificateRequest
{
    [Required]
    public string ExpectedClientVersion { get; set; } = string.Empty;
}

public sealed class CreateClientCredentialRequest
{
    public string? ExpectedClientVersion { get; set; }
    public string? Label { get; set; }
    public bool Generate { get; set; } = true;
    public string? ClientSecret { get; set; }
    public DateTimeOffset? NotBeforeUtc { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
}

public sealed class RevokeClientCredentialRequest
{
    public string? ExpectedCredentialVersion { get; set; }
    public string? Reason { get; set; }
}
