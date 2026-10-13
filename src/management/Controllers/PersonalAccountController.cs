using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Mcp;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Read-only first-party adapter for the authenticated user's own profile.
/// The bearer subject is the only accepted identity; callers cannot select or
/// inspect another account.
/// </summary>
[ApiController]
[Authorize(Policy = McpResourceMetadataChallenge.PolicyName)]
[Route("api/account/personal")]
public sealed class PersonalAccountController(
    UserManager<ApplicationUser> users,
    IUserAvatarUrlResolver avatars) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(
        CancellationToken cancellationToken = default)
    {
        var subject = User.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        cancellationToken.ThrowIfCancellationRequested();
        var user = await users.FindByIdAsync(subject);
        if (user is null)
        {
            return NotFound();
        }

        var claims = await users.GetClaimsAsync(user);
        var displayName = claims.LastOrDefault(claim =>
            claim.Type is OpenIddictConstants.Claims.Name or ClaimTypes.Name)?.Value;

        return Ok(new
        {
            id = user.Id,
            userName = user.UserName,
            email = user.Email,
            emailConfirmed = user.EmailConfirmed,
            phoneNumber = user.PhoneNumber,
            phoneNumberConfirmed = user.PhoneNumberConfirmed,
            displayName,
            twoFactorEnabled = user.TwoFactorEnabled,
            createdAtUtc = user.CreatedAtUtc,
            avatarUrl = await avatars.ResolveAsync(user.Id, cancellationToken),
        });
    }

    /// <summary>
    /// Revokes the caller's own delegated device credentials issued for one device
    /// (the <c>executor_id</c> label of the exchange). The owner's Genius calls it when
    /// it retires a cloud executor: a suspended executor cannot revoke its own
    /// credential, which otherwise stays active and counts toward the per-user cap.
    /// </summary>
    [HttpPost("delegated-credentials/revoke")]
    public async Task<IActionResult> RevokeDelegatedCredentials(
        [FromQuery] string? label,
        CancellationToken cancellationToken = default)
    {
        if (!Guid.TryParse(label, out var device) || device == Guid.Empty)
        {
            return BadRequest(new { error = "invalid_label" });
        }

        var subject = User.GetClaim(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrWhiteSpace(subject))
        {
            return Unauthorized();
        }

        if (HttpContext.RequestServices.GetService<IAccountAccessService>() is not { } access)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        // The account service resolves the user through ASP.NET Identity's user-id claim
        // type; a bearer principal carries only `sub`.
        var userIdClaim = HttpContext.RequestServices
            .GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity.UserIdClaimType;
        var owner = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(userIdClaim, subject)], authenticationType: "Bearer"));
        var target = device.ToString("D");
        var revoked = 0;
        foreach (var credential in await access.GetDelegatedCredentialsAsync(owner, cancellationToken))
        {
            if (!string.Equals(credential.Label, target, StringComparison.OrdinalIgnoreCase)) continue;
            if ((await access.RevokeDelegatedCredentialAsync(owner, credential.Id, cancellationToken)).Succeeded)
            {
                revoked++;
            }
        }

        return Ok(new { revoked });
    }
}
