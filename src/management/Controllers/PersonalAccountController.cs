using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
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
}
