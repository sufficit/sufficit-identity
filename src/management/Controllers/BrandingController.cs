using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Branding;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for the canonical identity branding management use cases.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/branding")]
public sealed class BrandingController(IBrandingManagementService branding)
    : ControllerBase
{
    /// <summary>Returns the currently active branding theme.</summary>
    [HttpGet("active")]
    public async Task<ActionResult<ManagementBrandingTheme>> GetActive(
        CancellationToken cancellationToken)
    {
        var theme = await branding.GetActiveAsync(
            RequestContext(),
            cancellationToken);
        return theme is null ? NotFound() : Ok(theme);
    }

    /// <summary>Lists all branding themes.</summary>
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementBrandingTheme>>> List(
        CancellationToken cancellationToken) =>
        Ok(await branding.ListAsync(RequestContext(), cancellationToken));

    /// <summary>Gets a branding theme by id.</summary>
    [HttpGet("{id:int}")]
    public async Task<ActionResult<ManagementBrandingTheme>> Get(
        int id,
        CancellationToken cancellationToken) =>
        Ok(await branding.GetAsync(
            id,
            RequestContext(),
            cancellationToken));

    /// <summary>Creates an inactive branding theme.</summary>
    [HttpPost]
    public async Task<ActionResult<ManagementBrandingTheme>> Create(
        [FromBody] BrandingRequest request,
        CancellationToken cancellationToken)
    {
        var result = await branding.CreateAsync(
            request.ToCommand(),
            RequestContext(),
            cancellationToken);
        return CreatedAtAction(nameof(Get), new { id = result.Id }, result);
    }

    /// <summary>Updates a branding theme.</summary>
    [HttpPut("{id:int}")]
    public async Task<ActionResult<ManagementBrandingTheme>> Update(
        int id,
        [FromBody] BrandingRequest request,
        CancellationToken cancellationToken) =>
        Ok(await branding.UpdateAsync(
            id,
            request.ToCommand(),
            RequestContext(),
            cancellationToken));

    /// <summary>Activates a theme and deactivates every other theme.</summary>
    [HttpPut("{id:int}/activate")]
    public async Task<ActionResult<ManagementBrandingTheme>> Activate(
        int id,
        CancellationToken cancellationToken) =>
        Ok(await branding.ActivateAsync(
            id,
            RequestContext(),
            cancellationToken));

    /// <summary>Deletes an inactive branding theme.</summary>
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(
        int id,
        CancellationToken cancellationToken)
    {
        await branding.DeleteAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}

public sealed class BrandingRequest
{
    [Required, StringLength(100)]
    public string Name { get; set; } = string.Empty;

    [StringLength(512)]
    public string? LogoUrl { get; set; }

    [StringLength(512)]
    public string? FaviconUrl { get; set; }

    [StringLength(512)]
    public string? HeaderIconUrl { get; set; }

    [StringLength(512)]
    public string? BackgroundImageUrl { get; set; }

    [StringLength(7), RegularExpression("^#[0-9a-fA-F]{6}$")]
    public string? BrandColor { get; set; }

    [StringLength(7), RegularExpression("^#[0-9a-fA-F]{6}$")]
    public string? BrandHoverColor { get; set; }

    [StringLength(7), RegularExpression("^#[0-9a-fA-F]{6}$")]
    public string? BrandSoftColor { get; set; }

    [StringLength(7), RegularExpression("^#[0-9a-fA-F]{6}$")]
    public string? ThemeColor { get; set; }

    [StringLength(200)]
    public string? Title { get; set; }

    [StringLength(100)]
    public string? BrandName { get; set; }

    [StringLength(100)]
    public string? BrandSubtitle { get; set; }

    [StringLength(512)]
    public string? AvatarUrlTemplate { get; set; }

    internal SaveManagementBrandingThemeCommand ToCommand() =>
        new(
            Name,
            LogoUrl,
            FaviconUrl,
            HeaderIconUrl,
            BackgroundImageUrl,
            BrandColor,
            BrandHoverColor,
            BrandSoftColor,
            ThemeColor,
            Title,
            BrandName,
            BrandSubtitle,
            AvatarUrlTemplate);
}
