using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// CRUD for branding themes (UI appearance: logo, favicon, colors, titles).
/// Gated by the "sufficit-identity-management" policy. Only one theme can
/// be active at a time; <see cref="Activate"/> deactivates all others.
/// The UI reads the active theme via <see cref="IBrandingThemeProvider"/>
/// (in-memory cached) and falls back to hardcoded defaults when null.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/branding")]
public sealed class BrandingController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IBrandingThemeProvider _provider;

    public BrandingController(AppDbContext db, IBrandingThemeProvider provider)
    {
        _db = db;
        _provider = provider;
    }

    // --- GET: active theme ---

    /// <summary>Returns the currently active branding theme.</summary>
    [HttpGet("active")]
    public async Task<IActionResult> GetActive(CancellationToken ct)
    {
        var theme = await _provider.GetActiveAsync(ct);
        return theme is null ? NotFound() : Ok(ToDto(theme));
    }

    // --- GET: list all ---

    /// <summary>Lists all branding themes.</summary>
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var themes = await _db.BrandingThemes
            .AsNoTracking()
            .OrderByDescending(t => t.IsActive)
            .ThenByDescending(t => t.UpdatedAt)
            .Select(t => ToDto(t))
            .ToListAsync(ct);
        return Ok(themes);
    }

    // --- GET: by id ---

    /// <summary>Gets a single branding theme by id.</summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id, CancellationToken ct)
    {
        var theme = await _db.BrandingThemes.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct);
        return theme is null ? NotFound() : Ok(ToDto(theme));
    }

    // --- POST: create ---

    /// <summary>Creates a new branding theme.</summary>
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] BrandingRequest req, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var theme = new BrandingTheme
        {
            Name = req.Name,
            IsActive = false,
            LogoUrl = req.LogoUrl,
            FaviconUrl = req.FaviconUrl,
            HeaderIconUrl = req.HeaderIconUrl,
            BackgroundImageUrl = req.BackgroundImageUrl,
            BrandColor = req.BrandColor,
            BrandHoverColor = req.BrandHoverColor,
            BrandSoftColor = req.BrandSoftColor,
            ThemeColor = req.ThemeColor,
            Title = req.Title,
            BrandName = req.BrandName,
            BrandSubtitle = req.BrandSubtitle,
            AvatarUrlTemplate = req.AvatarUrlTemplate,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.BrandingThemes.Add(theme);
        await _db.SaveChangesAsync(ct);

        return CreatedAtAction(nameof(Get), new { id = theme.Id }, ToDto(theme));
    }

    // --- PUT: update ---

    /// <summary>Updates a branding theme.</summary>
    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] BrandingRequest req, CancellationToken ct)
    {
        var theme = await _db.BrandingThemes.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (theme is null) return NotFound();

        theme.Name = req.Name;
        theme.LogoUrl = req.LogoUrl;
        theme.FaviconUrl = req.FaviconUrl;
        theme.HeaderIconUrl = req.HeaderIconUrl;
        theme.BackgroundImageUrl = req.BackgroundImageUrl;
        theme.BrandColor = req.BrandColor;
        theme.BrandHoverColor = req.BrandHoverColor;
        theme.BrandSoftColor = req.BrandSoftColor;
        theme.ThemeColor = req.ThemeColor;
        theme.Title = req.Title;
        theme.BrandName = req.BrandName;
        theme.BrandSubtitle = req.BrandSubtitle;
        theme.AvatarUrlTemplate = req.AvatarUrlTemplate;
        theme.UpdatedAt = DateTime.UtcNow;

        await _db.SaveChangesAsync(ct);
        _provider.Invalidate();

        return Ok(ToDto(theme));
    }

    // --- PUT: activate ---

    /// <summary>
    /// Activates a branding theme (deactivates all others). The UI cache is
    /// invalidated immediately.
    /// </summary>
    [HttpPut("{id:int}/activate")]
    public async Task<IActionResult> Activate(int id, CancellationToken ct)
    {
        var theme = await _db.BrandingThemes.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (theme is null) return NotFound();

        // Deactivate all, then activate the target
        var all = await _db.BrandingThemes.ToListAsync(ct);
        foreach (var t in all)
        {
            t.IsActive = t.Id == id;
            t.UpdatedAt = DateTime.UtcNow;
        }

        await _db.SaveChangesAsync(ct);
        _provider.Invalidate();

        return Ok(ToDto(theme));
    }

    // --- DELETE ---

    /// <summary>Deletes a branding theme. Cannot delete the active theme.</summary>
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        var theme = await _db.BrandingThemes.FirstOrDefaultAsync(t => t.Id == id, ct);
        if (theme is null) return NotFound();

        if (theme.IsActive)
            return BadRequest("Cannot delete the active theme. Activate another theme first.");

        _db.BrandingThemes.Remove(theme);
        await _db.SaveChangesAsync(ct);

        return NoContent();
    }

    private static BrandingDto ToDto(BrandingTheme t) => new()
    {
        Id = t.Id,
        Name = t.Name,
        IsActive = t.IsActive,
        LogoUrl = t.LogoUrl,
        FaviconUrl = t.FaviconUrl,
        HeaderIconUrl = t.HeaderIconUrl,
        BackgroundImageUrl = t.BackgroundImageUrl,
        BrandColor = t.BrandColor,
        BrandHoverColor = t.BrandHoverColor,
        BrandSoftColor = t.BrandSoftColor,
        ThemeColor = t.ThemeColor,
        Title = t.Title,
        BrandName = t.BrandName,
        BrandSubtitle = t.BrandSubtitle,
        AvatarUrlTemplate = t.AvatarUrlTemplate,
        CreatedAt = t.CreatedAt,
        UpdatedAt = t.UpdatedAt,
    };
}

// --- DTOs ---

public sealed class BrandingDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public string? LogoUrl { get; set; }
    public string? FaviconUrl { get; set; }
    public string? HeaderIconUrl { get; set; }
    public string? BackgroundImageUrl { get; set; }
    public string? BrandColor { get; set; }
    public string? BrandHoverColor { get; set; }
    public string? BrandSoftColor { get; set; }
    public string? ThemeColor { get; set; }
    public string? Title { get; set; }
    public string? BrandName { get; set; }
    public string? BrandSubtitle { get; set; }
    public string? AvatarUrlTemplate { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class BrandingRequest
{
    [Required, StringLength(100)]
    public string Name { get; set; } = string.Empty;

    [StringLength(512)] public string? LogoUrl { get; set; }
    [StringLength(512)] public string? FaviconUrl { get; set; }
    [StringLength(512)] public string? HeaderIconUrl { get; set; }
    [StringLength(512)] public string? BackgroundImageUrl { get; set; }
    [StringLength(7)] public string? BrandColor { get; set; }
    [StringLength(7)] public string? BrandHoverColor { get; set; }
    [StringLength(7)] public string? BrandSoftColor { get; set; }
    [StringLength(7)] public string? ThemeColor { get; set; }
    [StringLength(200)] public string? Title { get; set; }
    [StringLength(100)] public string? BrandName { get; set; }
    [StringLength(100)] public string? BrandSubtitle { get; set; }
    [StringLength(512)] public string? AvatarUrlTemplate { get; set; }
}
