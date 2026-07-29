using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Branding;

/// <summary>
/// Provides the active branding theme for the UI, backed by a database
/// table and cached in memory. The cache is invalidated when the management
/// API updates a theme.
/// </summary>
public interface IBrandingThemeProvider
{
    /// <summary>
    /// Returns the active branding theme, or null if none is configured
    /// (the UI then falls back to hardcoded defaults).
    /// </summary>
    Task<BrandingTheme?> GetActiveAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates the in-memory cache so the next <see cref="GetActiveAsync"/>
    /// call re-reads from the database. Called by the management API after
    /// any create/update/activate/delete operation.
    /// </summary>
    void Invalidate();
}
