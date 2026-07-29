using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Branding;

/// <summary>
/// Singleton cache for the active branding theme. Reads from
/// <see cref="AppDbContext"/> via <see cref="IServiceScopeFactory"/> (avoids
/// captive-dependency on a scoped DbContext). Cache TTL is 5 minutes; the
/// management API calls <see cref="Invalidate"/> after any mutation, so the
/// effective latency for edits is immediate.
/// </summary>
public sealed class BrandingThemeProvider : IBrandingThemeProvider
{
    private static readonly object CacheKey = new();

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<BrandingThemeProvider> _logger;
    private readonly TimeSpan _ttl;
    private readonly Lock _gate = new();
    private (BrandingTheme? Theme, DateTimeOffset ExpiresAt) _cached;

    public BrandingThemeProvider(
        IServiceScopeFactory scopeFactory,
        ILogger<BrandingThemeProvider> logger,
        TimeProvider? timeProvider = null)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _ttl = TimeSpan.FromMinutes(5);
    }

    public async Task<BrandingTheme?> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        // Fast path: check cache without locking
        var (theme, expiresAt) = _cached;
        if (expiresAt > _timeProvider.GetUtcNow())
        {
            return theme;
        }

        // Cache miss — acquire lock and double-check (prevents thundering herd)
        lock (_gate)
        {
            (theme, expiresAt) = _cached;
            if (expiresAt > _timeProvider.GetUtcNow())
            {
                return theme;
            }
        }

        // Query the database in a fresh scope
        BrandingTheme? result = null;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            // If the table doesn't exist yet (pre-migration), this will throw.
            // We catch and return null so the UI falls back to defaults.
            try
            {
                result = await db.BrandingThemes
                    .AsNoTracking()
                    .Where(theme => theme.IsActive)
                    .OrderByDescending(theme => theme.UpdatedAt)
                    .ThenByDescending(theme => theme.Id)
                    .FirstOrDefaultAsync(cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex,
                    "Failed to read brandingthemes table — falling back to hardcoded defaults. " +
                    "Run the database migration to create the table.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create DI scope for branding theme lookup.");
        }

        // Populate cache (even with null, so we don't hammer the DB on every request)
        lock (_gate)
        {
            _cached = (result, _timeProvider.GetUtcNow() + _ttl);
        }

        return result;
    }

    public void Invalidate()
    {
        lock (_gate)
        {
            _cached = default;
        }
    }
}
