using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Audit;
using BrandingThemeEntity = Sufficit.Identity.Core.Entities.BrandingTheme;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Branding;

internal sealed class BrandingManagementService(
    AppDbContext database,
    IBrandingThemeProvider activeThemeProvider,
    IManagementAuthorizationEvaluator authorization,
    ILogger<BrandingManagementService> logger) : IBrandingManagementService
{
    public async Task<IReadOnlyList<ManagementBrandingTheme>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(
            context,
            ManagementCapabilities.BrandingRead,
            new ManagementResource(ManagementResourceTypes.BrandingCollection),
            cancellationToken);

        return await database.BrandingThemes
            .AsNoTracking()
            .OrderByDescending(theme => theme.IsActive)
            .ThenByDescending(theme => theme.UpdatedAt)
            .ThenByDescending(theme => theme.Id)
            .Select(theme => ToContract(theme))
            .ToArrayAsync(cancellationToken);
    }

    public async Task<ManagementBrandingTheme?> GetActiveAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(
            context,
            ManagementCapabilities.BrandingRead,
            new ManagementResource(ManagementResourceTypes.BrandingCollection),
            cancellationToken);

        var active = await database.BrandingThemes
            .AsNoTracking()
            .Where(theme => theme.IsActive)
            .OrderByDescending(theme => theme.UpdatedAt)
            .ThenByDescending(theme => theme.Id)
            .FirstOrDefaultAsync(cancellationToken);

        return active is null ? null : ToContract(active);
    }

    public async Task<ManagementBrandingTheme> GetAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(
            context,
            ManagementCapabilities.BrandingRead,
            Resource(id),
            cancellationToken);

        var theme = await database.BrandingThemes
            .AsNoTracking()
            .FirstOrDefaultAsync(theme => theme.Id == id, cancellationToken);

        return theme is null
            ? throw NotFound(id)
            : ToContract(theme);
    }

    public async Task<ManagementBrandingTheme> CreateAsync(
        SaveManagementBrandingThemeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var decision = await DemandAsync(
            context,
            ManagementCapabilities.BrandingManage,
            new ManagementResource(ManagementResourceTypes.BrandingCollection),
            cancellationToken);
        var values = Validate(command);
        var now = DateTime.UtcNow;
        var theme = new BrandingThemeEntity
        {
            Name = values.Name,
            IsActive = false,
            CreatedAt = now,
            UpdatedAt = now
        };
        Apply(theme, values);

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        database.BrandingThemes.Add(theme);
        await database.SaveChangesAsync(cancellationToken);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.BrandingManage,
            Resource(theme.Id),
            decision,
            "succeeded",
            "branding_created"));
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        activeThemeProvider.Invalidate();

        return ToContract(theme);
    }

    public async Task<ManagementBrandingTheme> UpdateAsync(
        int id,
        SaveManagementBrandingThemeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var resource = Resource(id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.BrandingManage,
            resource,
            cancellationToken);
        var values = Validate(command);
        var theme = await database.BrandingThemes
            .FirstOrDefaultAsync(theme => theme.Id == id, cancellationToken);

        if (theme is null)
        {
            await TryWriteAuditAsync(
                context,
                resource,
                decision,
                "not-found",
                "branding_not_found",
                cancellationToken);
            throw NotFound(id);
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        Apply(theme, values);
        theme.UpdatedAt = DateTime.UtcNow;
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.BrandingManage,
            resource,
            decision,
            "succeeded",
            "branding_updated"));
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        activeThemeProvider.Invalidate();

        return ToContract(theme);
    }

    public async Task<ManagementBrandingTheme> ActivateAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = Resource(id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.BrandingManage,
            resource,
            cancellationToken);
        var themes = await database.BrandingThemes
            .OrderBy(theme => theme.Id)
            .ToArrayAsync(cancellationToken);
        var selected = themes.FirstOrDefault(theme => theme.Id == id);

        if (selected is null)
        {
            await TryWriteAuditAsync(
                context,
                resource,
                decision,
                "not-found",
                "branding_not_found",
                cancellationToken);
            throw NotFound(id);
        }

        var now = DateTime.UtcNow;
        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        foreach (var theme in themes)
        {
            var shouldBeActive = theme.Id == id;
            if (theme.IsActive != shouldBeActive)
            {
                theme.IsActive = shouldBeActive;
                theme.UpdatedAt = now;
            }
        }

        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.BrandingManage,
            resource,
            decision,
            "succeeded",
            "branding_activated"));
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        activeThemeProvider.Invalidate();

        return ToContract(selected);
    }

    public async Task DeleteAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        var resource = Resource(id);
        var decision = await DemandAsync(
            context,
            ManagementCapabilities.BrandingManage,
            resource,
            cancellationToken);
        var theme = await database.BrandingThemes
            .FirstOrDefaultAsync(theme => theme.Id == id, cancellationToken);

        if (theme is null)
        {
            await TryWriteAuditAsync(
                context,
                resource,
                decision,
                "not-found",
                "branding_not_found",
                cancellationToken);
            throw NotFound(id);
        }

        if (theme.IsActive)
        {
            await TryWriteAuditAsync(
                context,
                resource,
                decision,
                "conflict",
                "branding_active_cannot_be_deleted",
                cancellationToken);
            throw new ManagementConflictException(
                "branding_active_cannot_be_deleted",
                "The active branding theme cannot be deleted. Activate another theme first.");
        }

        await using var transaction = await database.Database
            .BeginTransactionAsync(cancellationToken);
        database.BrandingThemes.Remove(theme);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context,
            ManagementCapabilities.BrandingManage,
            resource,
            decision,
            "succeeded",
            "branding_deleted"));
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        activeThemeProvider.Invalidate();
    }

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            resource,
            cancellationToken);

        if (decision.IsAllowed)
        {
            return decision;
        }

        await TryWriteAuditAsync(
            context,
            resource,
            decision,
            "denied",
            decision.ReasonCode,
            cancellationToken,
            capability);
        throw new ManagementAccessException(decision);
    }

    private async Task TryWriteAuditAsync(
        ManagementRequestContext context,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string? reasonCode,
        CancellationToken cancellationToken,
        string capability = ManagementCapabilities.BrandingManage)
    {
        try
        {
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context,
                capability,
                resource,
                decision,
                operationOutcome,
                reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist branding audit event. Capability={Capability} CorrelationId={CorrelationId}",
                capability,
                context.CorrelationId);
        }
    }

    private static ValidatedBrandingTheme Validate(
        SaveManagementBrandingThemeCommand command)
    {
        var name = RequiredText(command.Name, 100, "name");

        return new ValidatedBrandingTheme(
            name,
            AssetUrl(command.LogoUrl, "logoUrl"),
            AssetUrl(command.FaviconUrl, "faviconUrl"),
            AssetUrl(command.HeaderIconUrl, "headerIconUrl"),
            AssetUrl(command.BackgroundImageUrl, "backgroundImageUrl"),
            Color(command.BrandColor, "brandColor"),
            Color(command.BrandHoverColor, "brandHoverColor"),
            Color(command.BrandSoftColor, "brandSoftColor"),
            Color(command.ThemeColor, "themeColor"),
            OptionalText(command.Title, 200, "title"),
            OptionalText(command.BrandName, 100, "brandName"),
            OptionalText(command.BrandSubtitle, 100, "brandSubtitle"),
            AssetUrl(command.AvatarUrlTemplate, "avatarUrlTemplate"));
    }

    private static string RequiredText(string? value, int maxLength, string field)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (normalized.Length is 0)
        {
            throw new ManagementValidationException(
                "branding_name_required",
                "A branding theme name is required.",
                field);
        }

        return Bounded(normalized, maxLength, field);
    }

    private static string? OptionalText(
        string? value,
        int maxLength,
        string field)
    {
        var normalized = NullIfWhiteSpace(value);
        return normalized is null ? null : Bounded(normalized, maxLength, field);
    }

    private static string? AssetUrl(string? value, string field)
    {
        var normalized = NullIfWhiteSpace(value);
        if (normalized is null)
        {
            return null;
        }

        Bounded(normalized, 512, field);

        if (normalized.Contains('\\', StringComparison.Ordinal)
            || normalized.StartsWith("//", StringComparison.Ordinal)
            || normalized.StartsWith('#')
            || normalized.StartsWith('?'))
        {
            throw InvalidAssetUrl(field);
        }

        if (normalized.StartsWith('/'))
        {
            return normalized;
        }

        if (Uri.TryCreate(normalized, UriKind.Absolute, out var absolute))
        {
            if (absolute.Scheme is not ("http" or "https"))
            {
                throw InvalidAssetUrl(field);
            }

            return absolute.AbsoluteUri;
        }

        var path = normalized.TrimStart('/');
        if (path.Length is 0
            || path.Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Any(segment => segment is "." or ".."))
        {
            throw InvalidAssetUrl(field);
        }

        return $"/{path}";
    }

    private static string? Color(string? value, string field)
    {
        var normalized = NullIfWhiteSpace(value);
        if (normalized is null)
        {
            return null;
        }

        if (normalized.Length != 7
            || normalized[0] != '#'
            || normalized.Skip(1).Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ManagementValidationException(
                "branding_color_invalid",
                $"{field} must use the #RRGGBB format.",
                field);
        }

        return normalized.ToLowerInvariant();
    }

    private static string Bounded(string value, int maxLength, string field)
    {
        if (value.Length > maxLength)
        {
            throw new ManagementValidationException(
                "branding_value_too_long",
                $"{field} must contain at most {maxLength} characters.",
                field);
        }

        return value;
    }

    private static ManagementValidationException InvalidAssetUrl(string field) =>
        new(
            "branding_asset_url_invalid",
            $"{field} must be a root-relative path or an absolute HTTP(S) URL.",
            field);

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static void Apply(
        BrandingThemeEntity theme,
        ValidatedBrandingTheme values)
    {
        theme.Name = values.Name;
        theme.LogoUrl = values.LogoUrl;
        theme.FaviconUrl = values.FaviconUrl;
        theme.HeaderIconUrl = values.HeaderIconUrl;
        theme.BackgroundImageUrl = values.BackgroundImageUrl;
        theme.BrandColor = values.BrandColor;
        theme.BrandHoverColor = values.BrandHoverColor;
        theme.BrandSoftColor = values.BrandSoftColor;
        theme.ThemeColor = values.ThemeColor;
        theme.Title = values.Title;
        theme.BrandName = values.BrandName;
        theme.BrandSubtitle = values.BrandSubtitle;
        theme.AvatarUrlTemplate = values.AvatarUrlTemplate;
    }

    private static ManagementBrandingTheme ToContract(BrandingThemeEntity theme) =>
        new(
            theme.Id,
            theme.Name,
            theme.IsActive,
            OutputUrl(theme.LogoUrl),
            OutputUrl(theme.FaviconUrl),
            OutputUrl(theme.HeaderIconUrl),
            OutputUrl(theme.BackgroundImageUrl),
            theme.BrandColor,
            theme.BrandHoverColor,
            theme.BrandSoftColor,
            theme.ThemeColor,
            theme.Title,
            theme.BrandName,
            theme.BrandSubtitle,
            OutputUrl(theme.AvatarUrlTemplate),
            theme.CreatedAt,
            theme.UpdatedAt);

    private static string? OutputUrl(string? value)
    {
        var normalized = NullIfWhiteSpace(value);
        if (normalized is null
            || normalized.StartsWith('/')
            || Uri.TryCreate(normalized, UriKind.Absolute, out _))
        {
            return normalized;
        }

        return $"/{normalized}";
    }

    private static ManagementResource Resource(int id) =>
        new(ManagementResourceTypes.BrandingTheme, id.ToString());

    private static ManagementNotFoundException NotFound(int id) =>
        new(
            "branding_not_found",
            $"Branding theme '{id}' was not found.");

    private sealed record ValidatedBrandingTheme(
        string Name,
        string? LogoUrl,
        string? FaviconUrl,
        string? HeaderIconUrl,
        string? BackgroundImageUrl,
        string? BrandColor,
        string? BrandHoverColor,
        string? BrandSoftColor,
        string? ThemeColor,
        string? Title,
        string? BrandName,
        string? BrandSubtitle,
        string? AvatarUrlTemplate);
}
