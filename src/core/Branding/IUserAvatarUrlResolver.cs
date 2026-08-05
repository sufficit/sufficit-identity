using Sufficit.Identity.Application.Branding;

namespace Sufficit.Identity.Core.Branding;

/// <summary>
/// Resolves the active theme's avatar URL template for an opaque user subject.
/// </summary>
public sealed class UserAvatarUrlResolver(
    IBrandingThemeProvider branding) : IUserAvatarUrlResolver
{
    private const string UserIdPlaceholder = "{userid}";
    private const int MaximumUserIdLength = 256;

    public async Task<string?> ResolveAsync(
        string? userId,
        CancellationToken cancellationToken = default)
    {
        var normalizedUserId = userId?.Trim();
        if (string.IsNullOrWhiteSpace(normalizedUserId)
            || normalizedUserId.Length > MaximumUserIdLength)
        {
            return null;
        }

        var theme = await branding.GetActiveAsync(cancellationToken);
        var template = theme?.AvatarUrlTemplate?.Trim();
        if (string.IsNullOrWhiteSpace(template))
        {
            return null;
        }

        return template.Replace(
            UserIdPlaceholder,
            Uri.EscapeDataString(normalizedUserId),
            StringComparison.Ordinal);
    }
}
