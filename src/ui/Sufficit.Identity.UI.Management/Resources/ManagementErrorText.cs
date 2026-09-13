using Microsoft.Extensions.Localization;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.UI.Management.Resources;

/// <summary>
/// Presents management service errors in the operator's culture.
/// </summary>
/// <remarks>
/// Management services report English messages with a stable reason code.
/// The UI looks the code up as <c>Error.{reasonCode}</c> in
/// <see cref="ManagementResource"/> and falls back to the service message when
/// no translation exists, so a new or parameterized message is still shown.
/// </remarks>
public static class ManagementErrorText
{
    public static string For(
        IStringLocalizer<ManagementResource> localizer,
        string? reasonCode,
        string fallback)
    {
        if (string.IsNullOrWhiteSpace(reasonCode))
        {
            return fallback;
        }

        var text = localizer[$"Error.{reasonCode}"];
        return text.ResourceNotFound ? fallback : text.Value;
    }

    public static string For(
        IStringLocalizer<ManagementResource> localizer,
        ManagementValidationException exception) =>
        For(localizer, exception.ReasonCode, exception.Message);

    public static string For(
        IStringLocalizer<ManagementResource> localizer,
        ManagementConflictException exception) =>
        For(localizer, exception.ReasonCode, exception.Message);

    public static string For(
        IStringLocalizer<ManagementResource> localizer,
        ManagementNotFoundException exception) =>
        For(localizer, exception.ReasonCode, exception.Message);
}
