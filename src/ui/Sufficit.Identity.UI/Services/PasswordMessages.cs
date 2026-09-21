using Microsoft.Extensions.Localization;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.UI.Resources;

namespace Sufficit.Identity.UI.Services;

public static class PasswordMessages
{
    public static string? ForError(string code, AccountPasswordPolicy policy,
        IStringLocalizer<SharedResource> localizer) => code switch
    {
        "PasswordTooShort" => localizer["PasswordRules.MinimumLength", policy.RequiredLength].Value,
        "PasswordRequiresDigit" => localizer["PasswordRules.Digit"].Value,
        "PasswordRequiresLower" => localizer["PasswordRules.Lowercase"].Value,
        "PasswordRequiresUpper" => localizer["PasswordRules.Uppercase"].Value,
        "PasswordRequiresNonAlphanumeric" => localizer["PasswordRules.Symbol"].Value,
        "PasswordRequiresUniqueChars" => localizer["PasswordRules.Unique", policy.RequiredUniqueChars].Value,
        "PasswordBreached" => localizer["PasswordError.Breached"].Value,
        "PasswordBreachCheckUnavailable" => localizer["PasswordError.CheckUnavailable"].Value,
        "PasswordMismatch" => localizer["PasswordError.CurrentIncorrect"].Value,
        "password-confirmation-mismatch" => localizer["Validation.PasswordMismatch"].Value,
        "password-required" => localizer["PasswordError.Required"].Value,
        "unauthenticated" => localizer["ChangePassword.SessionExpired"].Value,
        "ConcurrencyFailure" => localizer["PasswordError.ConcurrentChange"].Value,
        _ => null,
    };
}
