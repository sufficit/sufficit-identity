using System.Globalization;
using System.Resources;

namespace Sufficit.Identity.UI.Resources;

/// <summary>
/// Exposes localized validation messages to attributes, whose resource API
/// requires public static properties instead of an injected localizer.
/// </summary>
public static class ValidationMessages
{
    private static readonly ResourceManager Resources = new(typeof(SharedResource));

    public static string UserNameLength => Get("Validation.UserNameLength");
    public static string UserNameRequired => Get("Validation.UserNameRequired");
    public static string EmailRequired => Get("Validation.EmailRequired");
    public static string EmailInvalid => Get("Validation.EmailInvalid");
    public static string PasswordRequired => Get("Validation.PasswordRequired");
    public static string PasswordLength => Get("Validation.PasswordLength");
    public static string ConfirmPasswordRequired => Get("Validation.ConfirmPasswordRequired");
    public static string PasswordMismatch => Get("Validation.PasswordMismatch");
    public static string LoginIdentifierRequired => Get("Validation.LoginIdentifierRequired");
    public static string LoginIdentifier => Get("Validation.LoginIdentifier");
    public static string LoginPasswordRequired => Get("Validation.LoginPasswordRequired");
    public static string LoginPassword => Get("Validation.LoginPassword");
    public static string LoginRememberMe => Get("Validation.LoginRememberMe");

    private static string Get(string key) =>
        Resources.GetString(key, CultureInfo.CurrentUICulture) ?? key;
}
