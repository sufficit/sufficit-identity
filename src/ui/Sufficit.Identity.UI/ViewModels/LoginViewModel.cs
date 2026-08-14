using System.ComponentModel.DataAnnotations;
using Sufficit.Identity.UI.Resources;

namespace Sufficit.Identity.UI.ViewModels;

/// <summary>Login form input.</summary>
public sealed class LoginViewModel
{
    [Required(
        ErrorMessageResourceType = typeof(ValidationMessages),
        ErrorMessageResourceName = nameof(ValidationMessages.LoginIdentifierRequired))]
    [Display(
        ResourceType = typeof(ValidationMessages),
        Name = nameof(ValidationMessages.LoginIdentifier))]
    public string UserName { get; set; } = string.Empty;

    [Required(
        ErrorMessageResourceType = typeof(ValidationMessages),
        ErrorMessageResourceName = nameof(ValidationMessages.LoginPasswordRequired))]
    [DataType(DataType.Password)]
    [Display(
        ResourceType = typeof(ValidationMessages),
        Name = nameof(ValidationMessages.LoginPassword))]
    public string Password { get; set; } = string.Empty;

    [Display(
        ResourceType = typeof(ValidationMessages),
        Name = nameof(ValidationMessages.LoginRememberMe))]
    public bool RememberMe { get; set; }

    /// <summary>The original /connect/authorize URL to return to after sign-in.</summary>
    public string? ReturnUrl { get; set; }
}
