using System.ComponentModel.DataAnnotations;

namespace Sufficit.Identity.UI.ViewModels;

/// <summary>Login form input.</summary>
public sealed class LoginViewModel
{
    [Required(ErrorMessage = "Informe o e-mail ou usuário.")]
    [Display(Name = "E-mail ou usuário")]
    public string UserName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Informe a senha.")]
    [DataType(DataType.Password)]
    [Display(Name = "Senha")]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Manter conectado")]
    public bool RememberMe { get; set; }

    /// <summary>The original /connect/authorize URL to return to after sign-in.</summary>
    public string? ReturnUrl { get; set; }
}
