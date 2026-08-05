using System.ComponentModel.DataAnnotations;

namespace Sufficit.Identity.UI.ViewModels;

/// <summary>Consent screen input (scope toggles + decision).</summary>
public sealed class ConsentViewModel
{
    public string? ClientId { get; set; }
    public string? ClientName { get; set; }
    public string? ReturnUrl { get; set; }

    /// <summary>Scopes the user accepted (subset of requested scopes).</summary>
    public List<string> AcceptedScopes { get; set; } = new();

    /// <summary>"accept" or "deny" from the form submit button.</summary>
    public string? Decision { get; set; }
}
