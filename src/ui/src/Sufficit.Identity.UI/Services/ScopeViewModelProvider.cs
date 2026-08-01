using OpenIddict.Abstractions;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Builds friendly display models for the scopes requested in an
/// authorization/consent flow. Translates raw scope names into human-readable
/// descriptions (pt-BR) and groups them by identity vs API scope.
/// </summary>
public sealed class ScopeViewModelProvider
{
    /// <summary>Static display info for standard OIDC scopes.</summary>
    private static readonly Dictionary<string, (string DisplayName, string Description)> StandardScopes = new()
    {
        [OpenIddictConstants.Scopes.OpenId]        = ("Seu identificador", "Acessa seu identificador único (sub)."),
        [OpenIddictConstants.Scopes.Profile]       = ("Perfil",             "Acessa seu nome, nome de usuário e foto."),
        [OpenIddictConstants.Scopes.Email]         = ("E-mail",             "Acessa seu endereço de e-mail."),
        [OpenIddictConstants.Scopes.Roles]         = ("Funções",            "Acessa as suas funções (roles)."),
        [OpenIddictConstants.Scopes.Address]       = ("Endereço",           "Acessa seu endereço postal."),
        [OpenIddictConstants.Scopes.Phone]         = ("Telefone",           "Acessa seu número de telefone."),
        [OpenIddictConstants.Scopes.OfflineAccess] = ("Acesso offline",     "Permite manter acesso quando você estiver offline (refresh token)."),
    };

    /// <summary>Sufficit-specific scopes (from inventory-baseline).</summary>
    private static readonly Dictionary<string, (string DisplayName, string Description)> SufficitScopes = new()
    {
        ["directives"]                    = ("Diretivas de acesso",     "Acessa as suas diretivas de acesso no Sufficit."),
        ["policies"]                      = ("Policies",                "Acessa as suas policies (diretivas e roles combinados)."),
        ["skoruba_identity_admin_api"]    = ("Admin Identity API",      "Permite administrar usuários/clients/scopes (sensível)."),
        ["sufficit_ai_openai_bridge"]     = ("Bridge de IA",            "Permite usar o bridge de IA do Sufficit."),
    };

    public IReadOnlyList<ScopeViewModel> Build(IEnumerable<string> scopes)
    {
        var list = new List<ScopeViewModel>();
        foreach (var scope in scopes.Order())
        {
            var (displayName, description) = Resolve(scope);
            list.Add(new ScopeViewModel(scope, displayName, description));
        }
        return list;
    }

    private static (string DisplayName, string Description) Resolve(string scope)
    {
        if (StandardScopes.TryGetValue(scope, out var s)) return s;
        if (SufficitScopes.TryGetValue(scope, out var c)) return c;
        return (scope, $"Permite acessar o recurso '{scope}'.");
    }
}

/// <summary>Display model for a single scope in the consent screen.</summary>
public sealed record ScopeViewModel(string Name, string DisplayName, string Description);
