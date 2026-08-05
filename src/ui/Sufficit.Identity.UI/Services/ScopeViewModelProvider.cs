namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Builds friendly display models for the scopes requested in an
/// authorization/consent flow. Translates raw scope names into human-readable
/// descriptions (pt-BR) and groups them by identity vs API scope.
/// </summary>
public sealed class ScopeViewModelProvider
{
    /// <summary>Static display info for standard OIDC scopes.</summary>
    private static readonly Dictionary<
        string,
        (string DisplayName, string Description)> StandardScopes = new()
        {
            ["openid"] = (
            "Seu identificador",
            "Acessa seu identificador único (sub)."),
            ["profile"] = (
            "Perfil",
            "Acessa seu nome, nome de usuário e foto."),
            ["email"] = (
            "E-mail",
            "Acessa seu endereço de e-mail."),
            ["roles"] = (
            "Funções",
            "Acessa as funções associadas à sua conta."),
            ["address"] = (
            "Endereço",
            "Acessa seu endereço postal."),
            ["phone"] = (
            "Telefone",
            "Acessa seu número de telefone."),
            ["offline_access"] = (
            "Acesso offline",
            "Permite manter acesso quando você estiver offline."),
        };

    public IReadOnlyList<ScopeViewModel> Build(IEnumerable<string> scopes)
    {
        var list = new List<ScopeViewModel>();
        foreach (var scope in scopes.Order(StringComparer.Ordinal))
        {
            var (displayName, description) = Resolve(scope);
            list.Add(new ScopeViewModel(scope, displayName, description));
        }
        return list;
    }

    private static (string DisplayName, string Description) Resolve(string scope)
    {
        if (StandardScopes.TryGetValue(scope, out var standard))
            return standard;
        return (scope, $"Permite acessar o recurso '{scope}'.");
    }
}

/// <summary>Display model for a single scope in the consent screen.</summary>
public sealed record ScopeViewModel(string Name, string DisplayName, string Description);
