namespace Sufficit.Identity.UI.Management.Overview;

/// <summary>
/// Presentation-only copy and routing for module keys discovered from the
/// canonical runtime contract. Availability and authorization never originate
/// from this catalog.
/// </summary>
public sealed record ManagementModulePresentation(
    string Key,
    string Section,
    int SectionOrder,
    int Order,
    string Title,
    string Description,
    string Href,
    string Icon,
    bool ShowInNavigation = true);

public static class ManagementModulePresentations
{
    public static IReadOnlyList<ManagementModulePresentation> All { get; } =
    [
        new(
            "users",
            "Identidade",
            10,
            10,
            "Usuários",
            "Contas, perfil, credenciais e estado de acesso",
            "users",
            "users"),
        new(
            "claims",
            "Identidade",
            10,
            20,
            "Claims de usuários",
            "Atributos personalizados vinculados a cada identidade",
            "users",
            "shield",
            ShowInNavigation: false),
        new(
            "clients",
            "OAuth & OIDC",
            20,
            10,
            "Clientes",
            "Aplicações, redirects e fluxos autorizados",
            "clients",
            "key"),
        new(
            "service-accounts",
            "OAuth & OIDC",
            20,
            15,
            "Contas de sistema",
            "Serviços que se autenticam sozinhos e seus papéis de gestão",
            "service-accounts",
            "server"),
        new(
            "scopes",
            "OAuth & OIDC",
            20,
            20,
            "Scopes",
            "Recursos e permissões delegadas do protocolo",
            "scopes",
            "scope"),
        new(
            "authorizations",
            "OAuth & OIDC",
            20,
            30,
            "Autorizações",
            "Grants e consentimentos persistidos",
            "authorizations",
            "shield"),
        new(
            "branding",
            "Experiência",
            30,
            10,
            "Branding",
            "Temas aplicados às superfícies públicas",
            "branding",
            "palette"),
        new(
            "sessions",
            "Operações",
            40,
            10,
            "Sessões",
            "Credenciais ativas e revogação segura",
            "sessions",
            "clock"),
        new(
            "provisioning",
            "Operações",
            40,
            30,
            "Provisionamento",
            "Manifestos e tokens temporários de provisioning",
            "provisioning",
            "workflow"),
        new(
            "operator-tokens",
            "Operações",
            40,
            20,
            "Tokens temporários",
            "Credenciais curtas e atenuadas para automações administrativas",
            "tokens",
            "key"),
        new(
            "audit",
            "Operações",
            40,
            30,
            "Auditoria",
            "Decisões e mutações administrativas persistidas",
            "audit",
            "audit"),
        new(
            "metrics",
            "Operações",
            40,
            25,
            "Métricas",
            "Uso das aplicações e saúde da coleta",
            "metrics",
            "chart"),
        new(
            "database",
            "Operações",
            40,
            40,
            "Banco de dados",
            "Pool, conexões ativas e recuperação do runtime",
            "database",
            "database")
    ];

    public static ManagementModulePresentation? Find(string key) =>
        All.FirstOrDefault(
            item => string.Equals(
                item.Key,
                key,
                StringComparison.Ordinal));
}
