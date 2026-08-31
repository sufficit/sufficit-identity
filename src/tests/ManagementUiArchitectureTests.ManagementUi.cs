using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    [Fact]
    public void Management_navigation_does_not_invent_api_status_labels()
    {
        var navigation = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Layout",
            "NavMenu.razor"));

        Assert.DoesNotContain(
            "nav-item__meta",
            navigation,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            ">API<",
            navigation,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Runtime_surfaces_project_the_canonical_overview_contract()
    {
        var uiRoot = ResolveManagementUiSource();
        var pages = Path.Combine(uiRoot, "Components", "Pages");
        var layout = File.ReadAllText(Path.Combine(
            uiRoot,
            "Components",
            "Layout",
            "MainLayout.razor"));
        var navigation = File.ReadAllText(Path.Combine(
            uiRoot,
            "Components",
            "Layout",
            "NavMenu.razor"));
        var home = File.ReadAllText(Path.Combine(pages, "Home.razor"));
        var settings = File.ReadAllText(Path.Combine(pages, "Settings.razor"));
        var combined = layout + navigation + home + settings;

        Assert.Contains(
            "ManagementOverviewDataSource",
            layout,
            StringComparison.Ordinal);
        Assert.Contains(
            "ManagementModulePresentations",
            navigation,
            StringComparison.Ordinal);
        Assert.Contains(
            "CascadingParameter(Name = \"ManagementOverview\")",
            home,
            StringComparison.Ordinal);
        Assert.Contains(
            "CascadingParameter(Name = \"ManagementOverview\")",
            settings,
            StringComparison.Ordinal);
        Assert.DoesNotContain("IOptions<", home + settings, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IWebHostEnvironment",
            layout,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Prontidão dos módulos",
            combined,
            StringComparison.Ordinal);
        Assert.DoesNotContain("5 de 5", combined, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Listagem incorporada",
            combined,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Client_credentials_have_a_conditional_one_time_rotation_workflow()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var uiRoot = ResolveManagementUiSource();
        var editor = File.ReadAllText(Path.Combine(
            uiRoot,
            "Components",
            "Pages",
            "ClientEdit.razor"));
        var detail = File.ReadAllText(Path.Combine(
            uiRoot,
            "Components",
            "Pages",
            "ClientDetail.razor"));
        var dataSource = File.ReadAllText(Path.Combine(
            uiRoot,
            "Clients",
            "ManagementClientDataSource.cs"));
        var controller = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "management",
            "Controllers",
            "ClientsController.cs"));
        var styles = File.ReadAllText(Path.Combine(
            uiRoot,
            "wwwroot",
            "app.css"));

        Assert.Contains("new(\"Credenciais\", \"lock\")", editor,
            StringComparison.Ordinal);
        Assert.Contains("type=\"password\"", editor, StringComparison.Ordinal);
        Assert.Contains("credentialClientIdConfirmation", editor,
            StringComparison.Ordinal);
        Assert.Contains("navigator.clipboard.writeText", editor,
            StringComparison.Ordinal);
        Assert.Contains("RotateClientSecretAsync", dataSource,
            StringComparison.Ordinal);
        Assert.Contains("CreateClientCredentialAsync", dataSource,
            StringComparison.Ordinal);
        Assert.Contains("RevokeClientCredentialAsync", dataSource,
            StringComparison.Ordinal);
        Assert.Contains("OneTimeSecret", editor, StringComparison.Ordinal);
        Assert.Contains("private_key_jwt", editor, StringComparison.Ordinal);
        Assert.Contains("self_signed_tls_client_auth", editor,
            StringComparison.Ordinal);
        Assert.Contains("tls_client_auth", editor, StringComparison.Ordinal);
        Assert.Contains("MtlsRuntimeEnabled", editor, StringComparison.Ordinal);
        Assert.Contains("RegisterTlsCertificateAsync", dataSource,
            StringComparison.Ordinal);
        Assert.Contains("RevokeTlsCertificateAsync", dataSource,
            StringComparison.Ordinal);
        Assert.Contains("client-credential-list", editor, StringComparison.Ordinal);
        Assert.Contains("UsesClientCredentials", detail, StringComparison.Ordinal);
        Assert.Contains("HasClientSecret", detail, StringComparison.Ordinal);
        Assert.Contains("{clientId}/secret/rotate", controller,
            StringComparison.Ordinal);
        Assert.Contains("{clientId}/credentials", controller,
            StringComparison.Ordinal);
        Assert.Contains("{clientId}/certificates", controller,
            StringComparison.Ordinal);
        Assert.Contains("{keyId}/revoke", controller,
            StringComparison.Ordinal);
        Assert.Contains("{credentialId:guid}/revoke", controller,
            StringComparison.Ordinal);
        Assert.Contains("client-credential-editor", styles,
            StringComparison.Ordinal);
        Assert.DoesNotContain("localStorage", editor, StringComparison.Ordinal);
        Assert.DoesNotContain("sessionStorage", editor, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_edit_overview_uses_shared_vw_fields_and_form_grid()
    {
        var managementUi = ResolveManagementUiSource();
        var editor = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "ClientEdit.razor"));
        var styles = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "app.css"));

        Assert.Contains(
            "<SUIFormGrid Class=\"client-edit-form-grid\"",
            editor,
            StringComparison.Ordinal);
        Assert.Contains("<SUITextField T=\"string\"", editor,
            StringComparison.Ordinal);
        Assert.Contains("<SUISelect T=\"string\"", editor,
            StringComparison.Ordinal);
        Assert.Contains("data-sui-align-field", editor,
            StringComparison.Ordinal);
        Assert.DoesNotContain("<select id=\"edit-consent\"", editor,
            StringComparison.Ordinal);
        Assert.Contains(".client-edit-form-grid--consent", styles,
            StringComparison.Ordinal);
        Assert.Contains(".client-edit-par-choice", styles,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Branding_preview_uses_the_configured_background_and_safe_live_draft_values()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var page = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "ui",
            "Sufficit.Identity.UI.Management",
            "Components",
            "Pages",
            "Branding.razor"));
        var styles = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "ui",
            "Sufficit.Identity.UI.Management",
            "wwwroot",
            "app.css"));

        Assert.Contains("@bind-Value:event=\"oninput\"", page, StringComparison.Ordinal);
        Assert.Contains("SafePreviewImageUrl", page, StringComparison.Ordinal);
        Assert.Contains("--preview-background-image", page, StringComparison.Ordinal);
        Assert.Contains("var(--preview-background-image, none)", styles, StringComparison.Ordinal);
        Assert.Contains("Fundo personalizado", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Database_dashboard_uses_the_runtime_event_stream_instead_of_polling()
    {
        var page = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages",
            "Database.razor"));

        Assert.Contains(".WatchAsync(cancellationToken)", page, StringComparison.Ordinal);
        Assert.Contains("Eventos em tempo real", page, StringComparison.Ordinal);
        Assert.DoesNotContain("PeriodicTimer", page, StringComparison.Ordinal);
        Assert.DoesNotContain("FromSeconds(2)", page, StringComparison.Ordinal);
        Assert.DoesNotContain("a cada 2 segundos", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_configurator_is_resumable_protected_and_uses_shared_cases_of_use()
    {
        var repository = ResolveIdentityRepository();
        var managementUi = ResolveManagementUiSource();
        var wizard = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "ClientDraft.razor"));
        var list = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Clients.razor"));
        var dataSource = File.ReadAllText(Path.Combine(
            managementUi,
            "Clients",
            "ManagementClientDataSource.cs"));
        var controller = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "management",
            "Controllers",
            "ClientDraftsController.cs"));

        Assert.Contains("/clients/drafts/{Id:guid}/{Step}", wizard, StringComparison.Ordinal);
        Assert.Contains("Task.Delay(650", wizard, StringComparison.Ordinal);
        Assert.Contains("SaveClientDraftAsync", wizard, StringComparison.Ordinal);
        Assert.Contains("CompleteClientDraftAsync", wizard, StringComparison.Ordinal);
        Assert.Contains("OneTimeSecret", wizard, StringComparison.Ordinal);
        Assert.DoesNotContain("OneTimeSecret)}", wizard, StringComparison.Ordinal);
        Assert.Contains("SupplyParameterFromQuery(Name = \"q\")", list, StringComparison.Ordinal);
        Assert.Contains("SupplyParameterFromQuery(Name = \"type\")", list, StringComparison.Ordinal);
        Assert.Contains("GetClientDraftsAsync", list, StringComparison.Ordinal);
        Assert.Contains("IClientConfigurationDraftService", dataSource, StringComparison.Ordinal);
        Assert.Contains("IClientConfigurationDraftService", controller, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_configurator_styles_are_mobile_first_and_touch_friendly()
    {
        var stylesheet = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "wwwroot",
            "app.css"));

        Assert.Contains(".wizard-shell", stylesheet, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(0, 1fr);", stylesheet, StringComparison.Ordinal);
        Assert.Contains("@media (min-width: 768px)", stylesheet, StringComparison.Ordinal);
        Assert.Contains("@media (min-width: 1100px)", stylesheet, StringComparison.Ordinal);
        Assert.Contains("min-height: 44px", stylesheet, StringComparison.Ordinal);
        Assert.Contains("env(safe-area-inset-bottom)", stylesheet, StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", stylesheet, StringComparison.Ordinal);
    }

    [Fact]
    public void Management_home_sui_badges_preserve_the_mobile_grid()
    {
        var managementUi = ResolveManagementUiSource();
        var home = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Home.razor"));
        var stylesheet = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "app.css"));

        Assert.Contains("<SUIStatusBadge", home, StringComparison.Ordinal);
        Assert.Contains(
            ".capability-row .status-badge,\n    .capability-row .sui-status-badge {\n        display: none;",
            stylesheet,
            StringComparison.Ordinal);
        Assert.Contains(
            ".contract-strip > .status-badge,\n    .contract-strip > .sui-status-badge {\n        grid-column: 2;",
            stylesheet,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Authorization_filter_controls_share_a_baseline_and_consistent_select_inset()
    {
        var stylesheet = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "wwwroot",
            "app.css"));

        Assert.Contains(
            ".user-search {\n    display: flex;\n    /* Align the actual controls, not the select's label, to one baseline. */\n    align-items: flex-end;",
            stylesheet,
            StringComparison.Ordinal);
        Assert.Contains(".select-field .sui-select__trigger {", stylesheet, StringComparison.Ordinal);
        Assert.Contains("padding-inline: 12px;", stylesheet, StringComparison.Ordinal);
        Assert.Contains("min-width: 190px;", stylesheet, StringComparison.Ordinal);

        var page = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages",
            "Authorizations.razor"));
        Assert.Contains("authorization-state-filter", page, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Estado\"", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Service_account_form_uses_shared_sui_controls_and_page_vocabulary()
    {
        // A primeira versão desta tela escreveu inputs crus com classes
        // inventadas (field/input/card/actions) que não existem na folha de
        // estilo — o formulário saiu visualmente quebrado em produção. O que
        // impede a repetição não é lembrar da convenção, é falhar quando ela
        // não é seguida.
        var managementUi = ResolveManagementUiSource();
        var page = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "ServiceAccounts.razor"));
        var stylesheet = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "app.css"));

        Assert.Contains("<SUITextField T=\"string\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUILoadingButton", page, StringComparison.Ordinal);
        Assert.Contains("<SUIAlert", page, StringComparison.Ordinal);
        Assert.Contains("data-sui-align-row", page, StringComparison.Ordinal);

        // Nenhum botão cru: a tela inteira usa os componentes compartilhados.
        Assert.DoesNotContain("class=\"button ", page, StringComparison.Ordinal);

        // Classes que a página usa têm de existir na folha de estilo. Sem esta
        // asserção, um nome inventado passa despercebido até alguém abrir a
        // tela.
        foreach (var required in new[]
        {
            ".sa-create",
            ".sa-create__fields",
            ".sa-create__roles",
            ".sa-create__actions",
            ".sa-role-picker",
            ".service-account-secret",
            ".sa-footnote",
        })
        {
            Assert.Contains(required, stylesheet, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Operator_token_form_uses_shared_sui_controls_and_aligned_fields()
    {
        var managementUi = ResolveManagementUiSource();
        var page = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "OperatorTokens.razor"));
        var stylesheet = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "app.css"));

        Assert.Contains("data-sui-align-row", page, StringComparison.Ordinal);
        Assert.Contains("<SUITextField T=\"string\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUISelect T=\"int\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUISelectItem", page, StringComparison.Ordinal);
        Assert.Contains("<SUILoadingButton", page, StringComparison.Ordinal);
        Assert.Contains("<SUIButton", page, StringComparison.Ordinal);
        Assert.Contains("<SUIAlert", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<select class=\"form-control\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"button ", page, StringComparison.Ordinal);
        Assert.Contains("class=\"operator-token-issue-summary\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain(".operator-token-issue-actions span", stylesheet, StringComparison.Ordinal);
        Assert.Contains(".operator-token-issue-summary span {", stylesheet, StringComparison.Ordinal);
        Assert.Contains(
            ".operator-token-fields > .sui-field {",
            stylesheet,
            StringComparison.Ordinal);
        Assert.Contains("align-self: start;", stylesheet, StringComparison.Ordinal);
        Assert.Contains("min-width: 0;", stylesheet, StringComparison.Ordinal);
    }

    [Fact]
    public void Management_surface_pins_its_sui_theme_independently_of_module_registration_order()
    {
        var managementUi = ResolveManagementUiSource();
        var app = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "App.razor"));
        var theme = File.ReadAllText(Path.Combine(
            managementUi,
            "Configuration",
            "IdentitySuiTheme.cs"));

        Assert.Contains("<SUIThemeProvider Theme=\"@ManagementTheme\">", app, StringComparison.Ordinal);
        Assert.Contains("IdentitySUITheme ManagementTheme", app, StringComparison.Ordinal);
        Assert.Contains("Primary = \"#cc0000\"", theme, StringComparison.Ordinal);
        Assert.Contains("PrimaryContrast = \"#ffffff\"", theme, StringComparison.Ordinal);
    }

    [Fact]
    public void Metrics_page_uses_shared_sui_controls_for_filters_and_configuration()
    {
        var managementUi = ResolveManagementUiSource();
        var page = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Metrics.razor"));

        Assert.Contains("<SUISelect T=\"int\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUISelect T=\"string\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUITextField T=\"string\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUINumericField T=\"int\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUISwitch", page, StringComparison.Ordinal);
        Assert.Contains("<SUIButton", page, StringComparison.Ordinal);
        Assert.Contains("<SUIAlert", page, StringComparison.Ordinal);
        Assert.Contains("data-sui-align-row", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<select", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<input", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<InputSelect", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<InputText", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<InputNumber", page, StringComparison.Ordinal);
        Assert.DoesNotContain("<InputCheckbox", page, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"button ", page, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"form-control", page, StringComparison.Ordinal);
        Assert.DoesNotContain("switch-control", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Provisioning_page_uses_shared_sui_select_and_action_buttons()
    {
        var managementUi = ResolveManagementUiSource();
        var page = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Provisioning.razor"));
        var stylesheet = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "app.css"));

        Assert.Contains("data-sui-align-row", page, StringComparison.Ordinal);
        Assert.Contains("<SUISelect T=\"int\"", page, StringComparison.Ordinal);
        Assert.Contains("<SUISelectItem", page, StringComparison.Ordinal);
        Assert.Equal(
            3,
            page.Split("<SUILoadingButton", StringSplitOptions.None).Length - 1);
        Assert.Equal(
            2,
            page.Split("<SUIButton", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("<select", page, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("class=\"button ", page, StringComparison.Ordinal);
        Assert.DoesNotContain(".temporary-token-field select", stylesheet, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_list_filters_use_shared_selects_and_responsive_grid()
    {
        var managementUi = ResolveManagementUiSource();
        var page = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Clients.razor"));
        var stylesheet = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "app.css"));

        Assert.Contains("data-toolbar--clients", page, StringComparison.Ordinal);
        Assert.Contains("clients-filters", page, StringComparison.Ordinal);
        Assert.Equal(4, page.Split("<SUISelect T=\"string\" id=\"client-", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("<select id=\"client-", page, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(220px, 1.45fr)", stylesheet, StringComparison.Ordinal);
        Assert.Contains(".clients-filter--search", stylesheet, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: repeat(3, minmax(0, 1fr));", stylesheet, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(0, 1fr);", stylesheet, StringComparison.Ordinal);
    }

    [Fact]
    public void User_directory_filters_use_shared_sui_fields_and_portuguese_dates()
    {
        var managementUi = ResolveManagementUiSource();
        var page = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Users.razor"));
        var stylesheet = File.ReadAllText(Path.Combine(
            managementUi,
            "wwwroot",
            "users.css"));

        Assert.Equal(6, page.Split("<SUISelect T=", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("<select", page, StringComparison.Ordinal);
        Assert.Contains("users-review-filter", page, StringComparison.Ordinal);
        Assert.Contains("users-state-filter", page, StringComparison.Ordinal);
        Assert.Contains("users-email-filter", page, StringComparison.Ordinal);
        Assert.Contains("users-mfa-filter", page, StringComparison.Ordinal);
        Assert.Contains("users-sort-filter", page, StringComparison.Ordinal);
        Assert.Contains("users-analytics-filter", page, StringComparison.Ordinal);
        Assert.Equal(2, page.Split("<SUIDateField", StringSplitOptions.None).Length - 1);
        Assert.Equal(2, page.Split("Culture=\"@PtBr\"", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("InputType=\"date\"", page, StringComparison.Ordinal);
        Assert.Contains("users-field .sui-select__trigger", stylesheet, StringComparison.Ordinal);
        Assert.Contains("padding-inline: 12px;", stylesheet, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 767px)", stylesheet, StringComparison.Ordinal);
    }
}
