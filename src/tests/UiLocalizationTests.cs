using System.Globalization;
using System.Resources;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sufficit.Identity.UI.Resources;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Architecture tests for the public UI localization contract.
/// </summary>
/// <remarks>
/// These tests catch regressions when a page, component, view model, validation
/// message, action label, or feedback message bypasses the shared resources.
/// The Management UI remains a separate localization boundary.
/// </remarks>
public sealed class UiLocalizationTests
{
    [Theory]
    [InlineData("pt-BR", "Entrar")]
    [InlineData("en-US", "Sign in")]
    public void Shared_resource_marker_resolves_embedded_login_translations(
        string cultureName,
        string expected)
    {
        var resources = new ResourceManager(typeof(SharedResource));
        var translated = resources.GetString(
            "Login.Submit",
            CultureInfo.GetCultureInfo(cultureName));

        Assert.Equal(expected, translated);
    }

    [Theory]
    [InlineData("pt-BR", "ManagePasskeys.Rename", "Renomear")]
    [InlineData("pt-BR", "ManagePasskeys.Remove", "Remover")]
    [InlineData("en-US", "ManagePasskeys.Rename", "Rename")]
    [InlineData("en-US", "ManagePasskeys.Remove", "Remove")]
    public void Passkey_actions_resolve_in_the_selected_culture(
        string cultureName,
        string resourceKey,
        string expected)
    {
        var resources = new ResourceManager(typeof(SharedResource));
        var translated = resources.GetString(
            resourceKey,
            CultureInfo.GetCultureInfo(cultureName));

        Assert.Equal(expected, translated);
    }

    [Theory]
    [InlineData("pt-BR", "ExternalLogins.Remove", "Remover")]
    [InlineData("en-US", "ExternalLogins.Remove", "Remove")]
    [InlineData("pt-BR", "ChangePassword.Submit", "Alterar")]
    [InlineData("en-US", "ChangePassword.Submit", "Change")]
    public void Public_ui_actions_resolve_in_the_selected_culture(
        string cultureName,
        string resourceKey,
        string expected)
    {
        var resources = new ResourceManager(typeof(SharedResource));
        var translated = resources.GetString(
            resourceKey,
            CultureInfo.GetCultureInfo(cultureName));

        Assert.Equal(expected, translated);
    }

    [Theory]
    [InlineData("pt-BR", "Meu Vault")]
    [InlineData("en-US", "My Vault")]
    public void Vault_header_link_resolves_in_the_selected_culture(
        string cultureName,
        string expected)
    {
        var resources = new ResourceManager(typeof(SharedResource));
        var translated = resources.GetString(
            "Layout.MyVault",
            CultureInfo.GetCultureInfo(cultureName));

        Assert.Equal(expected, translated);
    }

    [Fact]
    public void Shared_resources_have_matching_portuguese_and_english_keys()
    {
        var resources = Path.Combine(
            FindUiRoot(),
            "Sufficit.Identity.UI",
            "Resources");
        var portuguese = ResourceKeys(Path.Combine(resources, "SharedResource.resx"));
        var english = ResourceKeys(Path.Combine(resources, "SharedResource.en.resx"));

        Assert.Equal(
            portuguese.OrderBy(key => key, StringComparer.Ordinal),
            english.OrderBy(key => key, StringComparer.Ordinal));
    }

    [Fact]
    public void Two_factor_resources_have_matching_portuguese_and_english_keys()
    {
        var resources = Path.Combine(
            FindUiRoot(),
            "Sufficit.Identity.UI",
            "Resources");
        var portuguese = ResourceKeys(Path.Combine(resources, "SharedResource.resx"));
        var english = ResourceKeys(Path.Combine(resources, "SharedResource.en.resx"));

        var portugueseTwoFactor = portuguese
            .Where(key => key.StartsWith("ManageTwoFactor.", StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);
        var englishTwoFactor = english
            .Where(key => key.StartsWith("ManageTwoFactor.", StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            portugueseTwoFactor.OrderBy(key => key, StringComparer.Ordinal),
            englishTwoFactor.OrderBy(key => key, StringComparer.Ordinal));
    }

    [Fact]
    public void Passkey_resources_have_matching_portuguese_and_english_keys()
    {
        var resources = Path.Combine(
            FindUiRoot(),
            "Sufficit.Identity.UI",
            "Resources");
        var portuguese = ResourceKeys(Path.Combine(resources, "SharedResource.resx"));
        var english = ResourceKeys(Path.Combine(resources, "SharedResource.en.resx"));

        var portuguesePasskeys = portuguese
            .Where(key => key.StartsWith("ManagePasskeys.", StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);
        var englishPasskeys = english
            .Where(key => key.StartsWith("ManagePasskeys.", StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            portuguesePasskeys.OrderBy(key => key, StringComparer.Ordinal),
            englishPasskeys.OrderBy(key => key, StringComparer.Ordinal));
    }

    private static IEnumerable<string> ResourceKeys(string path) =>
        XDocument.Load(path)
            .Root!
            .Elements("data")
            .Select(element => (string?)element.Attribute("name"))
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!);

    private static readonly Regex PtBrLiteral = new(
        "[áàâãéêíóôõúç]"
        + @"|\b(?:entrar|senha|conta|cancelar|confirmar|voltar|continuar|autorizar|"
        + "negar|concluir|esqueceu|redefinir|criar|dispositivo|permissões|sessões|"
        + "sessão|sair|remover|removendo|vincular|vinculado|carregando|alterar|"
        + "aplicações|aplicação|encerrar|emitida|expira|tipo|validade|renovação|"
        + "prazo|provedor|identidade|dados|revogar|revogando|credencial|usuário|"
        + @"obrigatório|inválido)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    [Fact]
    public void No_hardcoded_ptBR_strings_in_public_ui_sources()
    {
        var uiRoot = Path.Combine(FindUiRoot(), "Sufficit.Identity.UI");
        var sourceFiles = Directory
            .EnumerateFiles(uiRoot, "*.*", SearchOption.AllDirectories)
            .Where(path => path.EndsWith(".razor", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Where(path => !path.Contains(
                $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                StringComparison.OrdinalIgnoreCase))
            .Where(path => !path.Contains(
                $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                StringComparison.OrdinalIgnoreCase));

        var violations = new List<string>();

        foreach (var file in sourceFiles)
        {
            var relativePath = Path.GetRelativePath(uiRoot, file);
            var source = StripComments(File.ReadAllText(file))
                // Language names are intentionally shown as autonyms.
                .Replace("\"pt-BR\" => \"Português\"", string.Empty, StringComparison.Ordinal);
            var lines = source.Split('\n');

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (PtBrLiteral.IsMatch(line))
                {
                    violations.Add($"{relativePath}:{i + 1} → {line.Trim()}");
                }
            }
        }

        Assert.True(violations.Count == 0,
            $"Found {violations.Count} hardcoded pt-BR string(s) in public UI sources.\n" +
            "Move user-facing text to SharedResource.resx and SharedResource.en.resx.\n" +
            "Violations:\n" + string.Join("\n", violations));
    }

    private static string StripComments(string source) =>
        Regex.Replace(
            Regex.Replace(
                Regex.Replace(
                    Regex.Replace(source, @"@\*.*?\*@", string.Empty, RegexOptions.Singleline),
                    @"<!--.*?-->",
                    string.Empty,
                    RegexOptions.Singleline),
                @"/\*.*?\*/",
                string.Empty,
                RegexOptions.Singleline),
            @"//.*$",
            string.Empty,
            RegexOptions.Multiline);

    private static string FindUiRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src", "ui")))
        {
            dir = dir.Parent;
        }
        return dir is not null
            ? Path.Combine(dir.FullName, "src", "ui")
            : throw new DirectoryNotFoundException("Could not find src/ui from test base directory.");
    }
}

/// <summary>
/// Tests that backend error and warning messages include a machine-readable
/// error code alongside the human-readable message. This lets the front-end
/// map errors to localized strings without parsing Portuguese text.
/// </summary>
/// <remarks>
/// The convention: every user-visible error returned by the STS controllers
/// or the management services should include a stable, snake_case error code
/// (e.g. "locked_out", "capability_not_granted", "session_expired"). The
/// front-end uses this code to look up the localized string.
/// </remarks>
public sealed class BackendErrorCodeTests
{
    [Fact]
    public void Management_validation_exceptions_carry_a_reason_code()
    {
        var validation = new Sufficit.Identity.Management.Authorization.ManagementValidationException(
            "test_code", "Test message", "field");
        Assert.Equal("test_code", validation.ReasonCode);

        var conflict = new Sufficit.Identity.Management.Authorization.ManagementConflictException(
            "conflict_code", "Conflict message");
        Assert.Equal("conflict_code", conflict.ReasonCode);

        var notFound = new Sufficit.Identity.Management.Authorization.ManagementNotFoundException(
            "not_found_code", "Not found message");
        Assert.Equal("not_found_code", notFound.ReasonCode);

        var access = new Sufficit.Identity.Management.Authorization.ManagementAccessException(
            Sufficit.Identity.Management.Authorization.ManagementAuthorizationDecision.Denied("denied_code"));
        Assert.Equal("denied_code", access.Decision.ReasonCode);
    }

    [Fact]
    public void Management_authorization_decisions_carry_reason_codes()
    {
        var denied = Sufficit.Identity.Management.Authorization.ManagementAuthorizationDecision
            .Denied("capability_not_granted");
        Assert.Equal("capability_not_granted", denied.ReasonCode);

        var stepUp = Sufficit.Identity.Management.Authorization.ManagementAuthorizationDecision
            .StepUpRequired("mfa_required");
        Assert.Equal("mfa_required", stepUp.ReasonCode);

        var allowed = Sufficit.Identity.Management.Authorization.ManagementAuthorizationDecision
            .Allowed();
        Assert.Equal("allowed", allowed.ReasonCode);
    }
}
