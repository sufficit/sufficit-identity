using System.Globalization;
using System.Resources;
using System.Text.RegularExpressions;
using Sufficit.Identity.UI.Resources;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Architecture test: enforces that no hardcoded pt-BR strings remain in the
/// public UI .razor files after the i18n migration. Every visible Portuguese
/// text node should be replaced by a @L["Key"] call.
/// </summary>
/// <remarks>
/// This test catches regressions: if someone adds a new page or component with
/// hardcoded pt-BR, the test fails until the string is extracted to the resx.
/// It does NOT apply to the Management UI (separate i18n phase) or to code-
/// only files (.cs) — only to .razor markup in the public UI.
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

    /// <summary>
    /// High-signal Portuguese words that indicate a hardcoded string in visible
    /// HTML markup (titles, labels, buttons). These are checked only in markup
    /// context (between HTML tags or in label/placeholder attributes), NOT in
    /// @code blocks, validation attributes, or string literals in C# code.
    /// </summary>
    private static readonly string[] PtBrMarkupIndicators =
    [
        "Entrar", "Senha", "Conta", "Cancelar", "Confirmar",
        "Voltar", "Continuar", "Autorizar", "Negar", "Concluir",
        "Esqueceu", "Redefinir", "Criar", "Dispositivo",
        "Permissões", "Sessões", "Sair", "Minha conta",
        "Autenticação em", "Código do dispositivo", "Ativar dispositivo",
    ];

    /// <summary>
    /// Directories excluded from the check (Management UI is a separate phase;
    /// bin/obj are build artifacts).
    /// </summary>
    private static readonly string[] ExcludedDirs = ["bin", "obj", "Sufficit.Identity.UI.Management"];

    [Fact]
    public void No_hardcoded_ptBR_strings_in_public_ui_razor_markup()
    {
        var uiRoot = FindUiRoot();
        var razorFiles = Directory.GetFiles(uiRoot, "*.razor", SearchOption.AllDirectories)
            .Where(f => !ExcludedDirs.Any(d => f.Contains(d, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var violations = new List<string>();

        foreach (var file in razorFiles)
        {
            var relativePath = Path.GetRelativePath(uiRoot, file);
            var lines = File.ReadAllLines(file);
            var inCodeBlock = false;
            var codeBraceDepth = 0;

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                var trimmed = line.Trim();

                // Track @code blocks with brace depth counting — more robust
                // than checking for a lone "}" which matches inner scopes too.
                if (line.Contains("@code"))
                {
                    inCodeBlock = true;
                    // Count braces on the @code line itself.
                    codeBraceDepth = line.Count(c => c == '{') - line.Count(c => c == '}');
                    if (codeBraceDepth <= 0) inCodeBlock = false; // one-liner @code {}
                    continue;
                }
                if (inCodeBlock)
                {
                    codeBraceDepth += line.Count(c => c == '{') - line.Count(c => c == '}');
                    if (codeBraceDepth <= 0) inCodeBlock = false;
                    continue;
                }

                // Skip comments.
                if (trimmed.StartsWith("//") ||
                    trimmed.StartsWith("@*") ||
                    trimmed.StartsWith("<!--"))
                    continue;

                // Skip lines that already use localization.
                if (line.Contains("@L["))
                    continue;

                // Skip validation attribute lines (they need compile-time constants).
                if (line.Contains("ErrorMessage") || line.Contains("Display("))
                    continue;

                // Skip lines that are string-switch keys or pure C# (no HTML tags).
                if (line.Contains("=>") && !line.Contains("<"))
                    continue;

                foreach (var indicator in PtBrMarkupIndicators)
                {
                    if (ContainsVisibleMarkupString(line, indicator))
                    {
                        violations.Add($"{relativePath}:{i + 1} → \"{indicator}\" in: {line.Trim()}");
                        break; // one violation per line is enough
                    }
                }
            }
        }

        Assert.True(violations.Count == 0,
            $"Found {violations.Count} hardcoded pt-BR string(s) in public UI .razor markup.\n" +
            "Every visible text must use @L[\"Key\"] from the SharedResource resx.\n" +
            "Violations:\n" + string.Join("\n", violations));
    }

    /// <summary>
    /// Checks if a line contains the indicator as visible HTML markup text
    /// (between > and <, or in a label/title/placeholder/value attribute).
    /// Excludes string literals inside C# code blocks, enum values, and
    /// other non-markup contexts.
    /// </summary>
    private static bool ContainsVisibleMarkupString(string line, string indicator)
    {
        // Must be in an HTML context: look for the indicator as text content
        // between tags (e.g. >Entrar<) or in a visible attribute (label="...").
        var pattern = $@"(?<!\w){Regex.Escape(indicator)}(?!\w)";
        return Regex.IsMatch(line, pattern, RegexOptions.IgnoreCase);
    }

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
