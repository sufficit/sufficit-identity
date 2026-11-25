using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Localization;
using Sufficit.Blazor.UI.Components;
using Sufficit.Blazor.UI.Services;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.UI.Vault.Components.Pages;

public partial class UserVault
{
    private const string Namespace = "personal";
    private string PersonalSecretHint => $"{L["Vault.UserVault.PersonalSecretHintPrefix"].Value} example/api-key.";
    private PersonalSecretForm form = new();
    private IReadOnlyList<UserVaultSecretMetadata> personalSecrets = [];
    private IReadOnlyList<UserVaultManagedCredentialMetadata> managedCredentials = [];
    private IReadOnlyList<UserVaultSecretMetadata> visibleSecrets = [];
    private UserVaultSecretMetadata? selected;
    private string search = string.Empty;
    private SecretFilter filter;
    private bool showEditor;
    private bool showActions;
    private bool confirmRemoval;
    private bool focusSelected;
    private bool focusEditor;
    private ElementReference editorRegion;
    private ElementReference selectedHeading;
    private bool loading = true;
    private bool saving;
    private string? loadError;

    protected override async Task OnInitializedAsync()
    {
        form.Localizer = L;
        await LoadAsync();
    }

    private async Task LoadAsync()
    {
        loading = true;
        loadError = null;
        var result = await Data.LoadPersonalOverviewAsync();
        if (result.IsSuccess && result.Value is not null)
        {
            personalSecrets = result.Value.PersonalSecrets;
            managedCredentials = result.Value.ManagedCredentials;
        }
        else
        {
            personalSecrets = [];
            managedCredentials = [];
            loadError = result.Error;
        }
        ApplyFilters();
        loading = false;
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (focusEditor)
        {
            focusEditor = false;
            await editorRegion.FocusAsync();
        }
        if (focusSelected)
        {
            focusSelected = false;
            await selectedHeading.FocusAsync();
        }
    }

    private void SetSearch(string? value)
    {
        search = value ?? string.Empty;
        ApplyFilters();
    }

    private void SetFilter(SecretFilter value)
    {
        filter = value;
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        var term = search.Trim();
        visibleSecrets = personalSecrets.Where(item =>
            item.Name.Contains(term, StringComparison.OrdinalIgnoreCase) && MatchesFilter(item.Name)).ToArray();
        var current = visibleSecrets.FirstOrDefault(item => string.Equals(item.Name, selected?.Name, StringComparison.Ordinal));
        if (current is null)
        {
            confirmRemoval = false;
            showActions = false;
        }
        selected = current ?? visibleSecrets.FirstOrDefault();
    }

    private bool MatchesFilter(string name) => filter switch
    {
        SecretFilter.Passwords => KindOf(name) == SecretKind.Password,
        SecretFilter.KeysAndTokens => KindOf(name) is SecretKind.ApiKey or SecretKind.Token,
        _ => true
    };

    private void SelectSecret(UserVaultSecretMetadata item)
    {
        selected = item;
        showActions = false;
        confirmRemoval = false;
        focusSelected = true;
    }

    private void ToggleActions()
    {
        showActions = !showActions;
        confirmRemoval = false;
    }

    private void ToggleEditor()
    {
        if (showEditor) CloseEditor();
        else OpenEditor();
    }

    private void OpenEditor(string? name = null)
    {
        form = new PersonalSecretForm { Name = name ?? string.Empty, Localizer = L };
        showActions = false;
        confirmRemoval = false;
        showEditor = true;
        focusEditor = true;
    }

    private void CloseEditor()
    {
        form.Name = string.Empty;
        form.Value = string.Empty;
        showEditor = false;
    }

    private enum SecretFilter { All, Passwords, KeysAndTokens }
    private enum SecretKind { Password, ApiKey, Token, Session, Other }

    private static SecretKind KindOf(string name)
    {
        var leaf = name[(name.LastIndexOf('/') + 1)..].ToLowerInvariant().Replace('_', '-');
        return leaf switch
        {
            "password" or "senha" or "passphrase" or "passwd" => SecretKind.Password,
            "api-key" or "apikey" => SecretKind.ApiKey,
            "token" => SecretKind.Token,
            _ when leaf.EndsWith("-password", StringComparison.Ordinal)
                || leaf.EndsWith("-senha", StringComparison.Ordinal) => SecretKind.Password,
            _ when leaf.EndsWith("-api-key", StringComparison.Ordinal) => SecretKind.ApiKey,
            _ when leaf.EndsWith("-token", StringComparison.Ordinal) => SecretKind.Token,
            "session" or "sessao" => SecretKind.Session,
            _ => SecretKind.Other
        };
    }

    private static string IconClass(SecretKind kind) =>
        $"vault-secret-icon vault-secret-icon--{kind.ToString().ToLowerInvariant()}";

    private static string KindIcon(SecretKind kind) => kind switch
    {
        SecretKind.Password => "lock",
        SecretKind.Token => "code",
        SecretKind.Session => "browser",
        _ => "key"
    };

    private static SUIColor KindColor(SecretKind kind) => kind switch
    {
        SecretKind.Password => SUIColor.Warning,
        SecretKind.ApiKey => SUIColor.Info,
        SecretKind.Token => SUIColor.Success,
        _ => SUIColor.Default
    };

    private Task RevealAsync(string name) => Dialogs.ShowAsync<PersonalSecretReveal>(
        L["Vault.Reveal.Title"].Value,
        new Dictionary<string, object?> { [nameof(PersonalSecretReveal.SecretName)] = name },
        new SUIDialogOptions { Icon = "shield" });

    private async Task SaveAsync()
    {
        saving = true;
        var result = await Data.PutPersonalAsync(Namespace, form.Name, form.Value);
        Notify(result.IsSuccess, L["Vault.UserVault.SecretSavedWithEnvelope"].Value, result.Error);
        if (result.IsSuccess)
        {
            CloseEditor();
            search = string.Empty;
            filter = SecretFilter.All;
            await LoadAsync();
            selected = visibleSecrets.FirstOrDefault(item =>
                string.Equals(item.Name, result.Value?.Name, StringComparison.Ordinal)) ?? selected;
        }
        saving = false;
    }

    private async Task DeleteAsync(string name)
    {
        saving = true;
        var result = await Data.DeletePersonalAsync(Namespace, name);
        Notify(result.IsSuccess, L["Vault.UserVault.SecretRemoved"].Value, result.Error);
        if (result.IsSuccess)
        {
            showActions = false;
            confirmRemoval = false;
            await LoadAsync();
        }
        saving = false;
    }

    private void Notify(bool succeeded, string successMessage, string? error)
    {
        if (succeeded) Toast.Success(successMessage);
        else Toast.Error(error ?? L["Vault.Data.OperationFailed"].Value);
    }

    private sealed class PersonalSecretForm : IValidatableObject
    {
        public IStringLocalizer<Sufficit.Identity.UI.Vault.Resources.VaultResource>? Localizer { get; set; }

        public string Name { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (Localizer is null)
                throw new InvalidOperationException("Localizer must be assigned before validation.");
            var l = Localizer;

            if (string.IsNullOrWhiteSpace(Name))
            {
                yield return new ValidationResult(l["Vault.UserVault.Validation.NameRequired"].Value, [nameof(Name)]);
            }
            else
            {
                if (Name.Length > 128)
                    yield return new ValidationResult(l["Vault.UserVault.Validation.NameMaxLength"].Value, [nameof(Name)]);

                if (!System.Text.RegularExpressions.Regex.IsMatch(
                        Name,
                        @"^(?!/)(?!.*(?:\.\.|//))[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+(?<!/)$"))
                    yield return new ValidationResult(l["Vault.UserVault.Validation.NamePattern"].Value, [nameof(Name)]);
            }

            if (string.IsNullOrWhiteSpace(Value))
                yield return new ValidationResult(l["Vault.UserVault.Validation.ValueRequired"].Value, [nameof(Value)]);
            else if (Value.Length > 16384)
                yield return new ValidationResult(l["Vault.UserVault.Validation.ValueMaxLength"].Value, [nameof(Value)]);
        }
    }

    private static DateTimeOffset Utc(DateTime value) =>
        new(DateTime.SpecifyKind(value, DateTimeKind.Utc));
}
