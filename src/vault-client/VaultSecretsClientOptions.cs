namespace Sufficit.Identity.Vault.Client;

/// <summary>
/// Options for the vault REST client. Authentication is deliberately out of
/// scope: the host attaches its bearer-token handler to the named
/// <see cref="System.Net.Http.HttpClient"/> (see
/// <see cref="ServiceCollectionExtensions.AddSufficitVaultSecretsClient"/>).
/// </summary>
public sealed class VaultSecretsClientOptions
{
    public const string SectionName = "Sufficit:Vault:Client";

    /// <summary>Base address of the identity management API, e.g.
    /// https://identity.sufficit.com.br/.</summary>
    public Uri? BaseAddress { get; set; }

    /// <summary>Default context when a call does not specify one.</summary>
    public string ContextId { get; set; } = "global";

    /// <summary>Freshness window for resolved plaintext values. Within it,
    /// repeated resolves are served from memory without touching the API.</summary>
    public int ResolveCacheSeconds { get; set; } = 60;

    /// <summary>When the API is unreachable, a previously resolved value may
    /// be served for up to this long so consumers survive identity restarts.
    /// Set to 0 to fail closed instead.</summary>
    public int StaleFallbackHours { get; set; } = 24;
}
