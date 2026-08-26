using System.Text.Json.Serialization;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Provisioning;

/// <summary>
/// Versioned, secret-free description of the OpenIddict applications and
/// scopes that must exist in an environment.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IdentityProvisioningManifest
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;
    /// <summary>
    /// Stable identifier of the declarative source. When omitted, the
    /// provisioner derives a client-scoped compatibility identity.
    /// </summary>
    public string? ManifestId { get; init; }
    /// <summary>
    /// Compatibility rollout for sensitive changes to existing clients.
    /// Observe records future denials without mutating or interrupting callers;
    /// Enforce rejects unauthorized transitions.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter<ClientDefinitionRolloutMode>))]
    public ClientDefinitionRolloutMode RolloutMode { get; init; } =
        ClientDefinitionRolloutMode.Observe;
    public List<IdentityScopeManifest> Scopes { get; init; } = [];
    public List<IdentityClientManifest> Clients { get; init; } = [];
}

/// <summary>Declarative OpenIddict scope definition.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IdentityScopeManifest
{
    public string Name { get; init; } = "";
    public string? DisplayName { get; init; }
    public string? Description { get; init; }
    public List<string> Resources { get; init; } = [];
}

/// <summary>
/// Declarative OpenIddict client definition. <see cref="SecretReference"/>
/// identifies a value in an external secret store; it is never the secret
/// itself.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IdentityClientManifest
{
    public string ClientId { get; init; } = "";
    public string? DisplayName { get; init; }
    public string ClientType { get; init; } = ManifestClientTypes.Public;
    // L5 fix (eval L5): default to Explicit (secure-by-default — matches
    // ClientsController.Create and RegistrationController). A manifest that
    // omits consentType now provisions a client that prompts for consent,
    // not one that never asks.
    public string ConsentType { get; init; } = ManifestConsentTypes.Explicit;
    public string? SecretReference { get; init; }
    /// <summary>
    /// Explicitly authorizes provisioning to adopt an existing client that is
    /// unmanaged or owned by another manifest identity.
    /// </summary>
    public bool AdoptExisting { get; init; }
    /// <summary>
    /// Explicitly authorizes sensitive transitions for this client when the
    /// manifest rollout mode is Enforce. The provisioning service audits the
    /// actor and resulting transition.
    /// </summary>
    public bool AuthorizeSensitiveTransitions { get; init; }
    public bool RequirePkce { get; init; }
    public List<string> GrantTypes { get; init; } = [];
    public List<string> ResponseTypes { get; init; } = [];
    public List<string> Scopes { get; init; } = [];
    public List<Uri> RedirectUris { get; init; } = [];
    public List<Uri> PostLogoutRedirectUris { get; init; } = [];
    /// <summary>
    /// Native callbacks this client may be brought back to the foreground with
    /// once a grant completes (<c>native_return_uris</c> extension metadata,
    /// RFC 7591 section 2). Kept as strings, not <see cref="Uri"/>, because a
    /// private-use URI scheme (RFC 8252, section 7.1) is matched verbatim and
    /// would not survive canonicalization.
    /// </summary>
    public List<string> NativeReturnUris { get; init; } = [];
    public Uri? FrontchannelLogoutUri { get; init; }
    public bool FrontchannelLogoutSessionRequired { get; init; }
    public Uri? BackchannelLogoutUri { get; init; }
    public bool BackchannelLogoutSessionRequired { get; init; }
}

public static class ManifestClientTypes
{
    public const string Public = "public";
    public const string Confidential = "confidential";
}

public static class ManifestConsentTypes
{
    public const string Explicit = "explicit";
    public const string External = "external";
    public const string Implicit = "implicit";
    public const string Systematic = "systematic";
}

public static class ManifestGrantTypes
{
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
    public const string RefreshToken = "refresh_token";
    public const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
}

public static class ManifestResponseTypes
{
    public const string Code = "code";
}

/// <summary>
/// Resolves a logical secret reference only when a confidential client must be
/// created or explicitly rotated. Implementations should read a secret manager,
/// not configuration checked into source control.
/// </summary>
public interface IClientSecretResolver
{
    ValueTask<string> ResolveAsync(string reference, CancellationToken cancellationToken = default);
}

public sealed class ClientSecretResolverUnavailableException()
    : Exception(
        $"No {nameof(IClientSecretResolver)} is configured for this environment.");

public sealed class ClientSecretResolutionException : Exception
{
    public ClientSecretResolutionException()
        : base("The secret reference did not resolve to a usable value.")
    {
    }

    public ClientSecretResolutionException(Exception innerException)
        : base(
            "The secret reference did not resolve to a usable value.",
            innerException)
    {
    }
}
