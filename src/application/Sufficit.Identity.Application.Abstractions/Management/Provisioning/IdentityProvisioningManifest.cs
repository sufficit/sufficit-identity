using System.Text.Json.Serialization;

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
    public bool RequirePkce { get; init; }
    public List<string> GrantTypes { get; init; } = [];
    public List<string> ResponseTypes { get; init; } = [];
    public List<string> Scopes { get; init; } = [];
    public List<Uri> RedirectUris { get; init; } = [];
    public List<Uri> PostLogoutRedirectUris { get; init; } = [];
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

public sealed class ClientSecretResolutionException()
    : Exception("The secret reference did not resolve to a usable value.");
