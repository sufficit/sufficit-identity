using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ProvisioningManifestTests
{
    private static IdentityProvisioningManifest PublicClientManifest(
        string scopeName,
        string clientId,
        string displayName,
        string scopeDisplayName) =>
        new()
        {
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = scopeName,
                    DisplayName = scopeDisplayName,
                    Resources = [scopeName],
                },
            ],
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    DisplayName = displayName,
                    ClientType = ManifestClientTypes.Public,
                    ConsentType = ManifestConsentTypes.Explicit,
                    RequirePkce = true,
                    GrantTypes =
                    [
                        ManifestGrantTypes.AuthorizationCode,
                        ManifestGrantTypes.RefreshToken,
                    ],
                    ResponseTypes = [ManifestResponseTypes.Code],
                    Scopes = ["openid", "offline_access", scopeName],
                    RedirectUris =
                    [
                        new Uri($"https://{clientId}.example.invalid/signin-oidc"),
                    ],
                    PostLogoutRedirectUris =
                    [
                        new Uri(
                            $"https://{clientId}.example.invalid/signout-callback-oidc"),
                    ],
                    FrontchannelLogoutUri = new Uri(
                        $"https://{clientId}.example.invalid/oidc/frontchannel-logout"),
                    BackchannelLogoutUri = new Uri(
                        $"https://{clientId}.example.invalid/oidc/backchannel-logout"),
                },
            ],
        };

    private static IdentityProvisioningManifest RedirectTransitionManifest(
        string scopeName,
        string clientId,
        Uri redirectUri,
        ClientDefinitionRolloutMode rolloutMode,
        bool authorizeSensitiveTransitions = false) =>
        new()
        {
            ManifestId = $"transition:{clientId}",
            RolloutMode = rolloutMode,
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = scopeName,
                    Resources = [scopeName],
                },
            ],
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    ClientType = ManifestClientTypes.Public,
                    ConsentType = ManifestConsentTypes.Explicit,
                    RequirePkce = true,
                    AuthorizeSensitiveTransitions =
                        authorizeSensitiveTransitions,
                    GrantTypes = [ManifestGrantTypes.AuthorizationCode],
                    ResponseTypes = [ManifestResponseTypes.Code],
                    Scopes = [scopeName],
                    RedirectUris = [redirectUri],
                },
            ],
        };

    private static IdentityProvisioningManifest ConfidentialClientManifest(
        string scopeName,
        string clientId,
        string secretReference,
        bool adoptExisting = false) =>
        new()
        {
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = scopeName,
                    Resources = [scopeName],
                },
            ],
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    ClientType = ManifestClientTypes.Confidential,
                    ConsentType = ManifestConsentTypes.Implicit,
                    SecretReference = secretReference,
                    AdoptExisting = adoptExisting,
                    GrantTypes = [ManifestGrantTypes.ClientCredentials],
                    Scopes = [scopeName],
                },
            ],
        };

    private static string RepositoryFile(params string[] path)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            throw new DirectoryNotFoundException(
                "Could not locate the Sufficit.Identity repository root.");
        }

        return Path.Combine([directory.FullName, .. path]);
    }
}
