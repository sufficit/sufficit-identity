using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Seeds the OpenIddict clients/scope and the default test user shared by the
/// integration test suite. Runs once per <see cref="SufficitIdentityTestFactory"/>
/// (i.e. once per collection, since all test classes share one factory via
/// <see cref="StsCollection"/>). Tests that need an isolated user (lockout,
/// introspection, token exchange) create their own via <see cref="CreateUserAsync"/>
/// with a unique username instead of reusing <see cref="DefaultUsername"/>.
/// </summary>
public static class TestDataSeeder
{
    public const string ScopeName = "test.scope";

    public const string ClientCredentialsClientId = "test-cc";
    public const string ClientCredentialsClientSecret = "test-cc-secret";

    public const string PasswordClientId = "test-ropc";
    public const string PasswordClientSecret = "test-ropc-secret";

    public const string TokenExchangeClientId = "test-exchange";
    public const string TokenExchangeClientSecret = "test-exchange-secret";

    public const string IntrospectionClientId = "test-introspect";
    public const string IntrospectionClientSecret = "test-introspect-secret";

    // Public client (no secret): authorization_code + PKCE + refresh_token,
    // ConsentTypes.Implicit so /connect/authorize never redirects to the
    // (headless-unreachable) /consent UI page for the happy-path tests.
    public const string AuthorizationCodeClientId = "test-authcode";
    public const string AuthorizationCodeRedirectUri = "https://client.tests.local/callback";

    // Confidential client: RFC 8628 device authorization grant.
    public const string DeviceClientId = "test-device";
    public const string DeviceClientSecret = "test-device-secret";

    // Confidential client carrying the OpenIddict-level
    // Permissions.GrantTypes.TokenExchange permission (so it reaches
    // AuthorizationController.ExchangeForTokenExchangeAsync at all) but
    // deliberately NOT included in a restricted
    // Sufficit:Identity:TokenExchange:AllowedClientIds allowlist in the
    // dedicated test that exercises that second gate.
    public const string TokenExchangeBlockedClientId = "test-exchange-blocked";
    public const string TokenExchangeBlockedClientSecret = "test-exchange-blocked-secret";

    public const string DirectiveClaimType = "directive";

    public const string DefaultUsername = "alice";
    public const string DefaultPassword = "Str0ng!Passw0rd#1";
    public const string DefaultDirectiveValue = "sufficit:test:directive";

    public static async Task SeedAsync(IServiceProvider services)
    {
        var scopeManager = services.GetRequiredService<IOpenIddictScopeManager>();
        var appManager = services.GetRequiredService<IOpenIddictApplicationManager>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();

        if (await scopeManager.FindByNameAsync(ScopeName) is null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = ScopeName,
                DisplayName = "Test scope",
                // OpenIddict only includes a token's non-standard claims (e.g.
                // `directive`, `act`) in the introspection response for a caller
                // explicitly listed as one of the token's audiences/resources —
                // otherwise they're treated as "potentially sensitive" and
                // stripped. The introspection client is named here so tokens
                // requesting this scope get it as a trusted audience.
                //
                // The token-exchange client is ALSO named here: OpenIddict's
                // token-exchange grant separately requires the exchanging
                // client to already be one of the *subject* token's audiences
                // ("the subject token was issued to a different client or for
                // another resource server" otherwise) — and the exchanged
                // token in TokenExchangeTests inherits this same scope (hence
                // this same resource/audience list) from its subject token.
                // TokenExchangeBlockedClientId is included for the same
                // reason: it must pass OpenIddict's OWN audience check to
                // ever reach AuthorizationController.ExchangeForTokenExchangeAsync
                // at all, so that the dedicated allowlist test actually
                // exercises the Sufficit-level TokenExchangeOptions gate
                // instead of failing one layer earlier for an unrelated
                // reason.
                Resources = { IntrospectionClientId, TokenExchangeClientId, TokenExchangeBlockedClientId },
            });
        }

        // (a) confidential client_credentials caller.
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = ClientCredentialsClientId,
            ClientSecret = ClientCredentialsClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.ClientCredentials,
                Permissions.Prefixes.Scope + ScopeName,
            },
        });

        // (b) confidential resource-owner-password-credentials caller.
        // Also carries the "roles" scope permission (on top of ScopeName) so
        // TokenExchangeTests can request it explicitly when it needs a
        // subject_token that actually carries a role claim (destinations-
        // gating negative test) — existing tests never request "roles", so
        // this is additive and does not change their behavior.
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = PasswordClientId,
            ClientSecret = PasswordClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.Password,
                Permissions.Prefixes.Scope + ScopeName,
                Permissions.Prefixes.Scope + Scopes.Roles,
            },
        });

        // (c) confidential token-exchange (RFC 8693) caller. Carries the
        // "test.scope" scope permission (on top of the grant-type
        // permission) so the destinations-gating negative test can
        // explicitly REQUEST just that scope on the exchange call itself
        // (narrowing away "roles") — the pre-existing positive test never
        // sends an explicit `scope` param, so this addition doesn't change
        // its behavior.
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = TokenExchangeClientId,
            ClientSecret = TokenExchangeClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.TokenExchange,
                Permissions.Prefixes.Scope + ScopeName,
            },
        });

        // (d) introspection-only caller.
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = IntrospectionClientId,
            ClientSecret = IntrospectionClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Introspection,
            },
        });

        // (e) public authorization_code + PKCE + refresh_token caller
        // (the flow all 26 legacy clients are expected to migrate to).
        // ConsentTypes.Implicit auto-grants without an interactive /consent
        // redirect (see AuthorizationController's needsInteractiveConsent
        // switch) — deliberate, so the happy-path tests can run headless
        // without the sibling UI's consent page. Requirements.Features.
        // ProofKeyForCodeExchange makes PKCE mandatory for this client,
        // matching the OAuth 2.1 baseline the eval recommends.
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = AuthorizationCodeClientId,
            ClientType = ClientTypes.Public,
            ConsentType = ConsentTypes.Implicit,
            RedirectUris = { new Uri(AuthorizationCodeRedirectUri) },
            Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Prefixes.Scope + Scopes.OpenId,
                Permissions.Prefixes.Scope + Scopes.Profile,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                Permissions.Prefixes.Scope + ScopeName,
            },
            Requirements =
            {
                Requirements.Features.ProofKeyForCodeExchange,
            },
        });

        // (f) confidential device-authorization-grant caller (RFC 8628).
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = DeviceClientId,
            ClientSecret = DeviceClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.DeviceAuthorization,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.DeviceCode,
                Permissions.Prefixes.Scope + ScopeName,
            },
        });

        // (g) token-exchange caller with the OpenIddict-level permission but
        // deliberately excluded from the Sufficit-level allowlist configured
        // for the dedicated "blocked by allowlist" negative test.
        await CreateApplicationIfMissingAsync(appManager, new OpenIddictApplicationDescriptor
        {
            ClientId = TokenExchangeBlockedClientId,
            ClientSecret = TokenExchangeBlockedClientSecret,
            ClientType = ClientTypes.Confidential,
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.TokenExchange,
            },
        });

        if (await userManager.FindByNameAsync(DefaultUsername) is null)
        {
            await CreateUserAsync(userManager, DefaultUsername, DefaultPassword, DefaultDirectiveValue);
        }
    }

    /// <summary>
    /// Creates a user with the given username/password (and, optionally, a
    /// persisted `directive` claim). Callers that need pollution-free state
    /// (lockout, introspection, token exchange tests) should pass a
    /// per-test-unique username instead of <see cref="DefaultUsername"/>.
    /// </summary>
    public static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> userManager,
        string username,
        string password,
        string? directiveValue = null)
    {
        var user = new ApplicationUser
        {
            UserName = username,
            Email = $"{username}@tests.local",
            EmailConfirmed = true,
        };

        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to seed test user '{username}': " +
                string.Join("; ", result.Errors.Select(e => e.Description)));
        }

        if (directiveValue is not null)
        {
            await userManager.AddClaimAsync(user, new Claim(DirectiveClaimType, directiveValue));
        }

        return user;
    }

    /// <summary>
    /// Creates the given role if it doesn't already exist and assigns it to
    /// <paramref name="user"/>. Used by the token-exchange destinations-gating
    /// negative test, which needs a subject with a real role to prove the
    /// role claim is (or isn't) actually propagated.
    /// </summary>
    public static async Task AddToRoleAsync(
        RoleManager<ApplicationRole> roleManager,
        UserManager<ApplicationUser> userManager,
        ApplicationUser user,
        string roleName)
    {
        if (await roleManager.FindByNameAsync(roleName) is null)
        {
            var roleResult = await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
            if (!roleResult.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Failed to seed test role '{roleName}': " +
                    string.Join("; ", roleResult.Errors.Select(e => e.Description)));
            }
        }

        var addResult = await userManager.AddToRoleAsync(user, roleName);
        if (!addResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to add test user '{user.UserName}' to role '{roleName}': " +
                string.Join("; ", addResult.Errors.Select(e => e.Description)));
        }
    }

    private static async Task CreateApplicationIfMissingAsync(
        IOpenIddictApplicationManager appManager,
        OpenIddictApplicationDescriptor descriptor)
    {
        if (await appManager.FindByClientIdAsync(descriptor.ClientId!) is null)
        {
            await appManager.CreateAsync(descriptor);
        }
    }
}
