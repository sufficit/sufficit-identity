using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// DI extensions that wire up the Sufficit Identity STS server
/// (ASP.NET Core Identity + OpenIddict server/validation).
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the database, ASP.NET Core Identity, and OpenIddict server/validation.
    /// Reads configuration from the <c>Sufficit:Identity</c> section.
    /// </summary>
    public static IServiceCollection AddSufficitIdentitySTS(
        this IServiceCollection services,
        IConfiguration configuration,
        string configurationSection = "Sufficit:Identity")
    {
        // The STS is a self-contained API module. Register its controllers as
        // an MVC application part so any composition host can map them without
        // relying on entry-assembly discovery.
        services.AddControllers()
            .AddApplicationPart(typeof(Controllers.AuthorizationController).Assembly);

        var options = configuration
            .GetSection(configurationSection)
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();

        // Read once, reused below both for the certificate fail-fast logic
        // and for the cookie SecurePolicy (#2): this reads the raw
        // environment variable (not IHostEnvironment) because this DI
        // extension has no IHostEnvironment of its own — only IConfiguration
        // is passed in — matching the pre-existing pattern this method
        // already relied on further down.
        var isDevelopmentEnvironment =
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";

        // ---- Database (MySQL via Oracle MySql.EntityFrameworkCore) ----
        // Stage 1 da migração Pomelo→Oracle (2026-07-21) — ver
        // docs/NOTICE-mysql-license.md para o racional de licença (GPLv2+
        // FOSS Exception temporária, voltar a Pomelo MIT quando shipar EF10).
        // API diff: UseMySQL(connectionString) — sem ServerVersion.AutoDetect
        // (Oracle provider deriva a versão do servidor da própria connection).
        var connectionString = configuration.GetConnectionString(options.ConnectionStringName)
            ?? throw new InvalidOperationException(
                $"Connection string '{options.ConnectionStringName}' not configured.");

        services.AddDbContext<AppDbContext>(db =>
        {
            db.UseMySQL(connectionString);
            db.UseOpenIddict();
        });

        // ---- Antiforgery (defensive registration — #N1) ----
        // Required so the AuthorizationController's IAntiforgery dependency
        // resolves even if this STS is ever hosted headless (without the
        // sibling sufficit-identity-ui project, which is what normally
        // registers AddAntiforgery in production today). AddAntiforgery is
        // TryAdd-based, so this is a no-op when the UI project has already
        // registered it. DeviceController already takes the same hard
        // dependency, so this just makes the contract explicit instead of
        // relying on a transitive registration.
        services.AddAntiforgery();

        // ---- ASP.NET Core Data Protection persistence (P0 #B4) ----
        // Previously NONE was configured: the key ring defaulted to the
        // local filesystem (or nothing durable at all in a container),
        // meaning every restart/redeploy or additional replica silently
        // regenerated the keys used to protect auth cookies, antiforgery
        // tokens and ASP.NET Identity's own DataProtectorTokenProvider
        // (password reset / email confirmation links) — any of those
        // in-flight at the time break with an opaque "unprotect failed"
        // once the old key is gone. Persisting to the same AppDbContext
        // (table: dataprotectionkeys, see AppDbContext.MapDataProtectionTable)
        // shares one key ring across every replica and survives restarts.
        //
        // SetApplicationName pins a stable discriminator used to derive
        // per-application purposes; it MUST stay identical across every
        // replica/deployment of this same app (changing it invalidates all
        // previously-issued protected payloads) — hardcoded rather than
        // read from config so it can never accidentally drift between
        // environments/replicas due to a config typo.
        //
        // TODO(prod, optional hardening): keys are currently persisted to
        // MySQL unencrypted-at-rest (ASP.NET Core will log a startup
        // warning to that effect — informational only, does NOT block
        // boot). They *could* additionally be encrypted with
        // `.ProtectKeysWithCertificate(cert)` reusing the same signing
        // certificate already loaded from options.Certificates.SigningPath
        // below in AddServer(...). Deliberately NOT wired up here: that
        // path is only exercised in real production (never in
        // Development/tests, since SigningPath is never set there), so it
        // has never been exercised end-to-end against a real PFX in this
        // codebase — enabling an unverified code path here risks turning a
        // cert-format edge case into a boot failure, which would violate
        // the "must not block boot" contract this file otherwise upholds.
        // Wire it up deliberately, with a real cert in hand to test against,
        // before relying on it.
        services.AddDataProtection()
            .SetApplicationName("Sufficit.Identity")
            .PersistKeysToDbContext<AppDbContext>();

        // ---- ASP.NET Core Identity ----
        services.AddIdentity<ApplicationUser, ApplicationRole>(identity =>
            {
                // Lockout policy from Sufficit:Identity:Lockout. Enforced by
                // CheckPasswordSignInAsync on both interactive login and the
                // password grant (lockoutOnFailure: true).
                identity.Lockout.MaxFailedAccessAttempts = options.Lockout.MaxFailedAttempts;
                identity.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(options.Lockout.DurationMinutes);
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();
        // .NET 10 native passkeys (WebAuthn/FIDO2): a inclusão do 9º generic
        // arg IdentityUserPasskey<string> em IdentityDbContext (AppDbContext)
        // faz AddEntityFrameworkStores<AppDbContext>() registrar automaticamente
        // IUserPasskeyStore<ApplicationUser>. UserManager<T> ganha os métodos
        // AddOrUpdatePasskeyAsync / GetPasskeysAsync / RemovePasskeyAsync /
        // FindByPasskeyIdAsync, e SignInManager<T> ganha CheckPasskeySignIn.
        // A UI Blazor (sufficit-identity-ui) invoca via JS interop com
        // navigator.credentials.create/get. A tabela userpasskeys é mapeada
        // em AppDbContext.MapIdentityTables.

        // Cookies used by the OpenIddict ASP.NET Core host.
        services.ConfigureApplicationCookie(o =>
        {
            // Lowercase canonical paths (matches the URL canonicalization
            // middleware that redirects /Account/Login → /account/login).
            o.LoginPath = "/account/login";
            o.LogoutPath = "/account/logout";
            o.AccessDeniedPath = "/account/accessdenied";
            // Required for Blazor Server + OIDC: SameSite=Lax works because the
            // UI is hosted on the same origin as the STS.
            o.Cookie.SameSite = SameSiteMode.Lax;

            // Secure policy (#2): outside Development, never send the auth
            // cookie over plaintext HTTP. The previous default
            // (SameAsRequest) trusted Request.Scheme, which silently reads
            // as "http" whenever TrustedProxies/X-Forwarded-Proto are
            // misconfigured (#1/#8) — this makes the cookie itself fail
            // safe regardless of that. Development keeps SameAsRequest
            // because the STS is exercised over both http:// and https://
            // locally (see appsettings.Development.json Kestrel endpoints),
            // and the TestServer used by src/tests is HTTP-only.
            o.Cookie.SecurePolicy = isDevelopmentEnvironment
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
        });

        // ---- External login providers (Google, GitHub, etc) ----
        // Reads from "Sufficit:Identity:ExternalProviders" section.
        // Each provider is registered only if Enabled=true and credentials
        // are present. The UI (Login.razor) lists the registered schemes
        // automatically via SignInManager.GetExternalAuthenticationSchemesAsync().
        var externalBuilder = services.AddAuthentication();
        AddExternalProviders(externalBuilder, configuration);

        // ---- OpenIddict (Core + Server + Validation) ----
        services.AddOpenIddict()
            .AddCore(core =>
            {
                core.UseEntityFrameworkCore()
                    .UseDbContext<AppDbContext>();
            })
            .AddServer(server =>
            {
                // -------------------------------------------------------------------
                // Endpoints (paths aligned with the legacy Duende deployment).
                // -------------------------------------------------------------------
                server.SetAuthorizationEndpointUris("connect/authorize")
                      .SetEndSessionEndpointUris("connect/endsession")
                      .SetTokenEndpointUris("connect/token")
                      .SetUserInfoEndpointUris("connect/userinfo")
                      .SetIntrospectionEndpointUris("connect/introspect")
                      .SetRevocationEndpointUris("connect/revocation")
                      .SetDeviceAuthorizationEndpointUris("connect/deviceauthorization")
                      .SetEndUserVerificationEndpointUris("connect/device")
                      .SetJsonWebKeySetEndpointUris(".well-known/openid-configuration/jwks")
                      .SetPushedAuthorizationEndpointUris("connect/par");

                // -------------------------------------------------------------------
                // Issuer (#8). Without this, OpenIddict derives `issuer` /
                // the token `iss` claim from the incoming request's
                // scheme+host on every call — which silently tracks
                // whatever Host header arrived, including a spoofed one if
                // AllowedHosts/TrustedProxies (Program.cs, appsettings) are
                // ever misconfigured, and diverges between direct-to-app
                // and behind-the-proxy requests. Pinning it here makes the
                // issuer a fixed, deliberate value everywhere. Only applied
                // when Sufficit:Identity:Issuer is actually configured; an
                // empty value preserves the previous request-derived
                // behavior (relied on by the test host, which serves plain
                // HTTP on an arbitrary TestServer address — though the test
                // configuration does also set an explicit Issuer, see
                // SufficitIdentityTestFactory).
                // -------------------------------------------------------------------
                if (!string.IsNullOrWhiteSpace(options.Issuer))
                {
                    server.SetIssuer(new Uri(options.Issuer, UriKind.Absolute));
                }

                // -------------------------------------------------------------------
                // Scopes advertised in discovery.
                // -------------------------------------------------------------------
                server.RegisterScopes(
                    Scopes.OpenId,
                    Scopes.Email,
                    Scopes.Profile,
                    Scopes.Roles,
                    Scopes.OfflineAccess,
                    Scopes.Address,
                    "directives",
                    "policies",
                    "skoruba_identity_admin_api",
                    "sufficit_ai_openai_bridge");

                // -------------------------------------------------------------------
                // Claims advertised in discovery (matches what the
                // AuthorizationController actually emits in tokens).
                // -------------------------------------------------------------------
                server.RegisterClaims(
                    Claims.Subject,
                    Claims.Name,
                    Claims.Email,
                    Claims.EmailVerified,
                    Claims.Role,
                    Claims.PreferredUsername,
                    // Sufficit-specific claim used by blazor/AI/endpoints for authz:
                    "directive");

                // -------------------------------------------------------------------
                // Grant types in use by Sufficit clients.
                // Implicit/hybrid flows are NOT enabled: OpenIddict 5+ deprecates them;
                // legacy clients must be migrated to authorization_code + PKCE.
                // Token Exchange (RFC 8693) is enabled here; the delegation/
                // impersonation logic itself lives in AuthorizationController.
                // Password and None are legacy grants removed by OAuth 2.1 and are
                // gated behind the Sufficit:Identity:LegacyGrants feature flags
                // below (both default to true during migration; the "Onda E"
                // cutover will flip them off).
                // -------------------------------------------------------------------
                server.AllowAuthorizationCodeFlow()
                      .AllowClientCredentialsFlow()
                      .AllowDeviceAuthorizationFlow()
                      .AllowRefreshTokenFlow()
                      .AllowTokenExchangeFlow();

                if (options.LegacyGrants.Password)
                    server.AllowPasswordFlow();

                if (options.LegacyGrants.None)
                    server.AllowNoneFlow();

                // -------------------------------------------------------------------
                // Token lifetimes (Sufficit:Identity:Tokens). Refresh rotation is
                // ON: OpenIddict's default behavior already issues a new,
                // single-use refresh token on every redemption and revokes the
                // previous one (with a small reuse leeway to absorb client
                // retries). Rotating refresh tokens are a non-negotiable part of
                // the 2026 security baseline (they bound the blast radius of a
                // stolen refresh token to a single use). Do NOT disable rotation;
                // only the lifetimes are configurable.
                // -------------------------------------------------------------------
                server.SetRefreshTokenLifetime(TimeSpan.FromDays(options.Tokens.RefreshTokenLifetimeDays));

                if (options.Tokens.AccessTokenLifetimeMinutes is { } accessMinutes)
                    server.SetAccessTokenLifetime(TimeSpan.FromMinutes(accessMinutes));

                if (options.Tokens.IdentityTokenLifetimeMinutes is { } identityMinutes)
                    server.SetIdentityTokenLifetime(TimeSpan.FromMinutes(identityMinutes));

                // -------------------------------------------------------------------
                // Reference tokens (P0 #5 / eval #B2). Historically hardcoded
                // unconditionally here for parity with the legacy Duende
                // deployment (sufficit-endpoints relies on introspection) —
                // but the legacy client inventory (docs/migration/PLAN.md in
                // git HEAD) shows sufficit-endpoints was the ONLY one of the
                // 26 legacy clients configured for reference tokens; the
                // rest expect a self-contained JWT they validate locally.
                // Flipping every client's token format at once is a breaking
                // migration-contract change, not a mechanical hardening — and
                // OpenIddict has no native per-client token-format switch, so
                // it cannot be fixed by config alone. Surfaced here as an
                // explicit, reversible flag
                // (Sufficit:Identity:Tokens:UseReferenceAccessTokens,
                // default true = current behavior, unchanged) so the
                // decision is deliberate and documented instead of buried in
                // a hardcoded call; see the XML doc on
                // TokenLifetimeOptions.UseReferenceAccessTokens for the full
                // JWT-vs-reference tradeoff. Do NOT flip to false without
                // coordinating with every resource server first.
                // -------------------------------------------------------------------
                if (options.Tokens.UseReferenceAccessTokens)
                {
                    server.UseReferenceAccessTokens();
                }

                // -------------------------------------------------------------------
                // PAR (Pushed Authorization Request, RFC 9126). The legacy Duende
                // deployment used it. The endpoint is set above (connect/par);
                // whether PAR is *required* is per-client
                // (RequirePushedAuthorizationRequests forces it for all clients;
                // not enabled here to preserve backward compatibility).
                // -------------------------------------------------------------------

                // -------------------------------------------------------------------
                // Signing/encryption certificates (SECURITY CRITICAL). Production
                // requires persistent X.509 certificates configured under
                // Sufficit:Identity:Certificates (PFX files loaded from disk);
                // ephemeral development certificates are only ever used when
                // ASPNETCORE_ENVIRONMENT=Development, so a misconfigured
                // production deployment fails fast at startup instead of
                // silently signing tokens with a throwaway, regenerated-on-
                // every-restart key.
                // (isDevelopmentEnvironment computed once, near the top of
                // AddSufficitIdentitySTS, and reused here via closure.)
                // -------------------------------------------------------------------
                if (!string.IsNullOrWhiteSpace(options.Certificates.SigningPath))
                {
                    var signingCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                        options.Certificates.SigningPath,
                        options.Certificates.SigningPassword);
                    server.AddSigningCertificate(signingCertificate);
                }
                else if (isDevelopmentEnvironment)
                {
                    server.AddDevelopmentSigningCertificate();
                }
                else
                {
                    throw new InvalidOperationException(
                        "No signing certificate configured. Production deployments " +
                        "require 'Sufficit:Identity:Certificates:SigningPath' (and " +
                        "SigningPassword, if the PFX is protected) to point to a " +
                        "valid PFX file. Ephemeral development certificates are only " +
                        "allowed when ASPNETCORE_ENVIRONMENT=Development.");
                }

                if (!string.IsNullOrWhiteSpace(options.Certificates.EncryptionPath))
                {
                    var encryptionCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                        options.Certificates.EncryptionPath,
                        options.Certificates.EncryptionPassword);
                    server.AddEncryptionCertificate(encryptionCertificate);
                }
                else if (isDevelopmentEnvironment)
                {
                    server.AddDevelopmentEncryptionCertificate();
                }
                else
                {
                    throw new InvalidOperationException(
                        "No encryption certificate configured. Production deployments " +
                        "require 'Sufficit:Identity:Certificates:EncryptionPath' (and " +
                        "EncryptionPassword, if the PFX is protected) to point to a " +
                        "valid PFX file. Ephemeral development certificates are only " +
                        "allowed when ASPNETCORE_ENVIRONMENT=Development.");
                }

                // -------------------------------------------------------------------
                // Discovery customizations: explicitly advertise as `false` the
                // logout capabilities OpenIddict does not expose as first-class
                // metadata toggles AND that this STS does NOT implement
                // end-to-end today (#N3 — see AuthorizationController.Backchannel
                // Logout/FrontchannelLogout, which are unadvertised no-op ack
                // stubs; real logout_token distribution to each RP's configured
                // backchannel/frontchannel_logout_uri is tracked as Onda B).
                // Publishing these as `false` (rather than omitting them) is the
                // most explicit signal to OIDC clients — they natively skip
                // logout distribution when the flag is false, and any
                // opportunistic probing of discovery cannot mistake absence for
                // "maybe supported". Every other previously-advertised flag
                // (DPoP, JAR request object signing algorithms, request_uri/
                // request parameter support, claims parameter,
                // check_session_iframe, and a non-standard backchannel_logout_url
                // — that field is per-client registration metadata, not OP
                // discovery metadata) has been removed entirely: none of those
                // features are actually implemented either.
                // -------------------------------------------------------------------
                server.AddEventHandler(OpenIddictServerHandlerDescriptor
                    .CreateBuilder<OpenIddictServerEvents.HandleConfigurationRequestContext>()
                    .UseInlineHandler(context =>
                    {
                        // Backchannel logout (OIDC Back-Channel Logout 1.0):
                        // NOT implemented — ack stub only.
                        context.Metadata["backchannel_logout_supported"] = JsonValue.Create(false);
                        context.Metadata["backchannel_logout_session_supported"] = JsonValue.Create(false);

                        // Frontchannel logout (OIDC Front-Channel Logout 1.0):
                        // NOT implemented — ack stub only.
                        context.Metadata["frontchannel_logout_supported"] = JsonValue.Create(false);
                        context.Metadata["frontchannel_logout_session_supported"] = JsonValue.Create(false);

                        return default;
                    })
                    .SetOrder(OpenIddictServerHandlers.Discovery.AttachEndpoints.Descriptor.Order + 1)
                    .SetType(OpenIddictServerHandlerType.Custom)
                    .Build());

                // ASP.NET Core host: let the AuthorizationController handle the
                // connect/* endpoints (passthrough) instead of OpenIddict writing
                // the responses directly.
                var aspNetCore = server.UseAspNetCore()
                      .EnableAuthorizationEndpointPassthrough()
                      .EnableEndSessionEndpointPassthrough()
                      .EnableTokenEndpointPassthrough()
                      .EnableUserInfoEndpointPassthrough()
                      .EnableEndUserVerificationEndpointPassthrough()
                      .EnableStatusCodePagesIntegration();

                // In Development with HTTPS (same port as the legacy STS:
                // https://localhost:26501), no transport security override needed.
                // In pure-HTTP dev mode, disable the requirement:
                if (isDevelopmentEnvironment
                    && Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Contains("https://") != true)
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            })
            .AddValidation(validation =>
            {
                validation.UseLocalServer();
                validation.UseAspNetCore();
            });

        return services;
    }

    /// <summary>
    /// Registers external login providers (Google, GitHub, etc) from the
    /// <c>Sufficit:Identity:ExternalProviders</c> configuration section.
    /// Each provider is only registered if Enabled=true and credentials
    /// are present (ClientId + ClientSecret).
    /// </summary>
    private static void AddExternalProviders(AuthenticationBuilder builder, IConfiguration configuration)
    {
        var section = configuration.GetSection("Sufficit:Identity:ExternalProviders");
        if (section is null) return;

        // Google
        var google = section.GetSection("Google");
        if (google.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(google["ClientId"])
            && !string.IsNullOrWhiteSpace(google["ClientSecret"]))
        {
            builder.AddGoogle(options =>
            {
                options.ClientId = google["ClientId"]!;
                options.ClientSecret = google["ClientSecret"]!;
                // Use the ASP.NET Core default (/signin-google) to match the
                // redirect URI already authorized in the Google Cloud Console.
                // Surface Google's email_verified so the UI external-login flow
                // only auto-confirms accounts with a provider-verified email
                // (account-takeover fix). Google returns it as a JSON bool.
                options.ClaimActions.MapJsonKey("email_verified", "email_verified", "boolean");
            });
        }

        // GitHub (requires AspNet.Security.OAuth.GitHub package in the host)
        var github = section.GetSection("GitHub");
        if (github.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(github["ClientId"])
            && !string.IsNullOrWhiteSpace(github["ClientSecret"]))
        {
            builder.AddGitHub(options =>
            {
                options.ClientId = github["ClientId"]!;
                options.ClientSecret = github["ClientSecret"]!;
                options.Scope.Add("user:email");
                // Use the ASP.NET Core default (/signin-github).
            });
        }

        // Facebook
        var facebook = section.GetSection("Facebook");
        if (facebook.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(facebook["ClientId"])
            && !string.IsNullOrWhiteSpace(facebook["ClientSecret"]))
        {
            builder.AddFacebook(options =>
            {
                options.ClientId = facebook["ClientId"]!;
                options.ClientSecret = facebook["ClientSecret"]!;

                // Force the Meta Graph API version to v22.0 (the package's
                // built-in default of v14.0 is deprecated and Meta now rejects
                // requests built against it with the cryptic
                // "app is unavailable / needs at least one supported permission"
                // error, even when the permissions are correctly configured
                // with Advanced Access in the App Dashboard).
                options.AuthorizationEndpoint = "https://www.facebook.com/v22.0/dialog/oauth";
                options.TokenEndpoint = "https://graph.facebook.com/v22.0/oauth/access_token";
                options.UserInformationEndpoint = "https://graph.facebook.com/v22.0/me?fields=id,name,email";

                // Disable automatic PKCE: ASP.NET Core 8+ enables PKCE by default
                // for all OAuth handlers, but Facebook's /dialog/oauth endpoint
                // (legacy OAuth) does NOT accept code_challenge — only the OIDC
                // endpoint does. PKCE on the legacy endpoint causes Facebook to
                // reject the request with the cryptic
                // "app is unavailable / needs at least one supported permission".
                // The app is confidential (has a client_secret), so PKCE is not
                // required for security.
                options.UsePkce = false;

                // Use the ASP.NET Core default (/signin-facebook) to match the
                // redirect URI already authorized in the Facebook Developer Console.

                // Apps that carry the "Facebook Login for Business" product
                // (mutually exclusive with classic Facebook Login — the
                // Sufficit app 649979658412936 is one, because its WhatsApp
                // Embedded Signup configurations belong to that product)
                // require a `config_id` query parameter instead of the classic
                // `scope` list. Without it, the OAuth dialog returns:
                //   "App is unavailable / needs at least one supported permission"
                // The referenced configuration must be created in the App
                // Dashboard (Facebook Login for Business > Configurations)
                // and must contain at least one supported permission besides
                // email/public_profile (e.g. business_management), per Meta docs.
                // We inject it via OnRedirectToAuthorizationEndpoint because
                // AddFacebook does not natively support config_id.
                var configurationId = facebook["ConfigurationId"];
                if (!string.IsNullOrWhiteSpace(configurationId))
                {
                    options.Events.OnRedirectToAuthorizationEndpoint = ctx =>
                    {
                        // ctx.RedirectUri is the full OAuth dialog URL that the
                        // default OAuthHandler already built, including scope,
                        // client_id, redirect_uri=https://localhost:port/signin-facebook,
                        // code_challenge (PKCE) and state. We need to extract
                        // the inner redirect_uri and state to rebuild a clean
                        // URL with config_id instead of scope.

                        var inner = new Uri(ctx.RedirectUri);
                        var innerQs = System.Web.HttpUtility.ParseQueryString(inner.Query);

                        var query = new Dictionary<string, string?>
                        {
                            ["client_id"] = innerQs["client_id"] ?? ctx.Options.ClientId,
                            ["response_type"] = innerQs["response_type"] ?? "code",
                            // Preserve the inner /signin-facebook callback URL.
                            ["redirect_uri"] = innerQs["redirect_uri"],
                            ["state"] = innerQs["state"],
                            // Facebook Login for Business replaces the scope
                            // list with a single config_id referencing the
                            // permissions defined in the App Dashboard.
                            ["config_id"] = configurationId
                        };

                        // Preserve PKCE code_challenge if the handler added it.
                        if (innerQs["code_challenge"] is { } cc && !string.IsNullOrEmpty(cc))
                        {
                            query["code_challenge"] = cc;
                            query["code_challenge_method"] = innerQs["code_challenge_method"] ?? "S256";
                        }

                        var baseUrl = inner.GetLeftPart(UriPartial.Path);
                        ctx.Response.Redirect(QueryHelpers.AddQueryString(baseUrl, query));
                        return Task.CompletedTask;
                    };
                }
                else
                {
                    // Classic Facebook Login (scope-based). Only works for
                    // Consumer-type apps that carry the classic "Facebook
                    // Login" product; apps with "Facebook Login for Business"
                    // (like 649979658412936) reject any scope-based dialog
                    // with "needs at least one supported permission" and must
                    // set ConfigurationId above instead.
                    options.Scope.Add("public_profile");
                }
            });
        }
    }
}
