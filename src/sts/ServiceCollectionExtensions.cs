using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using MySqlConnector;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.STS.Diagnostics;
using Sufficit.Identity.STS.Email;
using Sufficit.Identity.STS.Metrics;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Management;
using Sufficit.Identity.Vault;
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
        string configurationSection = "Sufficit:Identity",
        ISecretStore? secretStore = null)
    {
        // The STS is a self-contained API module. Register its controllers as
        // an MVC application part so any composition host can map them without
        // relying on entry-assembly discovery.
        services.AddControllers()
            .AddApplicationPart(typeof(Controllers.AuthorizationController).Assembly);

        // AuthorizationController exposes the standard OIDC `picture` claim
        // from the active branding theme. Keep these dependencies inside the
        // STS module so composition hosts that use AddSufficitIdentitySTS()
        // directly can activate every controller. UI/management hosts may
        // still replace either service before this registration.
        services.TryAddSingleton<IBrandingThemeProvider, BrandingThemeProvider>();
        services.TryAddSingleton<IUserAvatarUrlResolver, UserAvatarUrlResolver>();

        var startupSecretStore = secretStore ?? new EnvironmentSecretStore(configuration);
        var options = configuration
            .GetSection(configurationSection)
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();
        var vaultOptions = configuration
            .GetSection(VaultOptions.SectionName)
            .Get<VaultOptions>() ?? new VaultOptions();
        if (vaultOptions.ManageSigningKeys && !vaultOptions.Enabled)
        {
            throw new InvalidOperationException(
                "Sufficit:Vault:ManageSigningKeys requires Sufficit:Vault:Enabled=true.");
        }
        ValidateAdvancedProtocolOptions(options);
        options.HumanVerification.Validate();
        services.AddSingleton(options);
        services.Replace(ServiceDescriptor.Singleton<
            IIdentityRuntimeCapabilityCatalog>(
            new SufficitIdentityRuntimeCapabilityCatalog(options)));
        services.AddSingleton(options.HumanVerification);
        services.AddSingleton(options.TwoFactor);
        services.AddSingleton(options.Passkeys);
        services.AddSingleton(options.CredentialMutations);
        services.AddSingleton(options.PersonalTokens);
        services.AddSingleton(options.Fapi2);
        services.AddSingleton(options.Mtls);
        services.AddSingleton(options.Jar);
        services.AddSingleton(options.Ciba);
        services.AddSingleton(options.SharedSignals);
        services.AddSingleton(options.OutboundHttp);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IProductionPostureContributor,
                Security.StsProductionPostureContributor>());
        services.AddSingleton<IPublicOriginResolver, PublicOriginResolver>();
        services.AddScoped<IAccountLookupPolicy, AccountLookupPolicy>();
        services.AddSingleton<ISecurityDecisionTelemetry,
            SecurityDecisionTelemetry>();
        services.AddSingleton<IReservedScopePolicy>(
            new ReservedScopePolicy(
                new[] { "identity.management", "scim" }
                    .Concat(RetiredIdentityScopes.Names)));
        services.AddSingleton<IClientScopeGrantPolicy,
            ClientScopeGrantPolicy>();
        services.AddSingleton<IClientDefinitionValidator,
            ClientDefinitionValidator>();
        services.AddSingleton<IApplicationClaimDestinationPolicy>(provider =>
            new ApplicationClaimDestinationPolicy(
                options.ClaimScopeMap,
                provider.GetRequiredService<ILogger<ApplicationClaimDestinationPolicy>>(),
                provider.GetRequiredService<ISecurityDecisionTelemetry>()));
        services.AddSingleton<ITokenIssuancePolicyKernel, TokenIssuancePolicyKernel>();
        services.AddSingleton<IPersonalTokenIssuancePolicy, PersonalTokenIssuancePolicy>();
        services.AddSingleton<ISubjectTokenProvenancePolicy, SubjectTokenProvenancePolicy>();
        services.AddScoped<IAuthenticationContextAccessor, AuthenticationContextAccessor>();
        services.AddSingleton<IAuthenticationContextProjector, AuthenticationContextProjector>();
        services.AddSingleton<Mtls.IMtlsClientCertificatePolicy,
            Mtls.MtlsClientCertificatePolicy>();
        services.AddSingleton<IdentityMetricsRuntimeState>();
        services.AddSingleton<IdentityUsageMetricChannel>();
        services.AddSingleton<IIdentityUsageMetricSink>(provider =>
            provider.GetRequiredService<IdentityUsageMetricChannel>());
        services.AddSafeHttpClient(
            "identity-metrics-export", options.OutboundHttp);
        services.AddHttpClient<IHumanVerificationService,
                RemoteHumanVerificationService>()
            .UseSafeOutboundHttp(options.OutboundHttp);

        var emailOptions = configuration
            .GetSection("Sufficit:Identity:Email")
            .Get<EmailOptions>() ?? new EmailOptions();
        services.AddSingleton(emailOptions);

        // L4 hardening: warn loudly when TestEmailAddress is set outside
        // Development — this redirects ALL outbound email (including password
        // resets) to that address, which is a silent misconfiguration in prod.
        // (isDevelopmentEnvironment is computed later in this method; read the
        // env var directly here since the email guard runs at DI-build time.)
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") != "Development"
            && !string.IsNullOrWhiteSpace(emailOptions.TestEmailAddress))
        {
            Console.Error.WriteLine(
                "[WARNING] Sufficit:Identity:Email:TestEmailAddress is set in a non-Development " +
                "environment. ALL outgoing emails (including password-reset links) are being " +
                "redirected to '{0}'. Clear this setting in production.",
                emailOptions.TestEmailAddress);
        }
        var smtpHost = configuration["Sufficit:Identity:Smtp:Host"];
        if (string.IsNullOrWhiteSpace(smtpHost))
        {
            services.AddTransient<IEmailSender, LoggingEmailSender>();
        }
        else
        {
            services.AddTransient<IEmailSender, SmtpEmailSender>();
        }

        // Read once, reused below both for the certificate fail-fast logic
        // and for the cookie SecurePolicy (#2): this reads the raw
        // environment variable (not IHostEnvironment) because this DI
        // extension has no IHostEnvironment of its own — only IConfiguration
        // is passed in — matching the pre-existing pattern this method
        // already relied on further down.
        var isDevelopmentEnvironment =
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
        var configuredPublicOrigin = PublicOriginResolver.ResolveConfigured(options);
        if (configuredPublicOrigin is null && options.PublicOrigin.Mode == PublicOriginMode.Enforce)
        {
            throw new InvalidOperationException(
                "PublicOrigin:Mode=Enforce requires Sufficit:Identity:PublicUrl or Issuer.");
        }
        if (!isDevelopmentEnvironment && configuredPublicOrigin is null)
        {
            Console.Error.WriteLine(
                "[WARNING] No canonical Sufficit:Identity:PublicUrl/Issuer is configured. Public URLs remain request-derived in compatibility Audit mode.");
        }
        // Auxiliary protocol JWTs (logout_token, JARM, SSF/CAEP and CIBA)
        // share one key for the lifetime of this service provider. In
        // production this resolves the configured STS certificate. In
        // Development it creates one ephemeral key that is also added to the
        // OpenIddict server below, ensuring its public half appears in JWKS.
        var certificateMaterial = LoadCertificateMaterial(
            options.Certificates,
            isDevelopmentEnvironment,
            startupSecretStore);
        var auxiliarySigningCredentials = ResolveProtocolSigningCredentials(
            certificateMaterial.PrimarySigning,
            isDevelopmentEnvironment);

        // ---- Database (MySQL/MariaDB via Pomelo.EntityFrameworkCore.MySql) ----
        // Sufficit fork of Pomelo (EF Core 10), built from upstream PR #2019.
        // Migrated off Oracle MySql.EntityFrameworkCore on 2026-07-26 because
        // of a production-blocking translation bug (FindByNamesAsync IN(@p)).
        // See docs/NOTICE-mysql-license.md for the full rationale + fork details.
        // API: UseMySql(connectionString, MariaDbServerVersion.AutoDetect(...)).
        var configuredConnectionString = ResolveSecret(
                startupSecretStore,
                "database/connection-string")
            ?? throw new InvalidOperationException(
                $"Connection string '{options.ConnectionStringName}' not configured.");
        DatabaseTransportPolicy.Validate(
            configuredConnectionString,
            options.Database.TransportMode,
            isDevelopmentEnvironment);
        // Integration hosts use the documented "unused" sentinel and replace
        // the provider with one shared in-memory SQLite connection. Running a
        // background writer against that single connection races EF's SQLite
        // function initialization. Real connection strings always enable the
        // collector; the sentinel keeps protocol tests deterministic.
        if (!string.Equals(configuredConnectionString, "unused", StringComparison.Ordinal))
            services.AddHostedService<IdentityUsageMetricsWorker>();
        var databaseTelemetry = new DatabaseRuntimeTelemetry();
        databaseTelemetry.ConfigureWatchdog(options.Database.Watchdog.Enabled);
        services.AddSingleton(databaseTelemetry);
        services.AddSingleton<IDatabaseRuntimeTelemetry>(databaseTelemetry);
        var connectionTelemetry =
            new DatabaseConnectionTelemetryInterceptor(databaseTelemetry);
        var commandTelemetry =
            new DatabaseCommandTelemetryInterceptor(databaseTelemetry);

        var connectionString = ApplyDatabaseConnectionPolicy(
            configuredConnectionString,
            options.Database.ConnectionPool,
            tolerateInvalidDevelopmentValue: isDevelopmentEnvironment);

        // AddDbContextFactory registers BOTH a singleton IDbContextFactory<AppDbContext>
        // (used by singletons like the server-side session ITicketStore, which
        // CookieAuthenticationOptions resolves from the root provider) AND a
        // scoped AppDbContext (used by the normal request-scoped services).
        // Registering AddDbContext alongside it causes a captive-dependency
        // fault (scoped DbContextOptions consumed by the singleton factory), so
        // the factory is the single registration point for both lifetimes.
        services.AddDbContextFactory<AppDbContext>(db =>
        {
            db.UseMySql(
                connectionString,
                MariaDbServerVersion.AutoDetect(connectionString),
                mysql => mysql.MigrationsHistoryTable(IdentityDatabaseSchema.MigrationsHistoryTable));
            db.UseOpenIddict();
            db.AddInterceptors(connectionTelemetry, commandTelemetry);
        });
        services.AddHostedService<DatabaseHealthWatchdog>();

        // ---- Antiforgery (defensive registration — #N1) ----
        // Required so the AuthorizationController's IAntiforgery dependency
        // resolves even if this STS is ever hosted headless (without the
        // embedded Sufficit.Identity.UI project, which is what normally
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
        // L8 hardening: encrypt DP keys at rest with the signing certificate
        // when one is configured. In Development (no cert) keys stay
        // unencrypted (harmless — ephemeral).
        //
        // Finding #12 (fail-open): the original code silently fell back to
        // plaintext keys if the cert couldn't be used, which is a security
        // downgrade. In production (cert configured), a DP-key encryption
        // failure is now FATAL — the process refuses to start rather than
        // silently storing keys in plaintext. In Development, no cert is
        // configured so this block is skipped entirely.
        var dpBuilder = services.AddDataProtection()
            .SetApplicationName("Sufficit.Identity")
            .PersistKeysToDbContext<AppDbContext>();

        if (certificateMaterial.PrimarySigning is not null)
        {
            // If ProtectKeysWithCertificate throws (wrong key type, etc.), let
            // it propagate — fail-closed is the correct posture for production.
            dpBuilder.ProtectKeysWithCertificate(
                certificateMaterial.PrimarySigning);
        }

        // ---- Internal secret vault (envelope encryption, Transit-style) ----
        // When Sufficit:Vault:Enabled is false (default), IKeyVault resolves to
        // PassThroughKeyVault (round-trip without crypto). When true, the real
        // KeyVault wraps DEKs via the Data Protection key ring above (zero new
        // deps). Consumers (SsfStreamStore, future) inject IKeyVault and get
        // the right impl transparently.
        services.AddSufficitVault(configuration);
        if (vaultOptions.ManageSigningKeys)
        {
            services.AddScoped<Vault.VaultSigningCredentialsHandler>();
            services.AddScoped<Vault.VaultJsonWebKeySetHandler>();
        }

        // ---- ASP.NET Core Identity ----
        services.AddIdentity<ApplicationUser, ApplicationRole>(identity =>
            {
                // Lockout policy from Sufficit:Identity:Lockout. Enforced by
                // CheckPasswordSignInAsync on both interactive login and the
                // password grant (lockoutOnFailure: true).
                identity.Lockout.MaxFailedAccessAttempts = options.Lockout.MaxFailedAttempts;
                identity.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(options.Lockout.DurationMinutes);

                // Password complexity policy from Sufficit:Identity:Password
                // (eval M2). Applied on creation/change/reset only — never
                // retroactively against existing users (ASP.NET Core Identity
                // semantics), so flipping this does not force a mass password
                // reset on login.
                identity.Password.RequiredLength = options.Password.RequiredLength;
                identity.Password.RequireDigit = options.Password.RequireDigit;
                identity.Password.RequireLowercase = options.Password.RequireLowercase;
                identity.Password.RequireUppercase = options.Password.RequireUppercase;
                identity.Password.RequireNonAlphanumeric = options.Password.RequireNonAlphanumeric;
                identity.Password.RequiredUniqueChars = options.Password.RequiredUniqueChars;

                // Sign-in policy from Sufficit:Identity:SignIn (eval M3). Every
                // grant in AuthorizationController consults CanSignInAsync, so
                // RequireConfirmedEmail gates interactive login AND every token
                // grant uniformly. See SignInPolicyOptions XML doc for the
                // external-login cross-repo dependency and the runbook.
                identity.SignIn.RequireConfirmedEmail = options.SignIn.RequireConfirmedEmail;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddClaimsPrincipalFactory<OidcSessionClaimsPrincipalFactory>()
            .AddDefaultTokenProviders();

        // L10: breached-password validator (HIBP k-anonymity range API).
        // Registered only when RejectBreached is true. Fail-open on API
        // unavailability (see BreachedPasswordValidator remarks).
        if (options.Password.RejectBreached)
        {
            services.AddHttpClient<BreachedPasswordValidator>()
                .UseSafeOutboundHttp(options.OutboundHttp);
            services.AddScoped<IPasswordValidator<ApplicationUser>, BreachedPasswordValidator>();
        }

        services.AddHttpContextAccessor();
        services.Configure<IdentityPasskeyOptions>(passkeys =>
        {
            if (!string.IsNullOrWhiteSpace(options.Passkeys.RelyingPartyId))
            {
                passkeys.ServerDomain = options.Passkeys.RelyingPartyId.Trim();
            }
        });
        // ASP.NET Identity stores WebAuthn challenge state in its temporary
        // TwoFactorUserId authentication scheme. Keeping that ticket inside
        // the cookie can produce response headers larger than common reverse
        // proxy buffers. Store the protected ticket server-side and send only
        // a random lookup key to the browser. AddDistributedMemoryCache is a
        // safe single-node default and remains replaceable by Redis or another
        // IDistributedCache when the host is replicated.
        services.AddDistributedMemoryCache();
        services.AddSingleton<PasskeyAuthenticationTicketStore>();
        services.AddOptions<CookieAuthenticationOptions>(
                IdentityConstants.TwoFactorUserIdScheme)
            .Configure<PasskeyAuthenticationTicketStore>((cookie, ticketStore) =>
                cookie.SessionStore = ticketStore);

        // ---- Server-side OIDC sessions (the Identity application cookie) ----
        // The browser receives only the opaque OIDC sid as its session-cookie
        // value; the full AuthenticationTicket lives in AppDbContext
        // (oidcusersessions), DataProtection-protected and serialized exactly
        // as the passkey store does. This gives the sid a durable, enumerable,
        // revocable row — closing the protocol gap vs. Keycloak/Duende/Zitadel
        // (server-side sessions) and enabling per-device revocation.
        //
        // The store key IS the sid already minted by
        // OidcSessionClaimsPrincipalFactory and carried in the ticket, so every
        // existing behavior (sid stability across refresh, logout_token fan-out)
        // is preserved. SINGLETON: CookieAuthenticationOptions.SessionStore is
        // resolved from the root provider; the store therefore depends on
        // IDbContextFactory<AppDbContext> (singleton) and creates a context per
        // operation. Multi-replica safe out of the box (DB persistence).
        services.AddSingleton<OidcUserSessionTicketStore>();
        services.AddSingleton<ISessionManagement>(sp =>
            sp.GetRequiredService<OidcUserSessionTicketStore>());
        services.AddOptions<CookieAuthenticationOptions>(
                IdentityConstants.ApplicationScheme)
            .Configure<OidcUserSessionTicketStore>((cookie, store) =>
                cookie.SessionStore = store);
        // .NET 10 native passkeys (WebAuthn/FIDO2): a inclusão do 9º generic
        // arg IdentityUserPasskey<string> em IdentityDbContext (AppDbContext)
        // faz AddEntityFrameworkStores<AppDbContext>() registrar automaticamente
        // IUserPasskeyStore<ApplicationUser>. UserManager<T> ganha os métodos
        // AddOrUpdatePasskeyAsync / GetPasskeysAsync / RemovePasskeyAsync /
        // FindByPasskeyIdAsync, e SignInManager<T> ganha CheckPasskeySignIn.
        // A UI Blazor incorporada invoca via JS interop com
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
        services.Configure<SecurityStampValidatorOptions>(options =>
        {
            // Administrative lockout updates the user's security stamp. Check
            // it on every cookie-authenticated request so a blocked account
            // loses its local Identity session immediately instead of waiting
            // for the framework's default validation interval.
            options.ValidationInterval = TimeSpan.Zero;
        });

        // ---- External login providers (Google, GitHub, etc) ----
        // Reads from "Sufficit:Identity:ExternalProviders" section.
        // Each provider is registered only if Enabled=true and credentials
        // are present. The UI (Login.razor) lists the registered schemes
        // automatically via SignInManager.GetExternalAuthenticationSchemesAsync().
        var externalBuilder = services.AddAuthentication();
        AddExternalProviders(externalBuilder, configuration, startupSecretStore);

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
                // Mutual TLS (mTLS) endpoint aliases (RFC 8705, item 3.4).
                // Opt-in via Sufficit:Identity:Mtls:Enabled — mTLS requires the
                // HOST to request/validate client certificates at the TLS layer,
                // so this just registers the aliased paths (distinct from the
                // plain endpoints) so clients can target them for certificate-
                // based authentication. The discovery metadata flag below
                // advertises the capability only when Enabled. private_key_jwt
                // (RFC 7523) is enabled by OpenIddict unconditionally and is
                // NOT gated here — it is the OTHER strong client-auth method.
                // -------------------------------------------------------------------
                if (options.Mtls.Enabled)
                {
                    // MTLS alias setters require ABSOLUTE URI strings (unlike
                    // SetTokenEndpointUris, which accepts relative paths and
                    // resolves them against the issuer). Build absolute URIs
                    // from the configured issuer so they parse cleanly; the
                    // discovery handler re-roots them to the real request
                    // issuer at runtime.
                    var mtlsIssuer = string.IsNullOrWhiteSpace(options.Issuer)
                        ? "https://localhost/"
                        : options.Issuer;
                    var mtlsBase = new Uri(mtlsIssuer, UriKind.Absolute);

                    server.SetMtlsTokenEndpointAliasUri(new Uri(mtlsBase, "connect/token/mtls").AbsoluteUri)
                          .SetMtlsIntrospectionEndpointAliasUri(new Uri(mtlsBase, "connect/introspect/mtls").AbsoluteUri)
                          .SetMtlsRevocationEndpointAliasUri(new Uri(mtlsBase, "connect/revocation/mtls").AbsoluteUri)
                          .SetMtlsDeviceAuthorizationEndpointAliasUri(new Uri(mtlsBase, "connect/deviceauthorization/mtls").AbsoluteUri)
                          .SetMtlsUserInfoEndpointAliasUri(new Uri(mtlsBase, "connect/userinfo/mtls").AbsoluteUri)
                          .SetMtlsPushedAuthorizationEndpointAliasUri(new Uri(mtlsBase, "connect/par/mtls").AbsoluteUri);
                }

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
                // Application-specific scopes are opt-in configuration. The
                // STS deliberately does not know domain names; a composing
                // application can map any persisted claim to any scope through
                // ClaimScopeMap.
                var configuredClaimScopes = options.ClaimScopeMap.ClaimToScope
                    .Where(pair => !string.IsNullOrWhiteSpace(pair.Key)
                        && !string.IsNullOrWhiteSpace(pair.Value))
                    .ToArray();
                var applicationScopes = configuredClaimScopes
                    .Select(pair => pair.Value.Trim())
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                var applicationClaims = configuredClaimScopes
                    .Select(pair => pair.Key.Trim())
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();

                server.RegisterScopes([
                    Scopes.OpenId,
                    Scopes.Email,
                    Scopes.Profile,
                    Scopes.Roles,
                    Scopes.OfflineAccess,
                    Scopes.Address,
                    "identity.management",
                    "sufficit_ai_openai_bridge",
                    .. applicationScopes]);

                // MCP / agent-AI resource servers (RFC 8707, item 4.2). Every
                // resource accepted by this host must be explicitly configured
                // and registered as an audience. OpenIddict's normal resource
                // validation remains enabled, so the per-client oi_rprm
                // permission and the host allow-list both have to authorize a
                // requested resource. This prevents an unrelated client from
                // turning an arbitrary URI into an access-token audience.
                if (options.Mcp.Resources.Count > 0)
                {
                    server.RegisterAudiences(options.Mcp.Resources.ToArray());
                    server.RegisterResources(options.Mcp.Resources.ToArray());
                }

                // -------------------------------------------------------------------
                // Claims advertised in discovery (matches what the
                // AuthorizationController actually emits in tokens).
                // -------------------------------------------------------------------
                server.RegisterClaims([
                    Claims.Subject,
                    Claims.Name,
                    Claims.Email,
                    Claims.EmailVerified,
                    Claims.Role,
                    Claims.PreferredUsername,
                    .. applicationClaims]);

                // -------------------------------------------------------------------
                // Grant types in use by Sufficit clients.
                // Implicit/hybrid flows are NOT enabled: OpenIddict 5+ deprecates them;
                // legacy clients must be migrated to authorization_code + PKCE.
                // Token Exchange (RFC 8693) is enabled here; the delegation/
                // impersonation logic itself lives in AuthorizationController.
                // Password and None are legacy grants removed by OAuth 2.1 and are
                // gated behind the Sufficit:Identity:LegacyGrants feature flags
                // below (both default to FALSE — secure-by-default; the "Onda E"
                // cutover will flip them off).
                // -------------------------------------------------------------------
                server.AllowAuthorizationCodeFlow()
                      .AllowClientCredentialsFlow()
                      .AllowDeviceAuthorizationFlow()
                      .AllowRefreshTokenFlow()
                      .AllowTokenExchangeFlow();

                server.AddEventHandler(RecordIdentityUsage.Descriptor);
                server.AddEventHandler(RecordAuthorizationUsageFailure.Descriptor);
                server.AddEventHandler(RecordTokenUsageFailure.Descriptor);

                if (options.Fapi2.Enabled)
                {
                    // These OpenIddict lifetimes are global. Tightening them
                    // for all clients is backward compatible and avoids a
                    // profiled client accidentally receiving a five-minute
                    // authorization code or hour-long PAR request URI.
                    server.SetAuthorizationCodeLifetime(TimeSpan.FromSeconds(
                        options.Fapi2.AuthorizationCodeLifetimeSeconds));
                    server.Configure(serverOptions =>
                        serverOptions.RequestTokenLifetime = TimeSpan.FromSeconds(
                            options.Fapi2.PushedAuthorizationRequestLifetimeSeconds));

                    server.AddEventHandler(Fapi.ValidateFapiAuthorizationRequest.Descriptor);
                    server.AddEventHandler(Fapi.ValidateFapiPushedAuthorizationRequest.Descriptor);
                    server.AddEventHandler(Fapi.ValidateFapiTokenRequest.Descriptor);
                }

                if (options.Jarm.Enabled)
                {
                    server.Configure(serverOptions =>
                    {
                        serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.QueryJwt);
                        serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.FragmentJwt);
                        serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.FormPostJwt);
                        serverOptions.ResponseModes.Add(Jarm.JarmAuthorizationResponseHandler.Jwt);
                    });
                    server.AddEventHandler(Jarm.JarmAuthorizationResponseHandler.Descriptor);
                }

                // ---- JWT-Secured Authorization Requests (JAR, RFC 9101) ----
                // Two endpoint hooks (authorization + PAR) that extract a
                // signed `request` parameter, validate it against the client's
                // registered keys, and merge its claims into the request. The
                // handlers are scoped (need IOpenIddictApplicationManager).
                if (options.Jar.Enabled)
                {
                    server.AddEventHandler(Jar.JarRequestObjectHandler
                        .ExtractAuthorizationRequestObject.Descriptor);
                    server.AddEventHandler(Jar.JarRequestObjectHandler
                        .ExtractPushedAuthorizationRequestObject.Descriptor);
                }

                if (options.LegacyGrants.Password)
                    server.AllowPasswordFlow();

                if (options.LegacyGrants.None)
                    server.AllowNoneFlow();

                // OAuth 2.1 baseline: require PKCE for every authorization-code
                // client and accept only S256. Both controls have explicit
                // migration opt-outs for legacy confidential clients.
                if (options.Pkce.RequireForAllClients)
                    server.RequireProofKeyForCodeExchange();

                if (!options.Pkce.AllowPlainCodeChallengeMethod)
                {
                    server.Configure(serverOptions =>
                        serverOptions.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
                }

                if (options.Dpop.Enabled)
                {
                    server.AddEventHandler(Dpop.AttachDpopConfirmation.Descriptor);
                    server.AddEventHandler(Dpop.AttachDpopTokenType.Descriptor);
                    server.AddEventHandler(Dpop.ExtractDpopUserInfoToken.Descriptor);
                    server.AddEventHandler(Dpop.ValidateDpopAccessTokenProof.Descriptor);
                }

                if (options.Mtls.Enabled)
                {
                    server.AddEventHandler(Mtls.AttachMtlsConfirmation.Descriptor);
                }

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
                // PAR (Pushed Authorization Request, RFC 9126). The endpoint is
                // set above (connect/par). PAR is required per-client by FAPI
                // 2.0 (ValidateFapiAuthorizationRequest); the global opt-in
                // here extends the requirement to every client, and the global
                // lifetime knob applies to non-FAPI requests.
                // -------------------------------------------------------------------
                if (options.Par.RequireForAllClients)
                {
                    server.RequirePushedAuthorizationRequests();
                }

                if (options.Par.RequestUriLifetimeSeconds is { } parLifetime)
                {
                    server.Configure(serverOptions =>
                        serverOptions.RequestTokenLifetime = TimeSpan.FromSeconds(parLifetime));
                }

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
                if (vaultOptions.ManageSigningKeys)
                {
                    // OpenIddict token signing is replaced by the vault
                    // handler registered below. Certificates remain available
                    // to auxiliary protocol JWT generators.
                    // OpenIddict requires one asymmetric credential during
                    // options validation; this bootstrap key is never selected
                    // by GenerateTokenContext and is removed from JWKS by the
                    // vault discovery handler.
                    server.AddEphemeralSigningKey();
                    // Auxiliary JWTs (logout/JARM/SSF/CIBA) still use the
                    // protocol credential resolved above. Publish their
                    // public halves alongside the vault keys without making
                    // them the OpenIddict token-signing choice.
                    foreach (var certificate in certificateMaterial.Signing)
                    {
                        server.AddSigningKey(new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate));
                    }
                    if (isDevelopmentEnvironment)
                    {
                        server.AddSigningKey(auxiliarySigningCredentials.Key);
                    }
                }
                else if (certificateMaterial.Signing.Count > 0)
                {
                    foreach (var certificate in certificateMaterial.Signing)
                    {
                        server.AddSigningCertificate(certificate);
                    }
                }
                else if (isDevelopmentEnvironment)
                {
                    server.AddDevelopmentSigningCertificate();
                    // Publish the same ephemeral public key used to sign JARM,
                    // SSF/CAEP, logout_token and CIBA JWTs. Without this extra
                    // signing key those JWTs worked only in-process and could
                    // not be verified through the advertised JWKS endpoint.
                    server.AddSigningKey(auxiliarySigningCredentials.Key);
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

                if (vaultOptions.ManageSigningKeys)
                {
                    server.AddEventHandler(Vault.VaultSigningCredentialsHandler.Descriptor);
                    server.AddEventHandler(Vault.VaultJsonWebKeySetHandler.Descriptor);
                }

                if (certificateMaterial.Encryption.Count > 0)
                {
                    foreach (var certificate in certificateMaterial.Encryption)
                    {
                        server.AddEncryptionCertificate(certificate);
                    }
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
                // Discovery customizations. Logout capabilities are advertised
                // only when their provider-neutral dispatcher is enabled. The
                // application cookie and ID Tokens carry the same opaque OIDC
                // sid, so session-specific support follows each dispatcher
                // flag. Every other previously-advertised flag
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
                        // Backchannel logout (OIDC Back-Channel Logout 1.0,
                        // item 3.2 [L1]): advertised as supported ONLY when the
                        // STS is configured to distribute logout_tokens to RPs
                        // (BackchannelLogoutOptions.Enabled). When disabled,
                        // publish `false` so OIDC clients natively skip the
                        // flow instead of probing.
                        context.Metadata["backchannel_logout_supported"] =
                            JsonValue.Create(options.BackchannelLogout.Enabled);
                        context.Metadata["backchannel_logout_session_supported"] =
                            JsonValue.Create(options.BackchannelLogout.Enabled);

                        // Frontchannel logout (OIDC Front-Channel Logout 1.0):
                        // one-time iframe fan-out to registered RP logout URIs.
                        context.Metadata["frontchannel_logout_supported"] =
                            JsonValue.Create(options.FrontchannelLogout.Enabled);
                        context.Metadata["frontchannel_logout_session_supported"] =
                            JsonValue.Create(options.FrontchannelLogout.Enabled);

                        // mTLS sender-constrained access tokens (RFC 8705, item
                        // 3.4). Advertised ONLY when Mtls.Enabled — the host
                        // must be configured for client certificates at the TLS
                        // layer for this to be true (see MtlsOptions XML doc).
                        // OpenIddict 7.6 does not advertise this automatically,
                        // so we publish it here to match the actual capability.
                        context.Metadata["tls_client_certificate_bound_access_tokens"] =
                            JsonValue.Create(options.Mtls.Enabled);

                        // OpenIddict attaches `iss` to every redirectable
                        // authorization response (RFC 9207). Publish the
                        // matching capability bit explicitly for FAPI clients.
                        context.Metadata["authorization_response_iss_parameter_supported"] =
                            JsonValue.Create(true);

                        // Note: request_uri_parameter_supported and
                        // require_pushed_authorization_requests are published
                        // by OpenIddict itself based on the server options
                        // (RequirePushedAuthorizationRequests above toggles the
                        // latter). The PAR endpoint
                        // (pushed_authorization_request_endpoint) is always
                        // advertised once the endpoint URI is registered.

                        // DPoP (RFC 9449, item 3.1). Advertised ONLY when
                        // Dpop.Enabled: the STS validates DPoP proofs and
                        // sender-constrains tokens. The signing-algorithms list
                        // matches what DpopProofValidator accepts (EC P-256 and
                        // RSA). OpenIddict 7.6 omits this entirely (no DPoP
                        // support), so DiscoveryTests previously pinned its
                        // absence — that assertion is updated alongside this.
                        if (options.Dpop.Enabled)
                        {
                            // dpop_signing_alg_values_supported is a JSON array
                            // of JWS alg names the AS accepts in DPoP proofs.
                            context.Metadata["dpop_signing_alg_values_supported"] =
                                System.Text.Json.JsonSerializer.SerializeToNode(
                                    new[] { "ES256", "RS256" });
                        }

                        if (options.Jarm.Enabled)
                        {
                            // JARM final section 4 defines this metadata value.
                            context.Metadata["authorization_signing_alg_values_supported"] =
                                System.Text.Json.JsonSerializer.SerializeToNode(
                                    new[] { auxiliarySigningCredentials.Algorithm });

                            // When JWE encryption is configured, advertise the
                            // key-management and content-encryption algorithms
                            // (FAPI 2.0 Advancing Profile signed+encrypted mode).
                            if (options.Jarm.Encryption.Enabled)
                            {
                                context.Metadata["authorization_encryption_alg_values_supported"] =
                                    System.Text.Json.JsonSerializer.SerializeToNode(
                                        new[] { options.Jarm.Encryption.KeyManagementAlgorithm });
                                context.Metadata["authorization_encryption_enc_values_supported"] =
                                    System.Text.Json.JsonSerializer.SerializeToNode(
                                        new[] { options.Jarm.Encryption.ContentEncryptionAlgorithm });
                            }
                        }

                        // JAR (RFC 9101): advertise request object support and
                        // the accepted signing algorithms when enabled.
                        if (options.Jar.Enabled)
                        {
                            context.Metadata["request_parameter_supported"] =
                                JsonValue.Create(true);
                            context.Metadata["request_object_signing_alg_values_supported"] =
                                System.Text.Json.JsonSerializer.SerializeToNode(
                                    options.Jar.AllowedSigningAlgorithms
                                        .OrderBy(a => a, StringComparer.Ordinal).ToArray());
                        }

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
                      .EnableStatusCodePagesIntegration()
                      .SuppressJsonResponseIndentation();

                // In Development with HTTPS (same port as the legacy STS:
                // https://localhost:5001), no transport security override needed.
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
                if (options.Dpop.Enabled)
                {
                    validation.AddEventHandler(
                        Dpop.ExtractDpopValidationToken.Descriptor);
                    validation.AddEventHandler(
                        Dpop.ValidateDpopApiAccessTokenProof.Descriptor);
                }
            });

        services.AddScoped<IIdentityUserSessionRevoker,
            OpenIddictIdentityUserSessionRevoker>();
        services.AddScoped<IIdentityAccountLifecycleService,
            IdentityAccountLifecycleService>();
        services.AddScoped<ICredentialMutationSecurityCoordinator,
            CredentialMutationSecurityCoordinator>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IAssuranceLevelResolver, AmrBasedAssuranceLevelResolver>();
        services.AddScoped<IAccountSelfService, AccountSelfService>();
        services.AddScoped<IAccountAccessService, AccountAccessService>();
        services.AddScoped<IAccountExternalIdentityService,
            AspNetCoreIdentityAccountExternalIdentityService>();
        services.AddScoped<IAccountTwoFactorService,
            AspNetCoreIdentityAccountTwoFactorService>();
        services.AddScoped<IInteractiveSignInService,
            AspNetCoreIdentityInteractiveSignInService>();
        services.AddScoped<IAccountOnboardingService,
            AspNetCoreIdentityAccountOnboardingService>();
        services.AddScoped<IAuthorizationConsentService,
            OpenIddictAuthorizationConsentService>();
        services.AddScoped<OpenIddictDeviceAuthorizationContextService>();
        services.AddScoped<IDeviceAuthorizationContextService>(provider =>
            provider.GetRequiredService<OpenIddictDeviceAuthorizationContextService>());
        services.AddScoped<IExternalSignInService,
            AspNetCoreIdentityExternalSignInService>();
        services.AddScoped<AspNetCoreIdentityPasskeyService>();
        services.AddScoped<IAccountPasskeyService>(services =>
            services.GetRequiredService<AspNetCoreIdentityPasskeyService>());
        services.AddScoped<IPasskeyAuthenticationService>(services =>
            services.GetRequiredService<AspNetCoreIdentityPasskeyService>());

        // ---- OIDC Back-Channel Logout 1.0 (item 3.2 [L1]) ----
        // OpenIddict 7.6 only consumes logout_tokens; the STS generates them
        // (LogoutTokenGenerator) and distributes them (BackchannelLogoutDistributor).
        // The IBackchannelLogoutDispatcher is ALWAYS registered (so the
        // AuthorizationController can take it as a hard dependency): when the
        // feature is disabled, a no-op implementation is used, so logout just
        // skips RP fan-out. The real generator+distributor+HttpClient are only
        // wired when Enabled, to avoid creating an HttpClient that is never used.
        if (options.BackchannelLogout.Enabled)
        {
            var issuer = string.IsNullOrWhiteSpace(options.Issuer)
                ? "https://localhost/"
                : options.Issuer;

            services.AddSingleton(new Logout.LogoutTokenGenerator(
                auxiliarySigningCredentials, issuer));
            services.AddHttpClient<Logout.IBackchannelLogoutDispatcher, Logout.BackchannelLogoutDistributor>()
                .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);
        }
        else
        {
            services.AddSingleton<Logout.IBackchannelLogoutDispatcher, Logout.NullBackchannelLogoutDispatcher>();
        }

        // ---- OIDC Front-Channel Logout 1.0 ----
        // RP URI lists are resolved from canonical application metadata before
        // local sign-out and kept behind an opaque, one-time, two-minute cache
        // key while OpenIddict completes the end-session response.
        if (options.FrontchannelLogout.Enabled)
        {
            services.AddScoped<Logout.IFrontchannelLogoutDispatcher,
                Logout.FrontchannelLogoutDispatcher>();
        }
        else
        {
            services.AddSingleton<Logout.IFrontchannelLogoutDispatcher,
                Logout.NullFrontchannelLogoutDispatcher>();
        }

        // ---- DPoP (RFC 9449, item 3.1) ----
        // The proof validator is registered unconditionally (cheap; it only
        // runs when invoked from AuthorizationController.Exchange AND the
        // option is enabled). The distributed replay cache and nonce store use
        // IDistributedCache (registered above as AddDistributedMemoryCache;
        // swap for Redis when multi-replica).
        services.AddSingleton<Dpop.DistributedDpopReplayCache>();
        services.AddSingleton(sp => new Dpop.DatabaseDpopReplayCache(
            sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            TimeProvider.System));
        services.AddSingleton<Dpop.IDpopReplayCache, Dpop.RollingDpopReplayCache>();
        services.AddSingleton(sp => new Dpop.DpopProofValidator(
            TimeProvider.System,
            Microsoft.Extensions.Logging.LoggerFactoryExtensions.CreateLogger<Dpop.DpopProofValidator>(
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()),
            sp.GetService<Dpop.IDpopReplayCache>()));

        // Distributed, partition-bound DPoP nonce (RFC 9449 §8). The cache
        // payload is encrypted through IKeyVault when enabled, so a shared
        // Redis/SQL cache does not expose nonce material at rest.
        services.AddSingleton<Dpop.IDpopNonceStore>(sp =>
            sp.GetRequiredService<Dpop.DistributedDpopNonceStore>());

        // Concrete registration is separate so tests and deployment-specific
        // composition roots can resolve the implementation directly.
        services.AddSingleton(sp => new Dpop.DistributedDpopNonceStore(
            sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            timeProvider: TimeProvider.System,
            keyVault: sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));

        if (options.Jarm.Enabled)
        {
            var issuer = string.IsNullOrWhiteSpace(options.Issuer)
                ? "https://localhost/"
                : options.Issuer;

            services.AddSingleton(new Jarm.JarmResponseGenerator(
                auxiliarySigningCredentials,
                issuer,
                TimeSpan.FromSeconds(options.Jarm.LifetimeSeconds)));
            services.AddScoped<Jarm.IJarmClientEncryptionCredentialsResolver,
                Jarm.JarmClientEncryptionCredentialsResolver>();
        }

        if (options.SharedSignals.Enabled)
        {
            services.AddSingleton(new SharedSignals.CaepEventGenerator(
                auxiliarySigningCredentials, options.Issuer!));
            services.AddHttpClient<SharedSignals.ISharedSignalsDispatcher,
                    SharedSignals.SharedSignalsPushDispatcher>()
                .ConfigureHttpClient(client =>
                    client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);

            // ISecurityEventTrigger adapter: translates credential/device
            // change calls from the account/management/SCIM surfaces into
            // SSF dispatcher calls. Real implementation only when SSF is on.
            services.AddScoped<ISecurityEventTrigger,
                SharedSignals.SharedSignalsSecurityEventTrigger>();

            // Stream-management store (RFC 8933/8934). Always available when
            // SSF is on so the push dispatcher can route poll streams to the
            // persistent queue even if the REST API is not exposed.
            services.AddScoped<SharedSignals.ISsfStreamStore, SharedSignals.SsfStreamStore>();
            services.AddSingleton<SharedSignals.ISsfSubscriptionMatcher,
                SharedSignals.SsfSubscriptionMatcher>();
        }
        else
        {
            services.AddSingleton<SharedSignals.ISharedSignalsDispatcher,
                SharedSignals.NullSharedSignalsDispatcher>();
            // Always resolvable: account/management/SCIM services take this as
            // a hard dependency regardless of the SSF feature flag.
            services.AddSingleton<ISecurityEventTrigger,
                SharedSignals.NullSecurityEventTrigger>();
        }

        // ---- Stream-management REST surface (RFC 8933, opt-in) ----
        // The /ssf/streams + /ssf/events controllers and the authorization
        // policy are registered only when the operator opts in. The store is
        // registered above (under SSF Enabled) so push-vs-poll routing works.
        if (options.SharedSignals is { Enabled: true, StreamManagementEnabled: true })
        {
            services.AddHttpClient("ssf-verification")
                .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(7))
                .UseSafeOutboundHttp(options.OutboundHttp);
            services.AddScoped<IAuthorizationHandler, Controllers.SsfScopeHandler>();
            services.AddAuthorizationBuilder()
                .AddPolicy("sufficit-ssf-transmitter", policy =>
                {
                    policy.AuthenticationSchemes.Add(
                        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new Controllers.SsfScopeRequirement(options.SharedSignals.RequiredScope));
                });
        }

        // ---- OpenID Connect CIBA Core 1.0 ----
        // The pending-request store is distributed (IDistributedCache-backed)
        // so CIBA works across replicas and survives restarts. The in-memory
        // fallback is still used when IDistributedCache is the local memory
        // cache (single-node default). The CibaController and the CIBA poll
        // branch only run when the option is enabled, but the store is always
        // available so the dependency resolves regardless.
        services.AddSingleton(sp => new Ciba.DistributedCibaPendingRequestStore(
            sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            TimeProvider.System,
            sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));
        services.AddSingleton(sp => new Ciba.DatabaseCibaPendingRequestStore(
            sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            TimeProvider.System));
        services.AddSingleton<Ciba.ICibaPendingRequestStore,
            Ciba.RollingCibaPendingRequestStore>();
        services.AddScoped<Ciba.ICibaClientPolicy, Ciba.CibaClientPolicy>();

        // Always resolvable so the disabled controller can return a deliberate
        // 404 instead of failing activation with a DI 500. The feature gate
        // prevents any generator method from running while CIBA is disabled.
        var cibaIssuer = string.IsNullOrWhiteSpace(options.Issuer)
            ? "https://localhost/"
            : options.Issuer;
        var cibaAccessTokenMinutes =
            options.Tokens.AccessTokenLifetimeMinutes ?? 60;
        services.AddSingleton(new Ciba.CibaAccessTokenGenerator(
            auxiliarySigningCredentials,
            cibaIssuer,
            cibaAccessTokenMinutes));

        return services;
    }

    private static void ValidateAdvancedProtocolOptions(SufficitIdentityOptions options)
    {
        if (options.Mtls.Enabled
            && options.Mtls.DeploymentMode == MtlsDeploymentMode.Unattested)
        {
            throw new InvalidOperationException(
                "mTLS is enabled without Sufficit:Identity:Mtls:DeploymentMode attestation.");
        }

        if (options.Fapi2.Enabled)
        {
            if (options.Fapi2.ClientIds.Count == 0)
                throw new InvalidOperationException(
                    "FAPI 2.0 is enabled but Sufficit:Identity:Fapi2:ClientIds is empty.");
            if (options.Fapi2.AuthorizationCodeLifetimeSeconds is < 1 or > 60)
                throw new InvalidOperationException(
                    "FAPI 2.0 authorization-code lifetime must be between 1 and 60 seconds.");
            if (options.Fapi2.PushedAuthorizationRequestLifetimeSeconds is < 1 or >= 600)
                throw new InvalidOperationException(
                    "FAPI 2.0 PAR request_uri lifetime must be between 1 and 599 seconds.");
            if (options.Fapi2.SenderConstraint == Fapi2SenderConstraint.Dpop &&
                !options.Dpop.Enabled)
                throw new InvalidOperationException(
                    "FAPI 2.0 SenderConstraint=DPoP requires Sufficit:Identity:Dpop:Enabled=true.");
            if (options.Fapi2.SenderConstraint == Fapi2SenderConstraint.Mtls &&
                !options.Mtls.Enabled)
                throw new InvalidOperationException(
                    "FAPI 2.0 SenderConstraint=mTLS requires Sufficit:Identity:Mtls:Enabled=true.");
            if (options.Fapi2.SenderConstraint == Fapi2SenderConstraint.Mtls)
            {
                var missingBindings = options.Fapi2.ClientIds
                    .Where(clientId =>
                        !options.Mtls.ClientCertificateThumbprints.TryGetValue(
                            clientId,
                            out var thumbprints)
                        || thumbprints.Count == 0)
                    .ToArray();
                if (missingBindings.Length > 0)
                    throw new InvalidOperationException(
                        "FAPI mTLS clients require certificate bindings: "
                        + string.Join(", ", missingBindings));
            }
        }

        if (options.Jarm.Enabled)
        {
            if (options.Jarm.LifetimeSeconds is < 1 or > 600)
                throw new InvalidOperationException(
                    "JARM response lifetime must be between 1 and 600 seconds.");
            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
                throw new InvalidOperationException(
                    "JARM requires an explicit absolute Sufficit:Identity:Issuer.");
        }

        if (options.SharedSignals.Enabled)
        {
            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) ||
                issuer.Scheme != Uri.UriSchemeHttps)
                throw new InvalidOperationException(
                    "SSF/CAEP requires an explicit HTTPS Sufficit:Identity:Issuer.");
            if (issuer.AbsolutePath != "/")
                throw new InvalidOperationException(
                    "This SSF/CAEP transmitter currently requires an issuer without a path component.");

            var duplicate = options.SharedSignals.Receivers
                .Where(receiver => !string.IsNullOrWhiteSpace(receiver.Id))
                .GroupBy(receiver => receiver.Id, StringComparer.Ordinal)
                .FirstOrDefault(group => group.Count() > 1);
            if (duplicate is not null)
                throw new InvalidOperationException(
                    $"SSF/CAEP receiver id '{duplicate.Key}' is duplicated.");

            foreach (var receiver in options.SharedSignals.Receivers)
            {
                if (string.IsNullOrWhiteSpace(receiver.Id) ||
                    string.IsNullOrWhiteSpace(receiver.Audience) ||
                    !Uri.TryCreate(receiver.Endpoint, UriKind.Absolute, out var endpoint) ||
                    endpoint.Scheme != Uri.UriSchemeHttps ||
                    endpoint.Fragment.Length != 0)
                    throw new InvalidOperationException(
                        "Each SSF/CAEP receiver requires an id, audience and fragment-free HTTPS endpoint.");
            }
        }
    }

    /// <summary>
    /// Resolves the signing credentials used by auxiliary protocol JWTs.
    /// Reuses the STS signing certificate when configured; otherwise falls
    /// back to one ephemeral ECDSA P-256 key for Development/tests. The caller
    /// also registers that development key with OpenIddict so it is published
    /// by the normal JWKS endpoint.
    /// </summary>
    private static Microsoft.IdentityModel.Tokens.SigningCredentials ResolveProtocolSigningCredentials(
        X509Certificate2? certificate,
        bool isDevelopmentEnvironment)
    {
        if (certificate is not null)
        {
            var algorithm = certificate.GetECDsaPrivateKey() is not null
                ? Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256
                : certificate.GetRSAPrivateKey() is not null
                    ? Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256
                    : throw new InvalidOperationException(
                        "The configured signing certificate must contain an RSA or ECDSA private key.");
            return new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate),
                algorithm);
        }

        if (isDevelopmentEnvironment)
        {
            // Ephemeral ECDSA P-256 key — fine for tests/dev where the issuer
            // and validator are the same process. Never used in production.
            var ecdsa = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            return new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.ECDsaSecurityKey(ecdsa)
                {
                    KeyId = Guid.NewGuid().ToString("N"),
                },
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256);
        }

        throw new InvalidOperationException(
            "No signing certificate is configured for protocol JWTs. " +
            "Production deployments require Sufficit:Identity:Certificates:SigningPath " +
            "(the logout_token is signed with the same key as access tokens).");
    }

    private static CertificateMaterial LoadCertificateMaterial(
        CertificatesOptions options,
        bool isDevelopmentEnvironment,
        ISecretStore secretStore)
    {
        var signingPassword = ResolveSecret(
            secretStore,
            "identity/certificates/signing-password");
        var encryptionPassword = ResolveSecret(
            secretStore,
            "identity/certificates/encryption-password");
        var signing = LoadCertificateSet(
            options.SigningPath,
            options.SigningPaths,
            signingPassword,
            "signing",
            options);
        var encryption = LoadCertificateSet(
            options.EncryptionPath,
            options.EncryptionPaths,
            encryptionPassword,
            "encryption",
            options);

        if (!isDevelopmentEnvironment
            && (signing.Count == 0 || encryption.Count == 0))
        {
            throw new InvalidOperationException(
                "Production deployments require persistent signing and encryption certificates.");
        }

        if (options.RequirePurposeSeparation
            && signing.Count > 0
            && encryption.Count > 0
            && string.Equals(
                signing[0].Thumbprint,
                encryption[0].Thumbprint,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Certificate purpose separation requires different active signing and encryption certificates.");
        }

        return new CertificateMaterial(signing, encryption);
    }

    private static IReadOnlyList<X509Certificate2> LoadCertificateSet(
        string? primaryPath,
        IEnumerable<string>? overlapPaths,
        string? password,
        string purpose,
        CertificatesOptions options)
    {
        var paths = new[] { primaryPath }
            .Concat(overlapPaths ?? [])
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path!.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var certificates = new List<X509Certificate2>(paths.Length);
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                path,
                password);
            ValidateCertificate(certificate, purpose, options);
            if (!thumbprints.Add(certificate.Thumbprint))
            {
                certificate.Dispose();
                continue;
            }

            certificates.Add(certificate);
        }

        return certificates;
    }

    private static void ValidateCertificate(
        X509Certificate2? certificate,
        string purpose,
        CertificatesOptions options)
    {
        if (certificate is null)
        {
            return;
        }

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"The configured {purpose} certificate does not contain a private key.");
        }

        var now = DateTimeOffset.UtcNow;
        if (certificate.NotBefore.ToUniversalTime() > now.UtcDateTime
            || certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime)
        {
            throw new InvalidOperationException(
                $"The configured {purpose} certificate is not currently valid.");
        }

        var minimumLifetime = TimeSpan.FromDays(
            Math.Clamp(options.MinimumRemainingLifetimeDays, 1, 365));
        if (certificate.NotAfter.ToUniversalTime() - now.UtcDateTime < minimumLifetime)
        {
            var message =
                $"The configured {purpose} certificate expires at {certificate.NotAfter:u}, inside the {minimumLifetime.TotalDays:0}-day rotation window.";
            if (options.FailOnExpiringCertificate)
            {
                throw new InvalidOperationException(message);
            }

            Console.Error.WriteLine("[WARNING] " + message);
        }
    }

    private sealed record CertificateMaterial(
        IReadOnlyList<X509Certificate2> Signing,
        IReadOnlyList<X509Certificate2> Encryption)
    {
        public X509Certificate2? PrimarySigning => Signing.FirstOrDefault();
    }

    private static string? ResolveSecret(
        ISecretStore secretStore,
        string logicalName)
    {
        return secretStore.GetSecretAsync(logicalName)
            .GetAwaiter()
            .GetResult();
    }

    /// <summary>
    /// Registers external login providers (Google, GitHub, etc) from the
    /// <c>Sufficit:Identity:ExternalProviders</c> configuration section.
    /// Each provider is only registered if Enabled=true and credentials
    /// are present (ClientId + ClientSecret).
    /// </summary>
    private static void AddExternalProviders(
        AuthenticationBuilder builder,
        IConfiguration configuration,
        ISecretStore secretStore)
    {
        var section = configuration.GetSection("Sufficit:Identity:ExternalProviders");
        if (section is null) return;

        // Google
        var google = section.GetSection("Google");
        var googleClientId = ResolveSecret(
            secretStore,
            "identity/external-providers/google/client-id");
        var googleClientSecret = ResolveSecret(
            secretStore,
            "identity/external-providers/google/client-secret");
        if (google.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(googleClientId)
            && !string.IsNullOrWhiteSpace(googleClientSecret))
        {
            builder.AddGoogle(options =>
            {
                ConfigureExternalProvider(options);
                options.ClientId = googleClientId!;
                options.ClientSecret = googleClientSecret!;
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
        var githubClientId = ResolveSecret(
            secretStore,
            "identity/external-providers/github/client-id");
        var githubClientSecret = ResolveSecret(
            secretStore,
            "identity/external-providers/github/client-secret");
        if (github.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(githubClientId)
            && !string.IsNullOrWhiteSpace(githubClientSecret))
        {
            builder.AddGitHub(options =>
            {
                ConfigureExternalProvider(options);
                options.ClientId = githubClientId!;
                options.ClientSecret = githubClientSecret!;
                options.Scope.Add("user:email");
                // Use the ASP.NET Core default (/signin-github).
                // Surface GitHub's email verification so the UI external-login
                // flow only auto-confirms accounts with a provider-verified email
                // (M5 fix, eval M5 — matches the Google mapping above). GitHub's
                // /user endpoint does not expose email_verified directly, but the
                // user:email scope's primary email response does; the AspNet.Security
                // provider maps the verified flag onto "email_verified" when present.
                options.ClaimActions.MapJsonKey("email_verified", "email_verified", "boolean");
            });
        }

        // Facebook
        var facebook = section.GetSection("Facebook");
        var facebookClientId = ResolveSecret(
            secretStore,
            "identity/external-providers/facebook/client-id");
        var facebookSecret = ResolveSecret(
            secretStore,
            "identity/external-providers/facebook/client-secret");
        if (facebook.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(facebookClientId)
            && !string.IsNullOrWhiteSpace(facebookSecret))
        {
            builder.AddFacebook(options =>
            {
                ConfigureExternalProvider(options);
                options.ClientId = facebookClientId!;
                options.ClientSecret = facebookSecret!;

                // Force the Meta Graph API version to v22.0 (the package's
                // built-in default of v14.0 is deprecated and Meta now rejects
                // requests built against it with the cryptic
                // "app is unavailable / needs at least one supported permission"
                // error, even when the permissions are correctly configured
                // with Advanced Access in the App Dashboard).
                options.AuthorizationEndpoint = "https://www.facebook.com/v22.0/dialog/oauth";
                options.TokenEndpoint = "https://graph.facebook.com/v22.0/oauth/access_token";
                options.UserInformationEndpoint = "https://graph.facebook.com/v22.0/me?fields=id,name,email";

                // Surface Facebook's email verification (M5 fix, eval M5 —
                // matches the Google/GitHub mappings). Meta's Graph API exposes
                // the verified flag as the "verified" boolean field on the user
                // object; map it onto the same "email_verified" claim the
                // external-login flow reads, so a provider-verified email yields
                // EmailConfirmed=true.
                options.ClaimActions.MapJsonKey("email_verified", "verified", "boolean");

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

    internal static string ApplyDatabaseConnectionPolicy(
        string connectionString,
        DatabaseConnectionPoolOptions options,
        bool tolerateInvalidDevelopmentValue = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(options);

        try
        {
            var builder = new MySqlConnectionStringBuilder(connectionString);
            var maximumSize = Math.Clamp(options.MaximumSize, 1, 10_000);
            var minimumSize = Math.Clamp(options.MinimumSize, 0, maximumSize);

            builder.Pooling = true;
            builder.MaximumPoolSize = (uint)maximumSize;
            builder.MinimumPoolSize = (uint)minimumSize;
            builder.ConnectionTimeout = (uint)Math.Clamp(
                options.ConnectionTimeoutSeconds,
                1,
                300);
            builder.DefaultCommandTimeout = (uint)Math.Clamp(
                options.CommandTimeoutSeconds,
                1,
                3_600);
            builder.ConnectionLifeTime = (uint)Math.Clamp(
                options.ConnectionLifetimeSeconds,
                0,
                86_400);
            builder.ConnectionIdleTimeout = (uint)Math.Clamp(
                options.ConnectionIdleTimeoutSeconds,
                0,
                3_600);
            builder.ConnectionReset = options.ResetOnCheckout;
            builder.ApplicationName = string.IsNullOrWhiteSpace(options.ApplicationName)
                ? "Sufficit.Identity"
                : options.ApplicationName.Trim()[..Math.Min(
                    options.ApplicationName.Trim().Length,
                    64)];

            return builder.ConnectionString;
        }
        catch (ArgumentException) when (tolerateInvalidDevelopmentValue)
        {
            // Test hosts replace the provider registration after composing the
            // STS and historically use the sentinel value "unused". Preserve
            // that development-only seam; production still fails fast.
            return connectionString;
        }
    }

    /// <summary>
    /// Applies the common browser contract for all remote OAuth handlers.
    ///
    /// The correlation ticket is created before the browser leaves Identity
    /// and is consumed by the provider callback.  Keeping it explicitly
    /// HTTPS-only and <c>SameSite=None</c> makes the contract deterministic
    /// behind the nginx TLS terminator (and for providers that use a
    /// cross-site callback).  A failed/expired ticket must not become a 500:
    /// the default handler leaves the caller in an OIDC retry loop.  Redirect
    /// to the login page with the original local return URL so the user can
    /// start a fresh challenge instead.
    /// </summary>
    private static void ConfigureExternalProvider(OAuthOptions options)
    {
        options.CorrelationCookie.SameSite = SameSiteMode.None;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.HttpOnly = true;

        options.Events.OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("Sufficit.Identity.ExternalAuthentication");
            var isCorrelationFailure = context.Failure?.Message?.Contains(
                "Correlation failed",
                StringComparison.OrdinalIgnoreCase) == true;

            logger.LogWarning(
                context.Failure,
                "External authentication failed for {Scheme} at {Path}. "
                    + "CorrelationFailure={CorrelationFailure}; returning to login.",
                context.Scheme.Name,
                context.HttpContext.Request.Path,
                isCorrelationFailure);

            var returnUrl = ExtractLocalReturnUrl(
                context.Properties?.RedirectUri);
            var error = isCorrelationFailure
                ? "external_correlation_failed"
                : "external_callback_unavailable";
            var location = QueryHelpers.AddQueryString(
                "/account/login",
                new Dictionary<string, string?>
                {
                    ["error"] = error,
                    ["returnUrl"] = returnUrl,
                });

            context.HandleResponse();
            context.Response.Redirect(location);
            return Task.CompletedTask;
        };
    }

    private static string ExtractLocalReturnUrl(string? redirectUri)
    {
        if (string.IsNullOrWhiteSpace(redirectUri)
            || !redirectUri.StartsWith("/", StringComparison.Ordinal)
            || redirectUri.StartsWith("//", StringComparison.Ordinal))
        {
            return "/";
        }

        var queryStart = redirectUri.IndexOf('?');
        if (queryStart < 0 || queryStart == redirectUri.Length - 1)
        {
            return "/";
        }

        var query = QueryHelpers.ParseQuery(redirectUri[(queryStart + 1)..]);
        var returnUrl = query.TryGetValue("returnUrl", out var value)
            ? value.ToString()
            : null;
        return LocalUrlValidator.EnsureLocal(returnUrl);
    }
}
