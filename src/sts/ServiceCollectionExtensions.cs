using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
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
using Sufficit.Identity.STS.Integrations;
using Sufficit.Identity.Vault;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// DI extensions that wire up the Sufficit Identity STS server
/// (ASP.NET Core Identity + OpenIddict server/validation).
/// </summary>
public static partial class ServiceCollectionExtensions
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
        services.AddOptions<Sufficit.Identity.Core.Networking.TrustedProxyOptions>()
            .Bind(configuration.GetSection(configurationSection));
        services.TryAddSingleton<Sufficit.Identity.Core.Networking.TrustedProxySnapshotStore>();
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
        services.TryAddSingleton<IClientCredentialSecretHasher,
            ClientCredentialSecretHasher>();

        var startupSecretStore = secretStore ?? new EnvironmentSecretStore();
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
        if (vaultOptions.ManageSigningKeys)
        {
            var longestTokenLifetimeSeconds = Math.Max(
                options.Tokens.RefreshTokenLifetimeDays * 86_400,
                Math.Max(
                    (options.Tokens.AccessTokenLifetimeMinutes ?? 60) * 60,
                    (options.Tokens.IdentityTokenLifetimeMinutes ?? 20) * 60));
            if (vaultOptions.SigningKeyOverlapSeconds
                < Math.Ceiling(longestTokenLifetimeSeconds))
            {
                throw new InvalidOperationException(
                    "Sufficit:Vault:SigningKeyOverlapSeconds must cover the longest configured token lifetime so retiring kids remain verifiable.");
            }
        }
        ValidateAdvancedProtocolOptions(options);
        options.HumanVerification.Validate();
        // The shared DCR initial access token gave no attribution and could not
        // be revoked per registrant. Refuse to start while it is configured, so
        // a deployment learns about the change instead of registrations
        // failing with invalid_token.
        if (!string.IsNullOrWhiteSpace(ResolveSecret(
                startupSecretStore,
                "identity/dcr/initial-access-token")))
        {
            throw new InvalidOperationException(
                "The shared DCR initial access token (secret identity/dcr/initial-access-token, "
                + "Sufficit:Identity:Mcp:Dcr:InitialAccessToken) is no longer supported. Remove it "
                + "and issue one initial access token per registrant through the management API "
                + "(POST api/registration-tokens).");
        }
        services.AddSingleton(options);
        services.TryAddSingleton<Sufficit.Identity.Core.Services.DcrInitialAccessTokenStore>();
        services.Replace(ServiceDescriptor.Singleton<
            IIdentityRuntimeCapabilityCatalog>(
            new SufficitIdentityRuntimeCapabilityCatalog(options)));
        services.AddSingleton(options.HumanVerification);
        services.AddSingleton(options.TwoFactor);
        services.AddSingleton(options.Branding);
        services.AddSingleton(options.AuthenticationContext);
        services.AddSingleton<IAuthenticationContextClassMapper,
            ConfigurableAuthenticationContextClassMapper>();
        services.AddSingleton(options.Passkeys);
        services.AddSingleton(options.CredentialMutations);
        services.AddSingleton(options.PersonalTokens);
        services.AddSingleton(options.Fapi2);
        services.AddSingleton(options.Mtls);
        services.AddSingleton(options.Jar);
        services.AddSingleton(options.Ciba);
        services.AddSingleton(options.TokenPruning);
        services.AddSingleton(options.SharedSignals);
        services.AddSingleton(options.OutboundHttp);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IProductionPostureContributor,
                Security.StsProductionPostureContributor>());
        services.TryAddScoped<IProductionPostureAdvisories,
            Security.ProductionPostureAdvisories>();
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
        services.AddSingleton(new Tokens.AccessTokenFormatPolicy(
            options.Tokens));
        services.AddSingleton<IPersonalTokenIssuancePolicy, PersonalTokenIssuancePolicy>();
        services.AddSingleton<ISubjectTokenProvenancePolicy, SubjectTokenProvenancePolicy>();
        services.AddScoped<IAuthenticationContextAccessor, AuthenticationContextAccessor>();
        services.AddSingleton<IAuthenticationContextProjector, AuthenticationContextProjector>();
        services.AddSingleton<Mtls.IMtlsCertificateChainValidator,
            Mtls.SystemMtlsCertificateChainValidator>();
        services.AddScoped<Mtls.IMtlsClientCertificatePolicy,
            Mtls.MtlsClientCertificatePolicy>();
        services.AddSingleton<IdentityMetricsRuntimeState>();
        services.AddSingleton<IdentityUsageMetricChannel>();
        services.AddSingleton<IIdentityUsageMetricSink>(provider =>
            provider.GetRequiredService<IdentityUsageMetricChannel>());
        services.AddSafeHttpClient(
            "identity-metrics-export", options.OutboundHttp);
        services.AddSafeHttpClient(
                "jar-remote-jwks",
                options.OutboundHttp)
            .ConfigureHttpClient(client =>
                client.Timeout = Timeout.InfiniteTimeSpan);
        services.AddSingleton<Jar.RemoteJwksProvider>();
        services.AddScoped<Jar.IJarSigningKeyResolver,
            Jar.JarSigningKeyResolver>();
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
        var certificateMaterial = IdentityCertificateMaterial.Load(
            options.Certificates,
            isDevelopmentEnvironment,
            ResolveSecret(
                startupSecretStore,
                "identity/certificates/signing-password"),
            ResolveSecret(
                startupSecretStore,
                "identity/certificates/encryption-password"));
        var auxiliarySigningCredentials =
            IdentityCertificateMaterial.ResolveProtocolSigningCredentials(
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
        {
            services.AddHostedService<IdentityUsageMetricsWorker>();
            // Prunes dead OpenIddict tokens/orphaned authorizations past
            // Sufficit:Identity:TokenPruning:RetentionDays. Registered only
            // for real connection strings for the same reason as the metrics
            // writer above: the shared in-memory SQLite connection used by
            // integration hosts races background writers.
            if (options.TokenPruning.RunInWebHost)
                services.AddHostedService<Tokens.OpenIddictPruningWorker>();
            // MariaDB rejects the LIMIT-in-subquery DELETE that the EF Core
            // bulk path emits for OpenIddict's PruneAsync batches (the same
            // dialect gap the audit retention worker hit in production), so
            // real deployments force the transactional batch path instead.
            // SufficitOpenIddictTokenStore keeps authorization-chain revocation
            // set-based independently of this pruning compatibility switch.
            services.AddOptions<OpenIddict.EntityFrameworkCore.OpenIddictEntityFrameworkCoreOptions>()
                .Configure(entityFrameworkCore => entityFrameworkCore.DisableBulkOperations = true);
        }
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
        // L8/S6 hardening: encrypt DP keys at rest with the vault's dedicated
        // protection certificate. It must be separate from token signing.
        // A bounded migration option can retain old signing certificates as
        // decrypt-only keys while the DP ring naturally rotates.
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

        if (vaultOptions.Enabled
            && !string.IsNullOrWhiteSpace(vaultOptions.CertificatePath))
        {
            var vaultProtectionCertificate =
                VaultKeyEncryptionCertificate.Load(
                    vaultOptions,
                    startupSecretStore);
            dpBuilder.ProtectKeysWithCertificate(vaultProtectionCertificate);

            var decryptOnlyCertificates =
                new List<X509Certificate2> { vaultProtectionCertificate };
            if (vaultOptions.LegacyDataProtectionCertificateMigration
                .IsConfigured)
            {
                decryptOnlyCertificates.AddRange(certificateMaterial.Signing);
            }
            dpBuilder.UnprotectKeysWithAnyCertificate(
                decryptOnlyCertificates.ToArray());
        }
        else if (CanProtectDataProtectionKeys(certificateMaterial.PrimarySigning))
        {
            // Development compatibility only. Non-Development rejects a
            // missing dedicated vault certificate in AddSufficitVault().
            dpBuilder.ProtectKeysWithCertificate(
                certificateMaterial.PrimarySigning!);
        }

        // ---- Internal secret vault (envelope encryption, Transit-style) ----
        // The real KeyVault wraps DEKs through the selected certificate,
        // external KMS/HSM or the now-dedicated Data Protection key ring.
        services.AddSufficitVault(configuration, startupSecretStore);
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
        // Registered only when RejectBreached is true. Password:
        // BreachedCheckFailureMode decides what an unavailable API does
        // (see BreachedPasswordValidator remarks).
        if (options.Password.RejectBreached)
        {
            services.AddHttpClient<BreachedPasswordValidator>()
                .UseSafeOutboundHttp(options.OutboundHttp);
            services.AddScoped<IPasswordValidator<ApplicationUser>, BreachedPasswordValidator>();
        }

        services.AddHttpContextAccessor();
        // End-user text rendered by the API module itself (email messages, the
        // fallback browser error page) resolves through IStringLocalizer.
        // TryAdd-based, so a presentation module registering it too is harmless.
        services.AddLocalization();
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
        // .NET 10 native passkeys (WebAuthn/FIDO2): declaring the ninth generic
        // argument IdentityUserPasskey<string> on IdentityDbContext (AppDbContext)
        // makes AddEntityFrameworkStores<AppDbContext>() register
        // IUserPasskeyStore<ApplicationUser> automatically. UserManager<T> gains
        // AddOrUpdatePasskeyAsync / GetPasskeysAsync / RemovePasskeyAsync /
        // FindByPasskeyIdAsync, and SignInManager<T> gains CheckPasskeySignIn.
        // The embedded Blazor UI calls them through JS interop with
        // navigator.credentials.create/get. The userpasskeys table is mapped in
        // AppDbContext.MapIdentityTables.

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

            // Keep the browser and server-side ticket on one explicit policy.
            // A remembered MFA device makes the application cookie persistent
            // in the sign-in adapter below; active persistent sessions renew
            // within this bounded window instead of depending on framework
            // defaults that can change invisibly between runtime upgrades.
            o.ExpireTimeSpan = TimeSpan.FromDays(Math.Clamp(
                options.UserSessions.AuthenticationLifetimeDays,
                1,
                90));
            o.SlidingExpiration = options.UserSessions.SlidingExpiration;

        });
        services.Configure<CookieAuthenticationOptions>(
            IdentityConstants.TwoFactorRememberMeScheme,
            cookie =>
            {
                cookie.ExpireTimeSpan = TimeSpan.FromDays(Math.Clamp(
                    options.UserSessions.RememberedMfaLifetimeDays,
                    1,
                    90));
                cookie.SlidingExpiration = options.UserSessions.SlidingExpiration;
            });
        services.Configure<SecurityStampValidatorOptions>(options =>
        {
            // Administrative lockout updates the user's security stamp. Check
            // it on every cookie-authenticated request so a blocked account
            // loses its local Identity session immediately instead of waiting
            // for the framework's default validation interval. The two-factor
            // remember-me validator honors this value directly; the application
            // cookie uses SessionSecurityStampValidator, which keeps the
            // per-request stamp check but rebuilds the principal only on
            // UserSessions.PrincipalRefreshIntervalSeconds or a user change.
            options.ValidationInterval = TimeSpan.Zero;

            // The validator rebuilds the principal through the claims factory.
            // Authentication-method claims are session evidence, not durable
            // user claims, so preserve them from the currently validated
            // ticket when the security stamp is renewed. Without this hook a
            // successful MFA ticket is immediately downgraded to Loa1 on the
            // next request even though the security stamp itself is valid.
            options.OnRefreshingPrincipal = context =>
            {
                var currentIdentity = context.CurrentPrincipal?.Identities
                    .FirstOrDefault();
                var newIdentity = context.NewPrincipal?.Identities
                    .FirstOrDefault();
                if (currentIdentity is null || newIdentity is null)
                {
                    return Task.CompletedTask;
                }

                // Revalidation renews this session; it must not mint another sid.
                // HttpContext.User may not yet be populated during authentication.
                foreach (var claimType in new[]
                {
                    OidcSessionClaimsPrincipalFactory.SessionIdClaimType,
                    AuthenticationContextProjector.AuthenticationMethodClaimType,
                    AuthenticationContextProjector.AuthenticationTimeClaimType,
                    OidcSessionClaimsPrincipalFactory.AssuranceLevelClaimType,
                    AuthenticationContextProjector.AuthenticationContextClassClaimType,
                })
                {
                    var currentClaims = currentIdentity
                        .FindAll(claimType)
                        .Select(claim => new Claim(claim.Type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer))
                        .ToArray();
                    if (currentClaims.Length == 0)
                    {
                        continue;
                    }

                    foreach (var existing in newIdentity.FindAll(claimType).ToArray())
                    {
                        newIdentity.RemoveClaim(existing);
                    }

                    foreach (var claim in currentClaims)
                    {
                        newIdentity.AddClaim(claim);
                    }
                }

                return Task.CompletedTask;
            };
        });

        // ---- External login providers (Google, GitHub, etc) ----
        // Reads from "Sufficit:Identity:ExternalProviders" section.
        // Each provider is registered only if Enabled=true and credentials
        // are present. The UI (Login.razor) lists the registered schemes
        // automatically via SignInManager.GetExternalAuthenticationSchemesAsync().
        services.AddSingleton(new IntegrationOAuthProviderRegistry(
            configuration,
            startupSecretStore));
        services.AddHttpClient("identity-integration-oauth", client =>
            client.Timeout = TimeSpan.FromSeconds(30));
        var externalBuilder = services.AddAuthentication();
        AddExternalProviders(externalBuilder, configuration, startupSecretStore);

        // ---- OpenIddict (Core + Server + Validation) ----
        services.AddOpenIddict()
            .AddCore(core =>
            {
                core.UseEntityFrameworkCore()
                    .UseDbContext<AppDbContext>();
                core.ReplaceTokenStore<
                    OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken,
                    Tokens.SufficitOpenIddictTokenStore>();
                core.ReplaceApplicationManager<
                    OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication,
                    SufficitOpenIddictApplicationManager>();
            })
            .AddServer(server => ConfigureOpenIddictServer(
                server,
                options,
                vaultOptions,
                certificateMaterial,
                auxiliarySigningCredentials,
                configuration,
                isDevelopmentEnvironment))
            .AddValidation(validation =>
            {
                validation.UseLocalServer();
                validation.UseAspNetCore();
                Features.ProtocolFeatureCatalog.ConfigureValidation(
                    validation,
                    new Features.ProtocolFeatureContext(options, auxiliarySigningCredentials));
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
        // ---- Client ID Metadata Documents (CIMD, A10, eval 2026-08-14) ----
        // draft-ietf-oauth-client-id-metadata-document-02: the client_id IS
        // an HTTPS URL serving its metadata; fetched on first use and
        // provisioned as a public PKCE client. Fetches never follow
        // redirects (the draft forbids them), respect the shared SSRF
        // policy through the safe outbound transport, and only successful
        // validations are cached.
        services.AddMemoryCache();
        services.AddSingleton(options.Mcp.ClientIdMetadataDocuments);
        services.AddHttpClient(Cimd.ClientIdMetadataResolver.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() =>
                new System.Net.Http.SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    AutomaticDecompression = System.Net.DecompressionMethods.None,
                })
            .UseSafeOutboundHttp(options.OutboundHttp);
        services.AddSingleton<Cimd.ClientIdMetadataResolver>();
        services.AddScoped<Cimd.CimdApplicationProvisioner>();

        // ---- Token-endpoint grant pipeline (A2, eval 2026-08-14) ----
        // Each grant is an ITokenGrantHandler; TokenGrantDispatcher owns the
        // DPoP preamble and resolves the handler by grant type. New grants
        // plug in here without touching AuthorizationController.
        // A3 (eval 2026-08-14): the single privileged-token minting boundary
        // (personal, provisioning and operator reference tokens).
        services.AddScoped<Application.Security.IPrivilegedTokenMintingService,
            PrivilegedTokenMintingService>();
        services.AddScoped<Grants.GrantOperations>();
        services.AddSingleton<McpScopeGrantPolicy>();
        services.AddScoped<FirstPartyUserScopePolicy>();
        services.AddScoped<McpScopeProvisioner>();
        services.AddScoped<PersonalTokenScopeProvisioner>();
        services.AddScoped<ClientTokenLifetimeReconciler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.UserTokenGrantsHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.DeviceCodeGrantHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.ClientCredentialsGrantHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.PasswordGrantHandler>();
        // The same section GrantOperations reads; registered so the resolver
        // does not have to carry the whole options graph to reach one flag.
        services.TryAddSingleton(
            configuration.GetSection("Sufficit:Identity:TokenExchange")
                .Get<Grants.TokenExchangeOptions>() ?? new Grants.TokenExchangeOptions());
        services.AddScoped<Grants.ISubjectTokenResolver, Grants.SubjectTokenResolver>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.TokenExchangeGrantHandler>();
        services.AddScoped<Grants.TokenGrantDispatcher>();
        // Skipping the per-request security-stamp read needs somewhere to
        // remember what is still valid. The cache is registered even when the
        // window is zero: the validator then never consults it, and nothing
        // else in the graph has to know whether the feature is on.
        services.TryAddSingleton<Core.Sessions.ISessionValidityCache>(
            new Core.Sessions.InMemorySessionValidityCache(
                TimeSpan.FromSeconds(Math.Clamp(
                    options.UserSessions.ValidityCacheSeconds,
                    0,
                    300))));
        services.Replace(ServiceDescriptor.Scoped<ISecurityStampValidator,
            SessionSecurityStampValidator>());
        services.AddScoped<SufficitSignInManager>();
        services.AddScoped<SignInManager<ApplicationUser>>(services =>
            services.GetRequiredService<SufficitSignInManager>());
        services.AddScoped<IInteractiveSignInService,
            AspNetCoreIdentityInteractiveSignInService>();
        services.AddScoped<IAccountOnboardingService,
            AspNetCoreIdentityAccountOnboardingService>();
        services.AddScoped<ScopeEntitlementProvisioner>();
        services.AddScoped<IAuthorizationConsentService,
            OpenIddictAuthorizationConsentService>();
        services.AddScoped<OpenIddictDeviceAuthorizationContextService>();
        services.AddScoped<IDeviceAuthorizationContextService>(provider =>
            provider.GetRequiredService<OpenIddictDeviceAuthorizationContextService>());
        services.AddScoped<IClientNativeReturnUriResolver,
            OpenIddictClientNativeReturnUriResolver>();
        services.AddSingleton<INativeReturnUriTicketService,
            DataProtectionNativeReturnUriTicketService>();
        services.AddScoped<IClientDeviceCloseFallbackResolver,
            OpenIddictDeviceCloseFallbackResolver>();
        services.AddSingleton<IDeviceCloseFallbackTicketService,
            DataProtectionDeviceCloseFallbackTicketService>();
        // External identities may only bootstrap a local account once control
        // of the email address is established. The policy is a seam because the
        // answer is a deployment decision, not a protocol fact.
        services.AddSingleton<IExternalIdentityLinkingPolicy>(sp =>
            new ConfigurableExternalIdentityLinkingPolicy(
                options.ExternalIdentities,
                sp.GetRequiredService<
                    ILogger<ConfigurableExternalIdentityLinkingPolicy>>()));
        services.AddSingleton<PendingExternalIdentityStore>(sp =>
            new PendingExternalIdentityStore(
                sp.GetRequiredService<IProtocolStateStore>()));
        services.AddScoped<ExternalIdentityVerificationMessenger>();
        services.AddScoped<IExternalSignInService,
            AspNetCoreIdentityExternalSignInService>();
        services.AddScoped<AspNetCoreIdentityPasskeyService>();
        services.AddScoped<IAccountPasskeyService>(services =>
            services.GetRequiredService<AspNetCoreIdentityPasskeyService>());
        services.AddScoped<IPasskeyAuthenticationService>(services =>
            services.GetRequiredService<AspNetCoreIdentityPasskeyService>());

        AddProtocolFeatures(services, options, auxiliarySigningCredentials);

        return services;
    }

    /// <summary>
    /// Whether a certificate can wrap the Data Protection key ring.
    /// </summary>
    /// <remarks>
    /// The key ring is protected with XML encryption, which only knows how to
    /// encrypt to an RSA certificate: an elliptic-curve one fails with "the
    /// certificate key algorithm is not supported" when the ring creates its
    /// first key — well after startup, on the first cookie issued. EC signing
    /// certificates are legitimate (FAPI 2.0 does not accept RS256), so this
    /// development fallback simply does not apply to them; a real deployment
    /// protects the ring with the dedicated vault certificate.
    /// </remarks>
    internal static bool CanProtectDataProtectionKeys(
        X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return false;
        }

        using var rsa = certificate.GetRSAPublicKey();
        return rsa is not null;
    }
}
