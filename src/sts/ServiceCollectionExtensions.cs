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
        var dcrInitialAccessTokenConfigured = !string.IsNullOrWhiteSpace(
            ResolveSecret(
                startupSecretStore,
                "identity/dcr/initial-access-token"));
        services.AddSingleton(options);
        services.Replace(ServiceDescriptor.Singleton<
            IIdentityRuntimeCapabilityCatalog>(
            new SufficitIdentityRuntimeCapabilityCatalog(
                options,
                dcrInitialAccessTokenConfigured)));
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
        else if (certificateMaterial.PrimarySigning is not null)
        {
            // Development compatibility only. Non-Development rejects a
            // missing dedicated vault certificate in AddSufficitVault().
            dpBuilder.ProtectKeysWithCertificate(
                certificateMaterial.PrimarySigning);
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
            // for the framework's default validation interval.
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

                foreach (var claimType in new[]
                {
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
        services.AddScoped<McpScopeProvisioner>();
        services.AddScoped<ClientTokenLifetimeReconciler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.UserTokenGrantsHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.DeviceCodeGrantHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.ClientCredentialsGrantHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.PasswordGrantHandler>();
        services.AddScoped<Grants.ITokenGrantHandler, Grants.TokenExchangeGrantHandler>();
        services.AddScoped<Grants.TokenGrantDispatcher>();
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
        // Durable key/value state for protocol features that have no table of
        // their own (DPoP nonces, front-channel logout context, passkey
        // ceremonies). See ProtocolStateStore — eval 2026-08-30, F-4.
        services.TryAddSingleton<IProtocolStateStore>(sp =>
            new DatabaseProtocolStateStore(
                sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
                TimeProvider.System));

        services.AddSingleton<Dpop.DistributedDpopReplayCache>();
        services.AddSingleton(sp => new Dpop.DatabaseDpopReplayCache(
            sp.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            TimeProvider.System));
        services.AddSingleton<Dpop.IAtomicDpopReplayCache>(sp =>
            sp.GetRequiredService<Dpop.DatabaseDpopReplayCache>());
        services.AddSingleton<Dpop.IDpopReplayCache, Dpop.RollingDpopReplayCache>();
        services.AddSingleton(sp => new Dpop.DpopProofValidator(
            TimeProvider.System,
            Microsoft.Extensions.Logging.LoggerFactoryExtensions.CreateLogger<Dpop.DpopProofValidator>(
                sp.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()),
            sp.GetService<Dpop.IDpopReplayCache>()));

        // Distributed, partition-bound DPoP nonce (RFC 9449 §8). The cache
        // payload is encrypted through IKeyVault when enabled, so a shared
        // Redis/SQL cache does not expose nonce material at rest.
        // Durable primary with the cache accepted during a rolling deployment
        // (eval 2026-08-30, F-4): a nonce challenge issued by one replica has to
        // be honored by whichever replica receives the client's retry.
        services.AddSingleton<Dpop.IDpopNonceStore>(sp =>
            sp.GetRequiredService<Dpop.RollingDpopNonceStore>());

        services.AddSingleton(sp => new Dpop.DatabaseDpopNonceStore(
            sp.GetRequiredService<IProtocolStateStore>(),
            ttl: null,
            timeProvider: TimeProvider.System,
            keyVault: sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));

        services.AddSingleton(sp => new Dpop.RollingDpopNonceStore(
            sp.GetRequiredService<Dpop.DatabaseDpopNonceStore>(),
            sp.GetRequiredService<Dpop.DistributedDpopNonceStore>()));

        // Concrete registration is separate so tests and deployment-specific
        // composition roots can resolve the implementation directly.
        services.AddSingleton(sp => new Dpop.DistributedDpopNonceStore(
            sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            timeProvider: TimeProvider.System,
            keyVault: sp.GetRequiredService<Sufficit.Identity.Vault.IKeyVault>()));

        if (options.Jar.Enabled)
        {
            if (options.Jar.MaxLifetimeSeconds is < 1 or > 600
                || options.Jar.RemoteJwksMaxBytes is < 1024 or > 1_048_576
                || options.Jar.RemoteJwksTimeoutSeconds is < 1 or > 30
                || options.Jar.RemoteJwksCacheSeconds is < 1 or > 86_400
                || options.Jar.RemoteJwksStaleSeconds is < 0 or > 86_400
                || options.Jar.RemoteJwksMaxCacheEntries is < 1 or > 4096)
            {
                throw new InvalidOperationException(
                    "JAR lifetime and remote JWKS timeout/size/cache settings are outside their supported security bounds.");
            }
        }

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
            services.AddScoped<IAuthorizationHandler, Controllers.SsfMfaHandler>();
            services.AddAuthorizationBuilder()
                .AddPolicy("sufficit-ssf-transmitter", policy =>
                {
                    policy.AuthenticationSchemes.Add(
                        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(
                        new Controllers.SsfScopeRequirement(options.SharedSignals.RequiredScope));
                    if (options.SharedSignals.RequireMfa)
                    {
                        policy.Requirements.Add(new Controllers.SsfMfaRequirement());
                    }
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

}
