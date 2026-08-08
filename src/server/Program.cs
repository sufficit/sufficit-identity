using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server;
using Sufficit.Identity.Server.Management;
using Sufficit.Identity.Scim;
using Sufficit.Identity.STS;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Sufficit.Identity.UI;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Vault;

var builder = WebApplication.CreateBuilder(args);
var migrateOnly = args.Contains("--migrate-only", StringComparer.Ordinal);

// WebApplication.CreateBuilder already loads appsettings.json followed by
// appsettings.{Environment}.json. Add the machine-specific file after those
// standard sources so each Sufficit server can override only its local values
// (for example, the database endpoint) using a lowercase hostname filename.
builder.Configuration.AddMachineSpecificJsonFile();

// Optional file-based certificate password ingress. The privileged bootstrap
// uses this for randomly generated Development certificates and operators can
// use it to keep production PFX passwords out of JSON/environment values. It
// only fills missing values, preserving explicit deployment configuration.
var certificatePasswordFile = Environment.GetEnvironmentVariable(
        "SUFFICIT_IDENTITY_CERTIFICATE_PASSWORD_FILE")
    ?? "/etc/sufficit/identity/certificate.password";
if (File.Exists(certificatePasswordFile)
    && string.IsNullOrWhiteSpace(builder.Configuration[
        "Sufficit:Identity:Certificates:SigningPassword"]))
{
    var certificatePassword = File.ReadAllText(certificatePasswordFile).Trim();
    if (!string.IsNullOrEmpty(certificatePassword))
    {
        builder.Configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Certificates:SigningPassword"] =
                    certificatePassword,
                ["Sufficit:Identity:Certificates:EncryptionPassword"] =
                    certificatePassword,
            });
    }
}

// ---- Forwarded headers (behind reverse proxy) ----
// Allows the STS to honor X-Forwarded-Proto / X-Forwarded-Host so that
// redirects, discovery document URLs and OpenIddict issuer match the
// public-facing URL (e.g. https://identity.example.com) instead of
// the internal http://localhost:port.
//
// Trust is restricted to Sufficit:Identity:TrustedProxies (a list of CIDR
// strings, e.g. "10.0.0.0/8"). When that list is empty we either trust any
// upstream (Development only, so local docker-compose / dev reverse
// proxies keep working out of the box) or fall back to the ASP.NET Core
// default (loopback only) in every other environment — a startup warning
// is logged below so the gap is visible instead of silently ignoring
// forwarded headers from real proxies.
var trustedProxies = builder.Configuration
    .GetSection("Sufficit:Identity:TrustedProxies")
    .Get<string[]>() ?? Array.Empty<string>();

// Host-level tunables (rate limit, HSTS) bound from the same Sufficit:Identity
// section the server extensions use, so every knob lives in one config surface.
var identityOptions = builder.Configuration
    .GetSection("Sufficit:Identity")
    .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();

DeploymentTopologyPolicy.Validate(
    identityOptions,
    trustedProxies.Length,
    builder.Environment.IsDevelopment());

// ---- Optional presentation composition ----
// Embedded is the compatibility default. Either surface can be set to None so
// the runtime starts without registering or mapping that UI. Remote hosting is
// intentionally not advertised until the versioned HTTP/BFF interaction
// contract is implemented; see docs/plans/PLAN-PLUGGABLE-USER-INTERFACES.md.
var uiHostingOptions = builder.Configuration
    .GetSection(IdentityUiHostingOptions.SectionName)
    .Get<IdentityUiHostingOptions>() ?? new IdentityUiHostingOptions();
uiHostingOptions.Validate();

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;

    if (trustedProxies.Length > 0)
    {
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();

        foreach (var cidr in trustedProxies)
        {
            var parts = cidr.Split('/', 2, StringSplitOptions.TrimEntries);
            var prefix = IPAddress.Parse(parts[0]);
            var prefixLength = parts.Length == 2
                ? int.Parse(parts[1])
                : (prefix.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);

            o.KnownIPNetworks.Add(new System.Net.IPNetwork(prefix, prefixLength));
        }
    }
    else if (builder.Environment.IsDevelopment())
    {
        // No TrustedProxies configured; in Development accept any upstream
        // (we run inside Docker/k8s/Nginx on private networks).
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();
    }
    // else: leave the ASP.NET Core defaults (loopback only) in place.
});

// ---- Compact JSON globally (before STS so OpenIddict picks it up) ----
builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(o =>
{
    o.SerializerOptions.WriteIndented = false;
});
builder.Services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(o =>
{
    o.JsonSerializerOptions.WriteIndented = false;
});
// OpenIddict resolves a root-level JsonSerializerOptions for discovery/JSON
// serialization — register one with WriteIndented=false so responses are compact.
builder.Services.AddSingleton(new System.Text.Json.JsonSerializerOptions
{
    WriteIndented = false,
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
});

// ---- Sufficit Identity STS (Identity + OpenIddict server/validation) ----
builder.Services.AddSufficitIdentitySTS(builder.Configuration);

// ---- Branding theme provider (singleton cache, DB-backed) ----
// Registered before UI and management so both can resolve it.
builder.Services.TryAddSingleton<IBrandingThemeProvider, BrandingThemeProvider>();
builder.Services.TryAddSingleton<IUserAvatarUrlResolver, UserAvatarUrlResolver>();

// ---- Sufficit Identity UI (Blazor Server: login/consent/logout/manage) ----
if (uiHostingOptions.Public.IsEmbedded)
{
    builder.Services.AddSufficitIdentityUI(builder.Configuration);
}

// ---- Sufficit email pipeline (RabbitMQ → Q-EMAIL) ----
// Activates only when Sufficit:Exchange:RabbitMQ:HostName is configured.
// When active, replaces the UI's default IEmailSender (Smtp/Logging) with
// the production RabbitMQEmailQueue (port from the legacy Skoruba STS).
builder.Services.AddSufficitEmailSender(builder.Configuration);

// ---- Optional: management REST API (opt-in via Sufficit:Identity:Management:Enabled) ----
var mgmtEnabled = builder.Configuration
    .GetValue<bool>("Sufficit:Identity:Management:Enabled");
var vaultUiEnabled = uiHostingOptions.Vault.IsEmbedded
    && builder.Configuration.GetValue(
        "Sufficit:Identity:UI:Vault:Enabled", defaultValue: true);

if (mgmtEnabled)
{
    builder.Services.AddSufficitIdentityManagement(builder.Configuration);
    builder.Services.Replace(
        ServiceDescriptor.Scoped<
            IManagementEntitlementResolver,
            SufficitOperatorManagementEntitlementResolver>());
    // M1 fix (eval): replace the MissingClientSecretResolver stub with a
    // vault-backed resolver so provisioning of confidential clients works.
    // The vault is already registered by AddSufficitIdentitySTS above; the
    // resolver consumes IKeyVault (pass-through by default, real crypto when
    // Sufficit:Vault:Enabled=true).
    builder.Services.Replace(
        ServiceDescriptor.Singleton<
            Sufficit.Identity.Management.Provisioning.IClientSecretResolver,
            Sufficit.Identity.Vault.VaultBackedClientSecretResolver>());
    if (uiHostingOptions.Management.IsEmbedded)
    {
        builder.Services.AddSufficitIdentityManagementUI(builder.Configuration);
    }
}

// ---- Optional Vault UI (personal secrets + capability-protected operator Vault) ----
if (vaultUiEnabled)
{
    builder.Services.AddSufficitIdentityVaultUI(builder.Configuration);
}

// ---- Optional: SCIM 2.0 provisioning (RFC 7643/7644) ----
var scimEnabled = builder.Configuration
    .GetValue<bool>("Sufficit:Identity:Scim:Enabled");
if (scimEnabled)
{
    builder.Services.AddSufficitIdentityScim(builder.Configuration);
}

// ---- MVC (for the /connect/* passthrough controllers) ----
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ---- Explicit browser CORS ----
// The Blazor client is hosted on a different port in the Castrum test
// topology. Keep CORS opt-in and exact-origin only: authenticated APIs must
// never fall back to '*' or reflect arbitrary Origin headers.
builder.Services.AddSufficitCors(identityOptions.Cors);

// ---- Health checks (liveness/readiness) ----
builder.Services.AddHealthChecks()
    .AddDbContextCheck<AppDbContext>("database");

// ---- HSTS (outside Development only; local dev is plain HTTP) ----
// Policy from Sufficit:Identity:Hsts (max-age days, subdomains, preload).
if (!builder.Environment.IsDevelopment())
{
    builder.Services.AddHsts(o =>
    {
        o.MaxAge = TimeSpan.FromDays(identityOptions.Hsts.MaxAgeDays);
        o.IncludeSubDomains = identityOptions.Hsts.IncludeSubDomains;
        o.Preload = identityOptions.Hsts.Preload;
    });
}

// ---- Rate limiting: protect token endpoint + interactive login surface ----
// Finding #3: the original limiter covered only POST /connect/token. The
// interactive login surface (POST /account/login, forgot-password, register)
// was unthrottled — per-account lockout doesn't stop cross-account password
// spraying. This limiter covers all credential-validation endpoints with
// a per-IP fixed window. Tunables come from Sufficit:Identity:RateLimit.
var rateLimit = identityOptions.RateLimit;
var tokenEndpointWindow = TimeSpan.FromSeconds(rateLimit.WindowSeconds);

// Interactive credential-validation endpoints (login, forgot-password,
// register, reset-password, external-login callback). These accept POST
// with user-supplied credentials and must be rate-limited per IP.
static bool IsCredentialEndpoint(PathString path, string method)
{
    if (!HttpMethods.IsPost(method)) return false;
    var p = path.Value ?? "";

    // Every POST under /connect/* is a protocol endpoint that either validates
    // client credentials, mints tokens, or mutates client/session state:
    //   /connect/token, /connect/authorize (consent POST), /connect/endsession,
    //   /connect/introspect, /connect/revocation, /connect/par,
    //   /connect/deviceauthorization, /connect/device (verify POST),
    //   /connect/ciba/complete, /connect/ciba/token, /connect/register (DCR).
    // Covering the whole prefix (rather than an explicit list) means a new
    // /connect/* endpoint can never be silently left unthrottled — the same
    // class of bug that bit when the original limiter covered only
    // /connect/token. GETs (discovery, userinfo, authorize challenge) are not
    // credential-validation surfaces and stay unrestricted.
    if (p.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    // CIBA initiation lives outside the /connect/ prefix as defined by the
    // OpenID Connect Client-Initiated Backchannel Authentication Core 1.0
    // specification. RFC 9126 defines PAR, not CIBA.
    if (p.StartsWith("/bc-authorize", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    // Interactive credential-validation endpoints.
    return p.StartsWith("/account/login", StringComparison.OrdinalIgnoreCase)
        || p.StartsWith("/account/forgotpassword", StringComparison.OrdinalIgnoreCase)
        || p.StartsWith("/account/resetpassword", StringComparison.OrdinalIgnoreCase)
        || p.StartsWith("/account/register", StringComparison.OrdinalIgnoreCase)
        || p.StartsWith("/account/externallogincallback", StringComparison.OrdinalIgnoreCase)
        || p.StartsWith("/account/passkeys", StringComparison.OrdinalIgnoreCase);
}

static bool IsDeviceInformationEndpoint(PathString path, string method) =>
    HttpMethods.IsGet(method)
    && path.StartsWithSegments(
        "/connect/device/info",
        StringComparison.OrdinalIgnoreCase);

if (rateLimit.Enabled)
{
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

        options.OnRejected = (context, cancellationToken) =>
        {
            context.HttpContext.Response.Headers.RetryAfter = ((int)tokenEndpointWindow.TotalSeconds).ToString();
            return ValueTask.CompletedTask;
        };

        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        {
            if (IsDeviceInformationEndpoint(
                httpContext.Request.Path,
                httpContext.Request.Method))
            {
                var clientId = httpContext.User.FindFirst("client_id")?.Value
                    ?? httpContext.User.FindFirst("azp")?.Value;
                var partition = !string.IsNullOrWhiteSpace(clientId)
                    ? "device-client:" + clientId
                    : "device-ip:" + (httpContext.Connection.RemoteIpAddress?.ToString()
                        ?? "unknown");
                return RateLimitPartition.GetFixedWindowLimiter(
                    partition,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = Math.Max(
                            1,
                            rateLimit.DeviceInformationPermitLimit),
                        Window = TimeSpan.FromSeconds(Math.Max(
                            1,
                            rateLimit.DeviceInformationWindowSeconds)),
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    });
            }

            if (!IsCredentialEndpoint(httpContext.Request.Path, httpContext.Request.Method))
            {
                return RateLimitPartition.GetNoLimiter("unrestricted");
            }

            var clientIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            return RateLimitPartition.GetFixedWindowLimiter(clientIp, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = rateLimit.PermitLimit,
                Window = tokenEndpointWindow,
                QueueLimit = 0,
                AutoReplenishment = true
            });
        });

        options.AddPolicy("device-information", httpContext =>
        {
            var clientId = httpContext.User.FindFirst("client_id")?.Value
                ?? httpContext.User.FindFirst("azp")?.Value;
            var partition = !string.IsNullOrWhiteSpace(clientId)
                ? "client:" + clientId
                : "ip:" + (httpContext.Connection.RemoteIpAddress?.ToString()
                    ?? "unknown");
            return RateLimitPartition.GetFixedWindowLimiter(
                partition,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = Math.Max(
                        1,
                        rateLimit.DeviceInformationPermitLimit),
                    Window = TimeSpan.FromSeconds(Math.Max(
                        1,
                        rateLimit.DeviceInformationWindowSeconds)),
                    QueueLimit = 0,
                    AutoReplenishment = true,
                });
        });
    });
}

var app = builder.Build();

// ---- Validate UI module composition (Phase 2) ----
// Catches: duplicate modules, incompatible versions, surface requested
// without a module, management UI without management API. All fail-fast
// with a clear message instead of silent no-ops or runtime 404s.
{
    var hostVersion = typeof(Program).Assembly.GetName().Version ?? new Version(0, 4, 0);
    var registry = app.Services.GetService<UiModuleRegistry>();
    if (registry is not null)
    {
        // Collect all UiModuleDescriptor singletons registered by the UI modules.
        foreach (var descriptor in app.Services.GetServices<UiModuleDescriptor>())
        {
            registry.Register(descriptor);
        }

        // Validate: incompatible versions.
        foreach (var module in registry.Modules)
        {
            if (module.MinHostVersion > hostVersion)
            {
                throw new UiCompositionException(
                    $"UI module '{module.Id}' v{module.Version} requires host >= " +
                    $"v{module.MinHostVersion}, but the host is v{hostVersion}.");
            }
        }

        // Validate: surface requested but no module registered for it.
        if (uiHostingOptions.Public.IsEmbedded && !registry.HasSurface(UiSurface.Public))
        {
            throw new UiCompositionException(
                "Public UI surface is Embedded but no public UI module was registered.");
        }

        if (uiHostingOptions.Management.IsEmbedded && !registry.HasSurface(UiSurface.Management))
        {
            if (!mgmtEnabled)
            {
                throw new UiCompositionException(
                    "Management UI surface is Embedded but the management API " +
                    "(Sufficit:Identity:Management:Enabled) is disabled.");
            }
            throw new UiCompositionException(
                "Management UI surface is Embedded but no management UI module was registered.");
        }

        if (vaultUiEnabled && !registry.HasSurface(UiSurface.Vault))
        {
            throw new UiCompositionException(
                "Vault UI surface is Embedded but no Vault UI module was registered.");
        }
    }
}

if (trustedProxies.Length == 0 && !app.Environment.IsDevelopment())
{
    var message =
        "Sufficit:Identity:TrustedProxies is not configured; only loopback proxies are trusted, so " +
        "X-Forwarded-* headers from remote reverse proxies will be ignored until it is set. " +
        "With the rate limiter partitioning by RemoteIpAddress, this means ALL token-endpoint " +
        "traffic shares ONE bucket (the proxy's IP) — a single source or even normal load can " +
        "trigger self-inflicted 429s for everyone.";

    // Item 5.1 [L4]: optionally make this a fatal startup error so a missing
    // TrustedProxies cannot silently turn the rate limiter into a self-DoS.
    if (identityOptions.RateLimit.FailOnUntrustedProxy)
    {
        throw new InvalidOperationException(message + " Set Sufficit:Identity:TrustedProxies " +
            "(or disable Sufficit:Identity:RateLimit:FailOnUntrustedProxy to degrade to a warning).");
    }

    app.Logger.LogWarning(message);
}

// ---- Distributed-cache guard for multi-replica deployments ----
// Several security-critical stores (DPoP replay cache + nonce store, CIBA
// pending requests, front-channel logout context, passkey ceremony tickets)
// depend on IDistributedCache. The default registration is
// AddDistributedMemoryCache (single-node, in-process) — correct for one
// replica, but in a multi-replica deployment each replica has its own isolated
// cache, so DPoP replay detection, CIBA cross-replica polling and nonce
// challenges silently break. When RequireShared is on and the registered
// IDistributedCache is the in-memory fallback, fail fast (or warn) so the gap
// is visible instead of a silent security degradation.
if (identityOptions.DistributedCache.RequireShared && !app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var cache = scope.ServiceProvider.GetService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
    var isMemoryFallback = cache?.GetType().Name is "MemoryDistributedCache";
    if (isMemoryFallback)
    {
        var message =
            "Sufficit:Identity:DistributedCache:RequireShared is true, but the registered " +
            "IDistributedCache is the in-memory fallback (AddDistributedMemoryCache), which is NOT " +
            "shared across replicas. DPoP replay protection, CIBA cross-replica polling, DPoP nonce " +
            "challenges and front-channel logout context would silently break with >1 replica. " +
            "Register a real shared cache (e.g. Redis via AddStackExchangeRedisCache) before scaling out, " +
            "or set Sufficit:Identity:DistributedCache:RequireShared=false if this is genuinely a single-replica deployment.";

        throw new InvalidOperationException(message);
    }
}

// ---- mTLS (mutual TLS, RFC 8705) host configuration reminder ----
// When Sufficit:Identity:Mtls:Enabled is true, the STS registers the MTLS-
// aliased endpoint paths and advertises tls_client_certificate_bound_access_tokens
// in discovery. But the actual client-certificate enforcement happens at the
// TLS layer and is the HOST's responsibility — this Program.cs does NOT
// configure it (it would require a real cert + Listen/Kestrel configuration
// that depends on the deployment topology). Operators enabling mTLS MUST also:
//
//   * For Kestrel directly: configure Kestrel's Listen options with
//       https.ClientCertificateMode = ClientCertificateMode.RequireCertificate
//       and a ClientCertificateValidation callback, on the MTLS-aliased paths.
//   * Behind nginx/Envoy: terminate mTLS at the proxy, forward the validated
//       client cert (or its thumbprint) to the app, and restrict the MTLS
//       paths at the proxy so only cert-authenticated traffic reaches them.
//
// Startup validation requires an explicit deployment attestation. Runtime
// FAPI policy additionally binds the validated certificate thumbprint to the
// requesting OAuth client before treating it as strong authentication.
if (identityOptions.Mtls.Enabled)
{
    app.Logger.LogInformation(
        "mTLS is enabled with deployment mode {DeploymentMode} and {BindingCount} client certificate binding(s).",
        identityOptions.Mtls.DeploymentMode,
        identityOptions.Mtls.ClientCertificateThumbprints.Count);
}

// ---- Honor X-Forwarded-* headers from reverse proxy (Nginx/k8s/CloudFlare) ----
// Must run BEFORE UseHttpsRedirection, UseAuthentication and any path-based
// middleware (e.g. UseLowercasePaths) so that Request.Scheme/Host reflect
// the public-facing URL.
app.UseForwardedHeaders();

// ---- HSTS + baseline security headers ----
// Must run AFTER UseForwardedHeaders (so it sees the real scheme) and
// BEFORE static files/endpoints. CSP (Content-Security-Policy) is emitted in
// the header middleware below in Report-Only mode by default — see
// CspOptions and the inline comment there for the calibration rollout.
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();

    // ---- HTTPS redirection (#8) ----
    // Outside Development only: Development runs Kestrel with both an
    // http:// and an https:// endpoint (see appsettings.Development.json)
    // so local plain-HTTP workflows and docker-compose setups that
    // terminate TLS upstream keep working; forcing a redirect there would
    // break them. Must run after UseForwardedHeaders (above) so a request
    // that already arrived as https at the edge (X-Forwarded-Proto: https,
    // downgraded to http by the time it reaches Kestrel) is correctly seen
    // as https here and NOT redirected again into a loop.
    app.UseHttpsRedirection();
}

// ---- Baseline security headers (X-Content-Type-Options, Referrer-Policy,
// X-Frame-Options, Content-Security-Policy). Implemented in the STS module
// (UseSufficitSecurityHeaders) so the same code runs in the integration test
// factory; see SecurityHeadersMiddlewareExtensions. CSP ships in Report-Only
// mode by default (CspOptions.ReportOnly=true) — flip to enforce only after
// calibrating against the real UI pages. ----
app.UseSufficitSecurityHeaders(identityOptions);

// Surface the CSP posture at startup. Report-Only is the safe default for
// calibration, but a production deployment running Report-Only gets NO
// browser-side XSS mitigation from the policy — only violation reports. Make
// that state explicit in the logs so going live in Report-Only is a conscious
// choice, not an unnoticed gap.
if (!app.Environment.IsDevelopment() && identityOptions.Csp.ReportOnly)
{
    app.Logger.LogWarning(
        "Content-Security-Policy is running in REPORT-ONLY mode in a non-Development "
        + "environment: violations are reported but NOT blocked. Flip "
        + "Sufficit:Identity:Csp:ReportOnly to false to enforce the policy once it "
        + "has been calibrated against the UI.");
}

// ---- i18n: request localization (cookie-based, Blazor Server safe) ----
var supportedCultures = new[] { "pt-BR", "en-US" };
app.UseRequestLocalization(new RequestLocalizationOptions()
    .SetDefaultCulture("pt-BR")
    .AddSupportedCultures(supportedCultures)
    .AddSupportedUICultures(supportedCultures));

// ---- Canonicalize URL paths to lowercase (308 redirect) ----
// Must run before any endpoint matching, so that /Account/Login,
// /ACCOUNT/LOGIn, /CONNECT/Authorize etc. all converge to the lowercase
// canonical form. Query string values are preserved untouched.
app.UseLowercasePaths();

// The explicit routing boundary is required before global CORS middleware so
// preflight requests can be handled with endpoint metadata rather than being
// rejected by an API controller.
app.UseRouting();

// Rate limiting runs after routing so named endpoint policies are visible, but
// still before authentication/authorization. It already sees the trusted
// forwarded client address resolved at the beginning of the pipeline.
if (rateLimit.Enabled)
{
    app.UseRateLimiter();
}

// CORS must run before authentication/authorization so browser preflight
// requests receive the policy headers without requiring a bearer token.
app.UseSufficitCors(identityOptions.Cors);

// ---- Database schema provisioning (migrations). ----
// Dev/test applies pending EF migrations to exercise migration paths. Outside
// Development, only the dedicated --migrate-only process may change schema;
// the HTTP process rejects the legacy AutoMigrate switch.
if (!app.Environment.IsDevelopment()
    && identityOptions.Database.AutoMigrate
    && !migrateOnly)
{
    throw new InvalidOperationException(
        "Database:AutoMigrate is no longer supported by the production web process. Run Sufficit.Identity.Server.dll --migrate-only as a dedicated deployment job.");
}

var shouldMigrate = migrateOnly || app.Environment.IsDevelopment();
if (shouldMigrate)
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

    if (identityOptions.Database.AllowedDatabaseNames.Length > 0)
    {
        var configured = builder.Configuration.GetConnectionString(identityOptions.ConnectionStringName);
        var actualName = ParseDatabaseName(configured);
        if (actualName is null || !identityOptions.Database.AllowedDatabaseNames.Contains(
                actualName, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"Automatic database migration is enabled, but the connection string's database " +
                $"'{actualName ?? "<unparsed>"}' is not in " +
                $"Sufficit:Identity:Database:AllowedDatabaseNames " +
                $"([{string.Join(", ", identityOptions.Database.AllowedDatabaseNames)}]). " +
                "This guard prevents migrating the wrong database. Either add the database name to the " +
                "allow-list, or disable Sufficit:Identity:Database:AutoMigrate and provision schema " +
                "from docs/migration/sql/* instead.");
        }
    }

    await ApplyMigrationsWithAdvisoryLockAsync(db);
    app.Logger.LogInformation(
        "Applied pending database migrations (environment: {Environment}, dedicatedMigrator: {DedicatedMigrator}).",
        app.Environment.EnvironmentName,
        migrateOnly);
}

if (migrateOnly)
{
    app.Logger.LogInformation(
        "Dedicated migration job completed; the HTTP host will not start.");
    return;
}

// Parse the MySQL/MariaDB database name out of a connection string for the
// allowed-database guard above. Returns null when it cannot be parsed. Hand-
// rolled (no DbConnectionStringBuilder) so the host needs no extra package
// reference; MySQL/MariaDB connection strings are semicolon-separated
// key=value pairs where the database is the "database"/"db" key.
static string? ParseDatabaseName(string? connectionString)
{
    if (string.IsNullOrWhiteSpace(connectionString))
    {
        return null;
    }
    foreach (var part in connectionString.Split(';'))
    {
        var kv = part.Split(new[] { '=' }, 2, StringSplitOptions.TrimEntries);
        if (kv.Length != 2)
        {
            continue;
        }
        if (string.Equals(kv[0], "database", StringComparison.OrdinalIgnoreCase)
            || string.Equals(kv[0], "db", StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(kv[1]) ? null : kv[1];
        }
    }
    return null;
}

static async Task ApplyMigrationsWithAdvisoryLockAsync(
    AppDbContext database)
{
    var provider = database.Database.ProviderName ?? string.Empty;
    if (!provider.Contains("MySql", StringComparison.OrdinalIgnoreCase))
    {
        await database.Database.MigrateAsync();
        return;
    }

    var connection = database.Database.GetDbConnection();
    await connection.OpenAsync();
    try
    {
        await using var acquire = connection.CreateCommand();
        acquire.CommandText =
            "SELECT GET_LOCK('sufficit_identity_schema_migrator', 60);";
        var acquired = Convert.ToInt32(
            await acquire.ExecuteScalarAsync(),
            System.Globalization.CultureInfo.InvariantCulture);
        if (acquired != 1)
        {
            throw new InvalidOperationException(
                "Unable to acquire the Sufficit Identity schema migration lock.");
        }

        try
        {
            await database.Database.MigrateAsync();
        }
        finally
        {
            await using var release = connection.CreateCommand();
            release.CommandText =
                "SELECT RELEASE_LOCK('sufficit_identity_schema_migrator');";
            await release.ExecuteScalarAsync();
        }
    }
    finally
    {
        await connection.CloseAsync();
    }
}

// ---- Swagger (#5) ----
// Development only: keeping the API description out of production avoids
// publishing the management surface and its security-sensitive schemas.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// ---- Health checks (liveness/readiness) ----
// /health: liveness only, no dependency checks (fast, always 200 once the
// process is up). /health/ready: runs all registered checks (e.g. DB).
app.MapHealthChecks("/health", new HealthCheckOptions
{
    Predicate = _ => false
});
app.MapHealthChecks("/health/ready");

// Map management endpoints (if enabled).
if (mgmtEnabled)
{
    app.UseSufficitIdentityManagementEndpoints(builder.Configuration);
    if (uiHostingOptions.Management.IsEmbedded)
    {
        app.UseSufficitIdentityManagementUI();
    }
}

if (vaultUiEnabled)
{
    app.UseSufficitIdentityVaultUI();
}

// ---- Sufficit Identity UI (Blazor Server endpoints + static assets) ----
if (uiHostingOptions.Public.IsEmbedded)
{
    app.UseSufficitIdentityUI();
}

app.Run();
