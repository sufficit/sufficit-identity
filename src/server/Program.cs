using Sufficit.Identity.Core.Networking;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Branding;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server;
using Sufficit.Identity.Scim;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Mtls;
using Sufficit.Identity.UI.Abstractions.Hosting;
using Sufficit.Identity.UI;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Vault;
using Sufficit.Identity.Vault;

if (args.Contains("--prune-tokens", StringComparer.Ordinal)
    || args.Contains("--check-token-pruning", StringComparer.Ordinal))
{
    Environment.ExitCode = await TokenPruningCommand.RunAsync(
        args.Contains("--check-token-pruning", StringComparer.Ordinal));
    return;
}

var builder = WebApplication.CreateBuilder(args);
var migrateOnly = args.Contains("--migrate-only", StringComparer.Ordinal);
var reconcileClientTokenLifetimes = args.Contains(
    "--reconcile-client-token-lifetimes", StringComparer.Ordinal);
var repairMetricsExportSecret = args.Contains(
    "--repair-metrics-export-secret", StringComparer.Ordinal);

// Resolve configuration-time secrets through the same ISecretStore boundary
// used by STS consumers. The store reads SUFFICIT_SECRET_* only.
var startupSecretStore = new EnvironmentSecretStore();

// WebApplication.CreateBuilder already loads appsettings.json followed by
// appsettings.{Environment}.json. Add the machine-specific file after those
// standard sources so each Sufficit server can override only its local values
// (for example, the database endpoint) using a lowercase hostname filename.
builder.Configuration.AddMachineSpecificJsonFile();
// Reject plaintext startup secrets before adding the environment layer. This
// makes a stale appsettings value a visible deployment failure instead of a
// silent compatibility fallback.
SecretConfigurationExtensions.EnsureNoPlaintextSecrets(builder.Configuration);
// Resolve deployment-provided secret overrides before any startup options are
// bound. Every startup consumer receives the same vault-secrets.env value.
// The report records which boundary answered for each secret — names and
// sources, never values — so the posture check can prove the configuration-time
// credentials came from the approved one.
builder.Configuration.AddSufficitSecretOverrides(
    startupSecretStore,
    out var secretResolution);
builder.Services.AddSingleton(secretResolution);

// Use the shared Redis cache when a deployment supplies a Redis connection
// through the secret boundary. AddSufficitIdentitySTS keeps the in-process
// memory cache as the single-node fallback; registering Redis first means its
// TryAdd registration wins for clustered production hosts.
var redisConnectionString = builder.Configuration.GetConnectionString("Redis");
if (!string.IsNullOrWhiteSpace(redisConnectionString))
{
    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = redisConnectionString;
        options.InstanceName = "sufficit:identity:";
    });
}

// ---- Forwarded headers (behind reverse proxy) ----
// Allows the STS to honor X-Forwarded-Proto / X-Forwarded-Host so that
// redirects, discovery document URLs and OpenIddict issuer match the
// public-facing URL (e.g. https://identity.example.com) instead of
// the internal http://localhost:port.
//
// File-managed networks are merged with the database configuration at startup.
// TrustedProxyForwardingMiddleware uses immutable in-memory snapshots and
// processes two trusted hops by default (edge proxy + local Nginx).

// Host-level tunables (rate limit, HSTS) bound from the same Sufficit:Identity
// section the server extensions use, so every knob lives in one config surface.
var identityOptions = builder.Configuration
    .GetSection("Sufficit:Identity")
    .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();

// A Development environment with a public issuer or production certificates is
// a misconfiguration, not a developer machine: refuse to start before anything
// that Development relaxes gets registered.
if (DeploymentTopologyPolicy.ValidateDevelopmentHost(
        identityOptions,
        builder.Configuration["Sufficit:Vault:CertificatePath"],
        builder.Environment.IsDevelopment()))
{
    Console.Error.WriteLine(
        "WARNING: running the Development environment on a host configured like a real "
        + "deployment because Sufficit:Identity:AllowDevelopmentOnPublicHost=true.");
}

// ---- Optional presentation composition ----
// Embedded is the compatibility default. Either surface can be set to None so
// the runtime starts without registering or mapping that UI. Remote hosting is
// intentionally not advertised until the versioned HTTP/BFF interaction
// contract is implemented; see docs/plans/PLAN-PLUGGABLE-USER-INTERFACES.md.
var uiHostingOptions = builder.Configuration
    .GetSection(IdentityUiHostingOptions.SectionName)
    .Get<IdentityUiHostingOptions>() ?? new IdentityUiHostingOptions();
uiHostingOptions.Validate();

builder.Services.Configure<TrustedProxyNatsOptions>(builder.Configuration.GetSection("Sufficit:Identity:ProxySynchronization:Nats"));
builder.Services.AddSingleton<TrustedProxyRefreshSignal>();
builder.Services.AddSingleton<TrustedProxyNatsBridge>();
builder.Services.AddSingleton<ITrustedProxyChangePublisher>(sp => sp.GetRequiredService<TrustedProxyNatsBridge>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<TrustedProxyNatsBridge>());
builder.Services.AddHostedService<TrustedProxyRefreshWorker>();

// Session validity notifications: the same best-effort shape as the trusted
// proxy bridge. Off unless configured; see UserSessions:ValidityCacheSeconds.
builder.Services.Configure<Sufficit.Identity.Server.UserSecurityNatsOptions>(
    builder.Configuration.GetSection("Sufficit:Identity:UserSessions:Nats"));
builder.Services.AddSingleton<Sufficit.Identity.Server.UserSecurityNatsBridge>();
builder.Services.AddSingleton<Sufficit.Identity.Core.Sessions.IUserSecurityChangePublisher>(
    sp => sp.GetRequiredService<Sufficit.Identity.Server.UserSecurityNatsBridge>());
builder.Services.AddHostedService(
    sp => sp.GetRequiredService<Sufficit.Identity.Server.UserSecurityNatsBridge>());

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
builder.Services.AddSufficitIdentitySTS(
    builder.Configuration,
    secretStore: startupSecretStore);

// ---- Branding theme provider (singleton cache, DB-backed) ----
// Registered before UI and management so both can resolve it.
builder.Services.TryAddSingleton<IBrandingThemeProvider, BrandingThemeProvider>();
builder.Services.TryAddSingleton<IUserAvatarUrlResolver, UserAvatarUrlResolver>();

// ---- Sufficit email pipeline (RabbitMQ → Q-EMAIL) ----
// Activates only when Sufficit:Exchange:RabbitMQ:HostName is configured.
// When active, replaces the UI's default IEmailSender (Smtp/Logging) with
// the production RabbitMQEmailQueue (port from the legacy Skoruba STS).
builder.Services.AddSufficitEmailSender(
    builder.Configuration,
    secretStore: startupSecretStore);

// ---- Feature modules (IIdentityModule) ----
// Each module reads its own enablement, registers its own services and
// contributes its own pipeline steps; the host only lists them. The list order
// is the service registration order and the order of endpoint contributions:
// management API, management console, Vault UI, public UI, SCIM (A8).
// Which plane this process serves (A7). All — the default — composes whatever
// the configuration enables, exactly as before; Sts and Admin split the two
// planes across hosts that share the database. See IdentityHostProfile.cs.
var hostProfile = IdentityHostProfilePolicy.Resolve(builder.Configuration);
var allModules = new Sufficit.Identity.Hosting.IIdentityModule[]
{
    new ManagementIdentityModule(),
    new ManagementUiIdentityModule(),
    new VaultUiIdentityModule(),
    new PublicUiIdentityModule(),
    new ScimIdentityModule(),
};
var identityModules = Sufficit.Identity.Hosting.IdentityModuleCatalog.Create(
    builder.Configuration,
    IdentityHostProfilePolicy.AdmittedModules(hostProfile),
    allModules);
var excludedModules = IdentityHostProfilePolicy.Excluded(
    hostProfile,
    Sufficit.Identity.Hosting.IdentityModuleCatalog
        .Create(builder.Configuration, allModules)
        .Enabled.Select(module => module.Id).ToArray());
identityModules.ConfigureServices(builder.Services, builder.Configuration);
var mgmtEnabled = identityModules.IsEnabled(ManagementIdentityModule.ModuleId);
var vaultUiEnabled = identityModules.IsEnabled(VaultUiIdentityModule.ModuleId);
var scimEnabled = identityModules.IsEnabled(ScimIdentityModule.ModuleId);

// Management and SCIM both customize authorization failures. When both
// modules are enabled, preserve the actionable Management Problem Details
// response and the SCIM denial audit instead of letting the last registration
// silently replace the first one.
if (mgmtEnabled && scimEnabled)
{
    builder.Services.Replace(
        ServiceDescriptor.Singleton<
            Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler,
            SufficitIdentityAuthorizationMiddlewareResultHandler>());
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
    .AddDbContextCheck<AppDbContext>("database")
    .AddCheck<TrustedProxySnapshotHealthCheck>("trusted-proxy-snapshot");

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

// ---- Rate limiting: protect OAuth/OIDC + interactive credential surfaces ----
// Finding #3: the original limiter covered only POST /connect/token. The
// interactive login surface (POST /account/login, forgot-password, register)
// was unthrottled — per-account lockout doesn't stop cross-account password
// spraying. This limiter covers all credential-validation endpoints with
// a per-IP fixed window. Tunables come from Sufficit:Identity:RateLimit.
var rateLimit = identityOptions.RateLimit;
var managementRoutePrefix = builder.Configuration
    .GetValue<string>("Sufficit:Identity:Management:RoutePrefix")
    ?.Trim('/')
    is { Length: > 0 } configuredPrefix
    ? configuredPrefix
    : "api";

// The full limiter (endpoint classification, credential/admin/PAR/device
// buckets and the rejection response) lives in
// RateLimiterServiceCollectionExtensions so this host and the integration-test
// factory register the IDENTICAL policy instead of two drifting reproductions
// (eval 2026-08-30, architecture item 1).
if (rateLimit.Enabled)
{
    builder.Services.AddSufficitIdentityRateLimiter(rateLimit, managementRoutePrefix);
}

var app = builder.Build();

// Say which plane this process serves, and what the profile left out: a
// missing endpoint should be explained by a log line, not by a 404.
app.Logger.LogInformation(
    "Identity host profile {Profile}; modules={Modules}; excludedByProfile={Excluded}.",
    hostProfile,
    string.Join(',', identityModules.Enabled.Select(module => module.Id)),
    excludedModules.Count == 0 ? "(none)" : string.Join(',', excludedModules));

// One-shot maintenance path for a corrupted/legacy metrics credential. It is
// deliberately a CLI mode (secret comes from stdin) rather than an HTTP
// escape hatch: the command rotates only the metrics-export key and persists a
// fresh ciphertext through the same IKeyVault implementation used by the
// management service. It never prints or stores the plaintext secret.
if (repairMetricsExportSecret)
{
    await HostBootstrap.RepairMetricsExportSecretAsync(app);
    return;
}

if (reconcileClientTokenLifetimes)
{
    using var scope = app.Services.CreateScope();
    var updated = await scope.ServiceProvider
        .GetRequiredService<ClientTokenLifetimeReconciler>()
        .ReconcileAsync();
    app.Logger.LogInformation(
        "Client token lifetime reconciliation completed; updatedClients={UpdatedClients}.",
        updated);
    return;
}

// ---- Development-only test authentication (MUST be before middleware) ----
// Debug builds only; see DevelopmentTestEndpoints.
DevelopmentTestEndpoints.Map(app);

// ---- Validate UI module composition (Phase 2) ----
UiCompositionValidation.Validate(app, uiHostingOptions, mgmtEnabled, vaultUiEnabled);

// ---- Distributed-cache guard for multi-replica deployments ----
HostStartupGuards.EnsureSharedDistributedCache(app, identityOptions);

// ---- Consolidated production posture check (fail-closed) ----
// Each enabled module contributes its own permissive settings. Development
// logs them; every other environment fails closed unless a finding has a
// bounded acknowledgement with owner, reason and expiry. The old global false
// switch is intentionally ignored: it could suppress unrelated boundaries at
// once and silently outlive a migration.
Sufficit.Identity.STS.Security.ProductionPostureCheck.Enforce(
    app.Services,
    identityOptions,
    app.Environment.IsDevelopment(),
    app.Logger);

app.Logger.LogInformation(
    "Interactive session policy active: AuthenticationLifetimeDays={AuthenticationLifetimeDays}; "
    + "RememberedMfaLifetimeDays={RememberedMfaLifetimeDays}; "
    + "SlidingExpiration={SlidingExpiration}.",
    Math.Clamp(identityOptions.UserSessions.AuthenticationLifetimeDays, 1, 90),
    Math.Clamp(identityOptions.UserSessions.RememberedMfaLifetimeDays, 1, 90),
    identityOptions.UserSessions.SlidingExpiration);

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
//       client certificate through the configured header, and restrict the
//       MTLS paths so only cert-authenticated traffic reaches them.
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

// Consume a proxy certificate assertion while the immediate connection peer
// is still visible. The middleware strips the configured header in every mode
// and only projects a certificate from the dedicated mTLS proxy CIDRs. This
// must precede UseForwardedHeaders, which rewrites RemoteIpAddress.
app.UseMtlsClientCertificateForwarding(identityOptions.Mtls);

// ---- Honor X-Forwarded-* headers from reverse proxy (Nginx/k8s/CloudFlare) ----
// Must run BEFORE UseHttpsRedirection, UseAuthentication and any path-based
// middleware (e.g. UseLowercasePaths) so that Request.Scheme/Host reflect
// the public-facing URL.
app.UseMiddleware<TrustedProxyForwardingMiddleware>();

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
    // Liveness/readiness probes intentionally use the private HTTP Unix
    // socket. Sending them through HttpsRedirectionMiddleware cannot produce
    // a useful redirect because Kestrel has no HTTPS listener in production,
    // and it emits "Failed to determine the https port" on every probe.
    app.UseWhen(
        context => !context.Request.Path.StartsWithSegments(
            "/health",
            StringComparison.OrdinalIgnoreCase),
        branch => branch.UseHttpsRedirection());
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
await HostBootstrap.ProvisionSchemaAsync(app, identityOptions, startupSecretStore, migrateOnly);

if (migrateOnly)
{
    app.Logger.LogInformation(
        "Dedicated migration job completed; the HTTP host will not start.");
    return;
}

// The Identity MCP/personal Vault scope is part of the server's own contract,
// not an operator-maintained database tweak. Reconcile it and the client
// permissions the deployment configured as implicitly entitled on every startup
// so fresh and existing deployments converge automatically before user traffic
// is accepted.
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider
        .GetRequiredService<McpScopeProvisioner>()
        .ProvisionAsync();
    await scope.ServiceProvider
        .GetRequiredService<PersonalTokenScopeProvisioner>()
        .ProvisionAsync();
}

// ---- Module pipeline contributions ----
// The host pipeline has not moved into the builder yet, so each stage a module
// may contribute to is applied at its position below; EnsureAllApplied fails
// startup if a module contributed to a stage this host does not apply.
var identityPipeline = new Sufficit.Identity.Hosting.IdentityPipelineBuilder();
identityModules.ConfigurePipeline(identityPipeline);

// ---- Swagger ----
// Both endpoints are anonymous, so publishing the document hands anyone the
// full controller inventory (management, SCIM, provisioning, vault). Default
// is Development-only; a deployment can opt back in with
// Sufficit:Identity:Swagger:Enabled. Keep this aligned with the public layout
// link, which reads the same flag.
var swaggerEnabled = identityOptions.Swagger.Enabled
    ?? app.Environment.IsDevelopment();
if (swaggerEnabled)
{
    app.UseSwagger();
    app.UseSwaggerUI();

    if (!app.Environment.IsDevelopment())
    {
        app.Logger.LogWarning(
            "Swagger is published outside Development: the complete controller "
            + "contract (management, SCIM, provisioning, vault) is served "
            + "anonymously at /swagger. Unset Sufficit:Identity:Swagger:Enabled "
            + "to restrict it to Development.");
    }
}

// Module steps that must run before authentication (the public UI's browser
// rendering of protocol errors).
identityPipeline.ApplyStage(app, Sufficit.Identity.Hosting.IdentityPipelineStage.PreAuthentication);

// Static assets are anonymous files; skipping authentication for them avoids
// a security-stamp read per script and stylesheet. The exclusion is based on
// endpoint metadata, so OpenIddict protocol requests still authenticate.
app.UseAuthenticationExceptStaticAssets();
app.UseAuthorization();

// Account recovery and registration are anonymous-only surfaces. Keep the
// rule at the host boundary so a signed-in user cannot reach them through a
// direct URL, enhanced navigation request, or a stale form POST. This also
// avoids rendering a recovery/register circuit before the client-side router
// has had a chance to inspect the current authentication state.
app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true
        && (context.Request.Path.StartsWithSegments(
                "/account/forgotpassword",
                StringComparison.OrdinalIgnoreCase)
            || context.Request.Path.StartsWithSegments(
                "/account/register",
                StringComparison.OrdinalIgnoreCase)))
    {
        context.Response.Redirect("/manage");
        return;
    }

    await next();
});

app.MapControllers();

// ---- Health checks (liveness/readiness) ----
// /health: liveness only, no dependency checks (fast, always 200 once the
// process is up). TrustedProxyForwardingMiddleware never refuses it, even when
// it refuses other traffic. /health/ready: runs all registered checks (e.g.
// DB, trusted proxy freshness); a stale proxy list served from the file
// baseline reports Degraded (200) so replicas sharing one database are not all
// removed from the load balancer at the same moment.
app.MapHealthChecks(HealthEndpoints.Liveness, new HealthCheckOptions
{
    Predicate = _ => false
});
app.MapHealthChecks(HealthEndpoints.Readiness);

// ---- Module endpoints ----
// Mapped in catalog order: management API, management console, Vault UI, then
// the public UI, whose Blazor endpoint also serves the embedded Vault pages.
identityPipeline.ApplyStage(app, Sufficit.Identity.Hosting.IdentityPipelineStage.Endpoints);
identityPipeline.EnsureAllApplied();

// Load the merged trust boundary before accepting traffic (after schema provisioning).
await HostStartupGuards.LoadTrustedProxiesAsync(app, identityOptions);

app.Run();
