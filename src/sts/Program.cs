using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management;
using Sufficit.Identity.Server;
using Sufficit.Identity.UI;

var builder = WebApplication.CreateBuilder(args);

// ---- Forwarded headers (behind reverse proxy) ----
// Allows the STS to honor X-Forwarded-Proto / X-Forwarded-Host so that
// redirects, discovery document URLs and OpenIddict issuer match the
// public-facing URL (e.g. https://identity.sufficit.com.br) instead of
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

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;

    if (trustedProxies.Length > 0)
    {
        o.KnownNetworks.Clear();
        o.KnownProxies.Clear();

        foreach (var cidr in trustedProxies)
        {
            var parts = cidr.Split('/', 2, StringSplitOptions.TrimEntries);
            var prefix = IPAddress.Parse(parts[0]);
            var prefixLength = parts.Length == 2
                ? int.Parse(parts[1])
                : (prefix.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);

            o.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(prefix, prefixLength));
        }
    }
    else if (builder.Environment.IsDevelopment())
    {
        // No TrustedProxies configured; in Development accept any upstream
        // (we run inside Docker/k8s/Nginx on private networks).
        o.KnownNetworks.Clear();
        o.KnownProxies.Clear();
    }
    // else: leave the ASP.NET Core defaults (loopback only) in place.
});

// ---- Sufficit Identity STS (Identity + OpenIddict server/validation) ----
builder.Services.AddSufficitIdentitySTS(builder.Configuration);

// ---- Sufficit Identity UI (Blazor Server: login/consent/logout/manage) ----
builder.Services.AddSufficitIdentityUI(builder.Configuration);

// ---- Sufficit email pipeline (RabbitMQ → Q-EMAIL) ----
// Activates only when Sufficit:Exchange:RabbitMQ:HostName is configured.
// When active, replaces the UI's default IEmailSender (Smtp/Logging) with
// the production RabbitMQEmailQueue (port from the legacy Skoruba STS).
builder.Services.AddSufficitEmailSender(builder.Configuration);

// ---- Optional: management REST API (opt-in via Sufficit:Identity:Management:Enabled) ----
var mgmtEnabled = builder.Configuration
    .GetValue<bool>("Sufficit:Identity:Management:Enabled");

if (mgmtEnabled)
{
    builder.Services.AddSufficitIdentityManagement(builder.Configuration);
}

// ---- MVC (for the /connect/* passthrough controllers) ----
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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

// ---- Rate limiting: protect /connect/token against brute force ----
// Global limiter that only restricts POST /connect/token (fixed window per
// client IP, no queueing); every other endpoint is unrestricted. Pairs with
// the password-grant lockout enforced by the authorization controller.
// Tunables come from Sufficit:Identity:RateLimit (Enabled/PermitLimit/
// WindowSeconds).
const string TokenEndpointPath = "/connect/token";
var rateLimit = identityOptions.RateLimit;
var tokenEndpointWindow = TimeSpan.FromSeconds(rateLimit.WindowSeconds);

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
            var isTokenEndpoint = HttpMethods.IsPost(httpContext.Request.Method)
                && httpContext.Request.Path.Equals(TokenEndpointPath, StringComparison.OrdinalIgnoreCase);

            if (!isTokenEndpoint)
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
    });
}

var app = builder.Build();

if (trustedProxies.Length == 0 && !app.Environment.IsDevelopment())
{
    app.Logger.LogWarning(
        "Sufficit:Identity:TrustedProxies is not configured; only loopback proxies are trusted, so " +
        "X-Forwarded-* headers from remote reverse proxies will be ignored until it is set.");
}

// ---- Honor X-Forwarded-* headers from reverse proxy (Nginx/k8s/CloudFlare) ----
// Must run BEFORE UseHttpsRedirection, UseAuthentication and any path-based
// middleware (e.g. UseLowercasePaths) so that Request.Scheme/Host reflect
// the public-facing URL.
app.UseForwardedHeaders();

// ---- HSTS + baseline security headers ----
// Must run AFTER UseForwardedHeaders (so it sees the real scheme) and
// BEFORE static files/endpoints. No CSP yet — the Blazor Server UI would
// need careful script/style allowances, tracked separately.
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

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});

// ---- Canonicalize URL paths to lowercase (308 redirect) ----
// Must run before any endpoint matching, so that /Account/Login,
// /ACCOUNT/LOGIn, /CONNECT/Authorize etc. all converge to the lowercase
// canonical form. Query string values are preserved untouched.
app.UseLowercasePaths();

// ---- Rate limiter (must see the real client IP resolved above; must run
// before UseAuthentication so unauthenticated brute-force attempts against
// /connect/token are throttled regardless of credentials supplied). ----
if (rateLimit.Enabled)
{
    app.UseRateLimiter();
}

// ---- Ensure database schema exists (dev/test only). ----
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
}

// ---- Swagger (#5) ----
// Development only: this previously published the whole API surface
// (including management controllers, if enabled) unconditionally in every
// environment.
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
}

// ---- Sufficit Identity UI (Blazor Server endpoints + static assets) ----
app.UseSufficitIdentityUI();

app.Run();
