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

namespace Sufficit.Identity.Server;

/// <summary>
/// Development-only helper endpoints under <c>/__test__</c>.
/// </summary>
internal static class DevelopmentTestEndpoints
{
    public static void Map(WebApplication app)
    {
        // Compiled into Debug builds only. Release binaries — CI, Docker and deploy.py
        // all publish Release — do not contain these endpoints at all, so a production
        // host started with ASPNETCORE_ENVIRONMENT=Development by mistake still cannot
        // expose an anonymous sign-in endpoint.
        #if DEBUG
        if (app.Environment.IsDevelopment())
        {
            app.Logger.LogInformation("REGISTERING __test__ endpoints");
            app.MapGet("/__test__/ping", () => "pong");
            // Lists every registered endpoint (route template, HTTP methods, auth
            // metadata), optionally filtered by ?path=. invaluable when debugging
            // route collisions between the root pipeline and the /management branch.
            app.MapGet("/__test__/endpoints", (string? path) =>
                string.Join("\n",
                    app.Services.GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>()
                        .Endpoints
                        .Select(e => e is RouteEndpoint re
                            ? $"{re.RoutePattern.RawText} [{string.Join(",", re.Metadata.GetMetadata<Microsoft.AspNetCore.Routing.HttpMethodMetadata>()?.HttpMethods ?? new[] { "?" })}] {string.Join(",", re.Metadata.OfType<Microsoft.AspNetCore.Authorization.IAuthorizeData>().Select(a => a.Policy ?? a.Roles ?? "auth"))}"
                            : $"{e.DisplayName} [no-route]")
                        .Where(l => path is null || l.Contains(path, StringComparison.OrdinalIgnoreCase))));
            app.MapPost("/__test__/signin", async (
                Microsoft.AspNetCore.Http.HttpContext context,
                Microsoft.AspNetCore.Identity.UserManager<Sufficit.Identity.Core.Entities.ApplicationUser> userManager,
                Microsoft.AspNetCore.Identity.SignInManager<Sufficit.Identity.Core.Entities.ApplicationUser> signInManager) =>
            {
                var form = await context.Request.ReadFormAsync();
                var username = form["username"].ToString();
                if (string.IsNullOrWhiteSpace(username))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("username required");
                    return;
                }
                var user = await userManager.FindByNameAsync(username)
                    ?? await userManager.FindByEmailAsync(username);
                if (user is null)
                {
                    user = new Sufficit.Identity.Core.Entities.ApplicationUser
                    {
                        UserName = username,
                        Email = username,
                        EmailConfirmed = true,
                    };
                    await userManager.CreateAsync(user, "Test123!@Test");
                    // Grants whatever the deployment configured as full administrator
                    // roles (see appsettings.Development.json); nothing otherwise.
                    var fullAdministratorRoles = context.RequestServices
                        .GetService<Microsoft.Extensions.Options.IOptions<Sufficit.Identity.Management.ManagementOptions>>()
                        ?.Value.Authorization.FullAdministratorRoles ?? [];
                    foreach (var role in fullAdministratorRoles)
                    {
                        await userManager.AddToRoleAsync(user, role);
                    }
                }
                var claims = new List<System.Security.Claims.Claim>
                {
                    new("amr", "pwd"),
                    new("auth_time",
                        DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                        System.Security.Claims.ClaimValueTypes.Integer64),
                };
                if (string.Equals(form["mfa"].ToString(), "true", StringComparison.OrdinalIgnoreCase))
                {
                    claims.Add(new System.Security.Claims.Claim("amr", "otp"));
                    claims.Add(new System.Security.Claims.Claim("amr", "mfa"));
                    claims.Add(new System.Security.Claims.Claim(
                        "acr",
                        context.RequestServices
                            .GetRequiredService<IAuthenticationContextClassMapper>()
                            .Map(Sufficit.Identity.Application.Security.CaepAssuranceLevel.Loa2)));
                }
                await signInManager.SignInWithClaimsAsync(user, null, claims);
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync("ok");
            });
        }

        #endif
    }
}
