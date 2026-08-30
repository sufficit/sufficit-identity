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

public static partial class ServiceCollectionExtensions
{
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

        // GitLab is broker-only: it deliberately has no display name, so it
        // is not offered as an Identity sign-in method. The confidential app
        // gives each integration user an `api` grant that Identity keeps in
        // their personal Vault. GitLab's dynamic registration endpoint cannot
        // be used here because it creates an MCP-only application even when
        // the requested registration scope is `api`.
        var gitlab = section.GetSection("GitLab");
        var gitlabClientId = ResolveSecret(
            secretStore,
            "identity/external-providers/gitlab/client-id");
        var gitlabClientSecret = ResolveSecret(
            secretStore,
            "identity/external-providers/gitlab/client-secret");
        if (gitlab.GetValue<bool>("Enabled")
            && !string.IsNullOrWhiteSpace(gitlabClientId)
            && !string.IsNullOrWhiteSpace(gitlabClientSecret))
        {
            builder.AddOAuth("GitLabIntegration", string.Empty, options =>
            {
                ConfigureExternalProvider(options);
                options.ClientId = gitlabClientId!;
                options.ClientSecret = gitlabClientSecret!;
                options.CallbackPath = "/signin-gitlab";
                options.AuthorizationEndpoint = "https://gitlab.com/oauth/authorize";
                options.TokenEndpoint = "https://gitlab.com/oauth/token";
                options.UserInformationEndpoint = "https://gitlab.com/api/v4/user";
                options.UsePkce = true;
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
        // The external cookie is also the short-lived handoff used by the
        // integration broker. Tokens stay server-side and are immediately
        // moved into the authenticated subject's personal Vault.
        options.SaveTokens = true;
        options.CorrelationCookie.SameSite = SameSiteMode.None;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.HttpOnly = true;

        // OAuthHandler persists access/refresh tokens when SaveTokens is set,
        // but it intentionally omits the token endpoint's `scope` field. The
        // integration broker must retain that provider-authenticated value so
        // /status and /access can enforce the complete required-scope set
        // instead of treating every successful provider callback as usable.
        options.Events.OnCreatingTicket = context =>
        {
            IntegrationOAuthProtocol.StoreGrantedScope(
                context.Properties,
                context.TokenResponse);
            return Task.CompletedTask;
        };

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
