namespace Sufficit.Identity.Server;

internal static class DeviceBrowserLaunch
{
    internal static IEndpointConventionBuilder MapDeviceBrowserLaunch(this IEndpointRouteBuilder app)
        => app.MapGet("/device/launch", (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            // Preserve the existing popup completion policy for desktop clients.
            context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups";
            var code = context.Request.Query["user_code"].ToString();
            if (code.Length is < 1 or > 64 || code.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != ' '))
                return Results.BadRequest();
            // Older clients still open this URL. Continue in the same browser
            // window instead of rendering a launcher that opens a second popup.
            // Forward only the validated public code; consent and token polling
            // remain at the existing device-flow endpoints.
            return Results.Redirect("/connect/device?user_code=" + Uri.EscapeDataString(code) + "&launch_mode=popup");
        }).AllowAnonymous();
}
