using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.STS.ErrorPages;

/// <summary>Presentation classification shared by embedded and headless STS hosts; never an authorization decision.</summary>
public static class BrowserNavigationRequest
{
    public static bool IsHtmlNavigation(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method)
            || !(request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase)
                || request.Path.Equals("/connect/endsession", StringComparison.OrdinalIgnoreCase)))
            return false;
        return PrefersHtmlDocument(request);
    }

    public static bool PrefersHtmlDocument(HttpRequest request)
    {
        var mode = request.Headers["Sec-Fetch-Mode"].ToString();
        var destination = request.Headers["Sec-Fetch-Dest"].ToString();
        if ((mode.Length > 0 && mode != "navigate")
            || (destination.Length > 0 && destination != "document")
            || request.Headers.ContainsKey("X-Requested-With"))
            return false;
        try
        {
            var accept = request.GetTypedHeaders().Accept;
            var html = accept?.Where(value => value.MediaType.Equals("text/html", StringComparison.OrdinalIgnoreCase))
                .Select(value => value.Quality ?? 1).DefaultIfEmpty(0).Max() ?? 0;
            var json = accept?.Where(value => value.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
                .Select(value => value.Quality ?? 1).DefaultIfEmpty(0).Max() ?? 0;
            return html > 0 && html > json;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
