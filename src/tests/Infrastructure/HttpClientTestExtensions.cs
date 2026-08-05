using System.Net;
using System.Text.Json;

namespace Sufficit.Identity.Tests.Infrastructure;

internal static class HttpClientTestExtensions
{
    /// <summary>
    /// POSTs an <c>application/x-www-form-urlencoded</c> request (used by every
    /// <c>/connect/*</c> endpoint) and parses the response body as JSON.
    /// </summary>
    public static async Task<(HttpStatusCode Status, JsonElement Body)> PostFormAsync(
        this HttpClient client,
        string requestUri,
        IDictionary<string, string> form)
    {
        using var response = await client.PostAsync(requestUri, new FormUrlEncodedContent(form));
        var text = await response.Content.ReadAsStringAsync();

        using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
        return (response.StatusCode, document.RootElement.Clone());
    }
}
