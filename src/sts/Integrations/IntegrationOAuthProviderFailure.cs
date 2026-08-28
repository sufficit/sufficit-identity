using System.Net;
using System.Text.Json;

namespace Sufficit.Identity.STS.Integrations;

internal sealed record IntegrationOAuthProviderFailure(
    HttpStatusCode StatusCode,
    string? Error)
{
    public bool RequiresReauthorization =>
        StatusCode == HttpStatusCode.BadRequest
        && Error is "invalid_grant" or "invalid_token";

    public static IntegrationOAuthProviderFailure Parse(
        HttpStatusCode statusCode,
        string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
            return new(statusCode, null);
        try
        {
            using var document = JsonDocument.Parse(payload);
            var error = document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("error", out var value)
                && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;
            return new(statusCode, error);
        }
        catch (JsonException)
        {
            return new(statusCode, null);
        }
    }
}

internal sealed class IntegrationOAuthTokenRequestException(
    IntegrationOAuthProviderFailure failure) : HttpRequestException(
        $"OAuth provider token request failed with HTTP {(int)failure.StatusCode}.",
        inner: null,
        failure.StatusCode)
{
    public IntegrationOAuthProviderFailure Failure { get; } = failure;
}
