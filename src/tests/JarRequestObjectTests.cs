using System.Text.Json;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS.Jar;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class JarRequestObjectTests
{
    [Fact]
    public void Signed_payload_replaces_outer_parameters_and_preserves_json_shapes()
    {
        var request = new OpenIddictRequest
        {
            ClientId = "jar-client",
            Scope = "identity.management",
            Prompt = "none",
            MaxAge = 3600,
            LoginHint = "injected@example.invalid",
            AcrValues = "urn:injected:acr",
        };
        request.SetParameter("resource", "https://injected.example.invalid");
        request.SetParameter("unknown_extension", "injected");
        request.SetParameter(OpenIddictConstants.Parameters.Request, "signed.jwt");

        using var document = JsonDocument.Parse(
            """
            {
              "iss": "jar-client",
              "aud": "https://identity.example.invalid",
              "exp": 1786300000,
              "iat": 1786299940,
              "jti": "signed-request-id",
              "client_id": "jar-client",
              "response_type": "code",
              "redirect_uri": "https://client.example.invalid/callback",
              "scope": "openid profile",
              "claims": {
                "id_token": {
                  "acr": { "essential": true }
                }
              },
              "authorization_details": [
                { "type": "payment", "actions": ["read", "approve"] }
              ]
            }
            """);

        var replaced = JarExtractor.TryReplaceWithSignedParameters(
            request,
            document.RootElement,
            "jar-client",
            out var error);

        Assert.True(replaced, error);
        Assert.Equal("jar-client", request.ClientId);
        Assert.Equal("code", request.ResponseType);
        Assert.Equal("openid profile", request.Scope);
        Assert.Equal(
            "https://client.example.invalid/callback",
            request.RedirectUri);
        foreach (var outerOnly in new[]
                 {
                     "resource",
                     "prompt",
                     "max_age",
                     "login_hint",
                     "acr_values",
                     "unknown_extension",
                     OpenIddictConstants.Parameters.Request,
                 })
        {
            Assert.False(request.HasParameter(outerOnly));
        }

        var claims = (JsonElement?)request.GetParameter("claims");
        var authorizationDetails =
            (JsonElement?)request.GetParameter("authorization_details");
        Assert.Equal(JsonValueKind.Object, claims?.ValueKind);
        Assert.True(claims?.GetProperty("id_token")
            .GetProperty("acr")
            .GetProperty("essential")
            .GetBoolean());
        Assert.Equal(JsonValueKind.Array, authorizationDetails?.ValueKind);
        Assert.Equal(
            "approve",
            authorizationDetails?[0]
                .GetProperty("actions")[1]
                .GetString());
    }

    [Theory]
    [InlineData("request")]
    [InlineData("request_uri")]
    public void Signed_payload_rejects_nested_request_carriers(string carrier)
    {
        var request = new OpenIddictRequest { ClientId = "jar-client" };
        using var document = JsonDocument.Parse(
            $$"""
            {
              "client_id": "jar-client",
              "response_type": "code",
              "{{carrier}}": "nested"
            }
            """);

        var replaced = JarExtractor.TryReplaceWithSignedParameters(
            request,
            document.RootElement,
            "jar-client",
            out var error);

        Assert.False(replaced);
        Assert.Contains("cannot contain", error, StringComparison.Ordinal);
    }
}
