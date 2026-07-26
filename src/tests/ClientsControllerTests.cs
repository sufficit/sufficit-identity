using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers <c>ClientsController.Create</c> secure-by-default changes (eval M4 /
/// plan item 2.4): the consent type defaults to <c>Explicit</c> when omitted,
/// and <c>redirect_uri</c> entries are validated (https required except for
/// loopback; fragments rejected). Uses <see cref="ManagementTestFactory"/>,
/// which wires the management module with authorization disabled (item 5.2 —
/// MFA/authz — is a later wave).
/// </summary>
public sealed class ClientsControllerTests
{
    private static CreateClientRequest ConfidentialClient(string clientId, params string[] redirectUris) => new()
    {
        ClientId = clientId,
        ClientSecret = $"secret-{clientId}",
        DisplayName = $"Test client {clientId}",
        GrantTypes = { Permissions.GrantTypes.AuthorizationCode },
        RedirectUris = redirectUris.Select(u => new Uri(u, UriKind.Absolute)).ToList(),
    };

    [Fact]
    public async Task Create_without_consent_type_persents_explicit_consent()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-explicit-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ConsentTypes.Explicit, body.GetProperty("consentType").GetString());
    }

    [Fact]
    public async Task Create_with_explicit_implicit_consent_type_is_honored()
    {
        // The default flipped to Explicit, but a caller can still opt into
        // Implicit explicitly (e.g. for a first-party trusted client). This
        // proves the override path works and we did not hardcode Explicit.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-implicit-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.ConsentType = "implicit";

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ConsentTypes.Implicit, body.GetProperty("consentType").GetString());
    }

    [Fact]
    public async Task Create_rejects_public_http_redirect_uri()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-http-{Guid.NewGuid():N}",
            "http://insecure.example.com/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // BadRequest(string) returns plain text, not JSON — read as string.
        var error = await response.Content.ReadAsStringAsync();
        Assert.Contains("https", error, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("loopback", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_accepts_http_redirect_uri_for_loopback()
    {
        // Dev convenience: http://localhost and http://127.0.0.1 must still be
        // accepted (local dev servers are plain http). Only public hosts are
        // forced to https.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-loopback-{Guid.NewGuid():N}",
            "http://localhost:5000/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Create_rejects_redirect_uri_with_fragment()
    {
        // OAuth 2.1 forbids fragments in redirect_uri; rejecting at creation
        // gives the operator early feedback instead of a runtime match failure.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-fragment-{Guid.NewGuid():N}",
            "https://client.tests.local/callback#section");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // BadRequest(string) returns plain text, not JSON — read as string.
        var error = await response.Content.ReadAsStringAsync();
        Assert.Contains("fragment", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_accepts_https_redirect_uri()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-https-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Create_rejects_unknown_consent_type()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-badconsent-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.ConsentType = "bogus";

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ----------------------------------------------------------------------
    // Item 3.3 — Pushed Authorization Request (RFC 9126) requirement, opt-in
    // per client. Proves the requirement is persisted when requested and
    // absent when not (so legacy clients are unaffected).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Create_with_require_par_persists_the_par_requirement()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-par-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.RequirePar = true;

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var requirements = body.GetProperty("requirements");
        Assert.Contains(requirements.EnumerateArray(),
            r => string.Equals(r.GetString(),
                OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests,
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task Create_without_require_par_does_not_persist_the_par_requirement()
    {
        // Regression guard: PAR must be opt-in. A client created without the
        // flag must NOT carry the requirement, otherwise it would be rejected
        // at /connect/authorize for a request_uri it never obtained.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-nopar-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        // RequirePar defaults to false.

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (body.TryGetProperty("requirements", out var requirements))
        {
            Assert.DoesNotContain(requirements.EnumerateArray(),
                r => string.Equals(r.GetString(),
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests,
                    StringComparison.Ordinal));
        }
        // If "requirements" is absent entirely, that also satisfies the assertion
        // (no requirement was persisted).
    }
}
