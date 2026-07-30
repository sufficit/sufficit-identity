using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
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
        RedirectUris = redirectUris.ToList(),
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

    // ----------------------------------------------------------------------
    // Eval test-coverage gap: assert that the management authz gate actually
    // rejects requests without the admin scope. Uses a factory variant that
    // does NOT bypass authorization (the real ScopeHandler runs).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Management_endpoints_reject_request_without_admin_scope()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        // No Authorization header → the [Authorize(Policy=...)] gate rejects.
        using var response = await client.GetAsync("/api/clients");
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"Expected 401/403 without admin scope, got {response.StatusCode}.");
        Assert.Null(response.Headers.Location);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            challenge => string.Equals(
                challenge.Scheme,
                "Bearer",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Detail_returns_the_canonical_client_contract()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-detail-{Guid.NewGuid():N}";
        var request = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        request.RequirePar = true;

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var response = await client.GetAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(clientId, body.GetProperty("clientId").GetString());
        Assert.Contains(
            body.GetProperty("redirectUris").EnumerateArray(),
            value => value.GetString() == "https://client.tests.local/callback");
        Assert.False(body.TryGetProperty("clientSecret", out _));
    }

    [Fact]
    public async Task Create_and_delete_append_redacted_audit_events()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-audit-{Guid.NewGuid():N}";
        var secret = $"secret-{Guid.NewGuid():N}";
        var request = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        request.ClientSecret = secret;

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var deleted = await client.DeleteAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var events = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == clientId)
            .OrderBy(entry => entry.Id)
            .ToArrayAsync();

        Assert.Collection(
            events,
            entry =>
            {
                Assert.Equal("identity.clients.create", entry.Capability);
                Assert.Equal("succeeded", entry.OperationOutcome);
            },
            entry =>
            {
                Assert.Equal("identity.clients.delete", entry.Capability);
                Assert.Equal("succeeded", entry.OperationOutcome);
            });
        Assert.All(events, entry =>
        {
            Assert.DoesNotContain(secret, entry.OperatorSubject, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, entry.CorrelationId, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Audit_endpoint_returns_persisted_mutations()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-audit-list-{Guid.NewGuid():N}";

        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            ConfidentialClient(
                clientId,
                "https://client.tests.local/callback"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var response = await client.GetAsync("/api/audit?limit=10");
        var records = await response.Content
            .ReadFromJsonAsync<ManagementAuditRecord[]>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            records!,
            entry => entry.ResourceId == clientId
                && entry.Capability == "identity.clients.create");
    }
}
